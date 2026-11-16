package devd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DefaultPipe is where devd(8) listens for readers on FreeBSD.
const DefaultPipe = "/var/run/devd.seqpacket.pipe"

// Conn is what the watcher needs of a connection to devd: one record per Read.
type Conn interface {
	io.Reader
	io.Closer
}

// Config configures a Watcher. Only Path and Sink are required.
type Config struct {
	Path   string
	Sink   func(Event)
	Mapper Mapper
	Log    *slog.Logger
	Now    func() time.Time
	// Dial opens the connection; the default is a unix seqpacket socket.
	Dial func(ctx context.Context, path string) (Conn, error)
	// MinRetry and MaxRetry bound the wait before a new connection attempt (default 1 s and 60 s); the wait doubles
	// after every failure.
	MinRetry, MaxRetry time.Duration
	// Window is how long an identical event is held back after it was published (default 30 s), and PerMinute the
	// most events published in a minute (default 30), so that a failing disk or a flapping link cannot flood the
	// event stream.
	Window    time.Duration
	PerMinute int
}

// Status is what the watcher knows about its connection.
type Status struct {
	Connected bool
	Since     time.Time // of the last change between connected and not
	Err       string    // why it is not connected
	Published uint64
	Dropped   uint64 // events held back by the window or the rate limit
}

// Watcher keeps a connection to devd and publishes the events of the records it reads.
type Watcher struct {
	cfg Config
	lim limiter

	mu     sync.Mutex
	status Status
	logged string // the last state that was logged, so that a retry loop logs once
}

// New returns a Watcher; Run starts it.
func New(cfg Config) *Watcher {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Dial == nil {
		cfg.Dial = dialSeqpacket
	}
	if cfg.MinRetry <= 0 {
		cfg.MinRetry = time.Second
	}
	if cfg.MaxRetry < cfg.MinRetry {
		cfg.MaxRetry = 60 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 30 * time.Second
	}
	if cfg.PerMinute <= 0 {
		cfg.PerMinute = 30
	}
	return &Watcher{cfg: cfg, lim: newLimiter(cfg.Window, cfg.PerMinute)}
}

// Status returns the state of the connection.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Path is the socket the watcher reads.
func (w *Watcher) Path() string { return w.cfg.Path }

func dialSeqpacket(ctx context.Context, path string) (Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unixpacket", path)
}

// Run connects, reads and reconnects until ctx ends. A host without devd, or a socket the daemon may not read, only
// shows in Status and in one line of the log per change.
func (w *Watcher) Run(ctx context.Context) {
	delay := w.cfg.MinRetry
	for ctx.Err() == nil {
		conn, err := w.cfg.Dial(ctx, w.cfg.Path)
		if err != nil {
			w.setState(false, err.Error())
			if !sleep(ctx, delay) {
				return
			}
			if delay *= 2; delay > w.cfg.MaxRetry {
				delay = w.cfg.MaxRetry
			}
			continue
		}
		w.setState(true, "")
		delay = w.cfg.MinRetry
		err = w.read(ctx, conn)
		_ = conn.Close()
		if ctx.Err() != nil {
			return
		}
		if err == nil || err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		w.setState(false, "the connection to devd ended: "+err.Error())
		if !sleep(ctx, delay) {
			return
		}
	}
}

func (w *Watcher) read(ctx context.Context, conn Conn) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	buf := make([]byte, MaxRecord+1)
	for {
		n, err := conn.Read(buf)
		// devd writes one record per packet and ends each with a newline. A socket that delivers queued packets in one
		// read (FreeBSD does when the sender does not mark the end of a record) still gives one record per line.
		for _, line := range bytes.Split(buf[:n], []byte{'\n'}) {
			if len(line) > 0 {
				w.handle(line)
			}
		}
		if err != nil {
			return err
		}
	}
}

func (w *Watcher) handle(packet []byte) {
	rec, ok := Parse(packet)
	if !ok {
		return
	}
	ev, ok := w.cfg.Mapper.Map(rec)
	if !ok {
		return
	}
	w.mu.Lock()
	allowed := w.lim.allow(ev, w.cfg.Now())
	if allowed {
		w.status.Published++
	} else {
		w.status.Dropped++
	}
	w.mu.Unlock()
	if allowed && w.cfg.Sink != nil {
		w.cfg.Sink(ev)
	}
}

func (w *Watcher) setState(connected bool, why string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status.Connected != connected || w.status.Err != why {
		if w.status.Connected != connected {
			w.status.Since = w.cfg.Now()
		}
		w.status.Connected, w.status.Err = connected, why
	}
	key := why
	if connected {
		key = "connected"
	}
	if key != w.logged {
		w.logged = key
		if connected {
			w.cfg.Log.Info("devd: reading kernel events", "socket", w.cfg.Path)
		} else {
			w.cfg.Log.Info("devd: kernel events are not read; retrying", "socket", w.cfg.Path, "reason", why)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// limiter holds an identical event back for a window and caps the events of a minute with a token bucket.
type limiter struct {
	window time.Duration
	burst  float64
	rate   float64 // tokens per second

	last   map[Event]time.Time
	tokens float64
	at     time.Time
}

func newLimiter(window time.Duration, perMinute int) limiter {
	return limiter{window: window, burst: float64(perMinute), rate: float64(perMinute) / 60, last: map[Event]time.Time{}, tokens: float64(perMinute)}
}

func (l *limiter) allow(ev Event, now time.Time) bool {
	if !l.at.IsZero() {
		l.tokens += now.Sub(l.at).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.at = now
	if t, ok := l.last[ev]; ok && now.Sub(t) < l.window {
		return false
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	if len(l.last) >= 256 {
		for k, t := range l.last {
			if now.Sub(t) >= l.window {
				delete(l.last, k)
			}
		}
	}
	l.last[ev] = now
	return true
}
