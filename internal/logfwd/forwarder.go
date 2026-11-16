package logfwd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"path"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/sdk/api"
)

// Jail is a jail whose logs may be forwarded.
type Jail struct {
	Project string
	Name    string
	Labels  map[string]string
	// App is the catalog app the jail was installed from ("" for none).
	App string
	// LogDir is <jail root>/var/log on the host.
	LogDir string
	// AppFiles are the files below /var/log the app declares.
	AppFiles []string
}

// Reader reads the end of a log file from an offset (the helper's fs.tail_file).
type Reader interface {
	TailFile(ctx context.Context, path string, offset, limit int64) (data []byte, start, size int64, err error)
}

// AuditRecord is one entry of the daemon's audit log, rendered as a line.
type AuditRecord struct {
	ID      int64
	Time    time.Time
	Project string
	Line    string
}

// Offsets keeps the per-source offsets of each sink across restarts.
type Offsets interface {
	Load(ctx context.Context, sink string) (map[string]int64, error)
	Save(ctx context.Context, sink string, offsets map[string]int64) error
	Delete(ctx context.Context, sink string) error
}

// Env is what the forwarder needs from the daemon.
type Env struct {
	Hostname string
	Reader   Reader
	// Jails lists the jails of every project.
	Jails func(ctx context.Context) ([]Jail, error)
	// AuditAfter returns up to limit audit entries with an id above after,
	// oldest first; AuditLast the newest id.
	AuditAfter func(ctx context.Context, after int64, limit int) ([]AuditRecord, error)
	AuditLast  func(ctx context.Context) (int64, error)
	Offsets    Offsets
	// Dial opens connections. The default dialer refuses, for a sink set through the API, a resolved address that
	// CheckTarget refuses; a replacement (tests) does what it does.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// CheckFile replaces the owner and mode check of a CA or token file (tests: their files are not root's). By
	// default the open descriptor is checked; either way the file is opened without following a symlink.
	CheckFile func(path string, secret bool) error
	// SecretsDir is logging.secrets_dir: the only directory the files of an API sink may lie in.
	SecretsDir string
	// CheckDir checks SecretsDir (CheckSecretsDir by default).
	CheckDir func(dir string) error
	// OwnPorts are the ports this daemon listens on: an API sink may not send to them on an address of the host.
	OwnPorts func() []int
	// TargetCheck replaces the check of an API sink's destination (tests).
	TargetCheck func(netip.AddrPort) error
	Clock       Clock
	Jitter      func() float64
	Log         *slog.Logger
	// Poll is how often files are read (default 2s); Refresh how often the
	// jail list is read again (default 30s).
	Poll    time.Duration
	Refresh time.Duration
	// MaxSources bounds the files one sink reads (default 1000).
	MaxSources int
}

func (e *Env) defaults() {
	if e.Dial == nil {
		e.Dial = e.guardedDialer()
	}
	if e.CheckDir == nil {
		e.CheckDir = CheckSecretsDir
	}
	if e.Clock == nil {
		e.Clock = realClock{}
	}
	if e.Jitter == nil {
		e.Jitter = defaultJitter
	}
	if e.Log == nil {
		e.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if e.Poll <= 0 {
		e.Poll = 2 * time.Second
	}
	if e.Refresh <= 0 {
		e.Refresh = 30 * time.Second
	}
	if e.MaxSources <= 0 {
		e.MaxSources = 1000
	}
}

// Forwarder runs one loop per sink.
type Forwarder struct {
	env *Env

	mu      sync.Mutex
	ctx     context.Context
	sinks   map[string]*sink
	order   []string
	pending []api.LogSink
	fromAPI bool // the pending list was set through the API
	wg      sync.WaitGroup
}

// New builds a forwarder; Apply and Start set it going.
func New(env Env) *Forwarder {
	env.defaults()
	return &Forwarder{env: &env, sinks: map[string]*sink{}}
}

// Start runs the sinks of the last Apply until ctx ends.
func (f *Forwarder) Start(ctx context.Context) {
	f.mu.Lock()
	f.ctx = ctx
	list, fromAPI := f.pending, f.fromAPI
	f.mu.Unlock()
	f.ApplyFrom(list, fromAPI)
}

// Env is the forwarder's environment, with its defaults.
func (f *Forwarder) Env() *Env { return f.env }

// Wait returns when every sink loop has saved its offsets and ended.
func (f *Forwarder) Wait() { f.wg.Wait() }

// Apply replaces the sink list with the list of jailopsd.yaml.
func (f *Forwarder) Apply(list []api.LogSink) { f.ApplyFrom(list, false) }

// ApplyFrom replaces the sink list: a sink whose configuration or origin changed starts over from its saved
// offsets; a removed sink's offsets are deleted. fromAPI restricts the sinks (see CheckTarget and SecretsDir).
func (f *Forwarder) ApplyFrom(list []api.LogSink, fromAPI bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending, f.fromAPI = slices.Clone(list), fromAPI
	if f.ctx == nil {
		return
	}
	want := map[string]api.LogSink{}
	f.order = f.order[:0]
	for _, k := range list {
		want[k.Name] = k
		f.order = append(f.order, k.Name)
	}
	for name, s := range f.sinks {
		k, keep := want[name]
		if keep && reflect.DeepEqual(k, s.cfg) && s.api == fromAPI {
			continue
		}
		s.stop()
		delete(f.sinks, name)
		if !keep {
			_ = f.env.Offsets.Delete(context.WithoutCancel(f.ctx), name)
		}
	}
	for _, k := range list {
		if _, ok := f.sinks[k.Name]; ok {
			continue
		}
		s := newSink(k, f.env)
		s.api = fromAPI
		f.sinks[k.Name] = s
		ctx, cancel := context.WithCancel(f.ctx)
		s.cancel = cancel
		f.wg.Add(1)
		go func() { defer f.wg.Done(); s.run(ctx) }()
	}
}

// Status reports every sink in list order.
func (f *Forwarder) Status() []api.LogSinkStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []api.LogSinkStatus{}
	if f.ctx == nil {
		for _, k := range f.pending {
			out = append(out, newSink(k, f.env).status())
		}
		return out
	}
	for _, n := range f.order {
		if s := f.sinks[n]; s != nil {
			out = append(out, s.status())
		}
	}
	return out
}

// TestLine is the text of a test message.
func TestLine(id, host string) string {
	return "jailops log forwarding test " + id + " from " + host
}

// Test sends one tagged line to k with a sender of its own, beside the
// running loop, and reports how it went: an error is a short fixed class
// (Classify), never what the receiver answered.
func (f *Forwarder) Test(ctx context.Context, k api.LogSink, fromAPI bool) api.LogForwardTestResult {
	var b [6]byte
	_, _ = rand.Read(b[:])
	start := f.env.Clock.Now()
	res := api.LogForwardTestResult{Sink: k.Name, Line: TestLine(hex.EncodeToString(b[:]), f.env.Hostname)}
	snd, err := newSender(k, f.env, fromAPI)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err = snd.send(ctx, []Entry{{Time: start, File: "test", Line: res.Line}})
		cancel()
		snd.close()
	}
	res.Millis = f.env.Clock.Now().Sub(start).Milliseconds()
	if err != nil {
		res.Error = Classify(err)
		return res
	}
	res.OK = true
	return res
}

// source is one file of a jail, or the audit log.
type source struct {
	key, project, jail, app, file, path string
	audit                               bool
}

// sink is the loop of one destination. The loop goroutine owns everything
// but the fields under mu, which Status reads.
type sink struct {
	cfg    api.LogSink
	api    bool // set through the API: restricted
	env    *Env
	cancel context.CancelFunc
	done   chan struct{}

	mu           sync.Mutex
	q            *queue
	sent         int64
	skipped      int64
	lastSuccess  time.Time
	failingSince time.Time
	lastErr      string
	warning      string
	nSources     int

	snd       sender
	srcs      []source
	read      map[string]int64 // where the next read of a source starts; -1: at the end, once readable
	acked     map[string]int64 // what is delivered or given up, per source
	pending   map[string]int   // queued entries per source
	fresh     bool             // no saved offsets: a sink that starts now reads only what is written from now on
	refreshed time.Time
	failures  int
	nextTry   time.Time
	dirty     bool
	saved     time.Time
	loaded    bool
	overLimit int
}

func newSink(k api.LogSink, env *Env) *sink {
	size := k.Queue
	if size == 0 {
		size = api.DefaultLogQueue
	}
	s := &sink{cfg: k, env: env, q: newQueue(size), done: make(chan struct{}),
		read: map[string]int64{}, acked: map[string]int64{}, pending: map[string]int{}}
	if k.Plaintext() {
		tr, hp, _ := k.SinkTarget()
		s.warning = fmt.Sprintf("plain %s to %s sends the logs in the clear; use tls://", tr, hp)
	}
	return s
}

func (s *sink) stop() {
	s.cancel()
	<-s.done
}

func (s *sink) run(ctx context.Context) {
	defer close(s.done)
	if s.warning != "" {
		s.env.Log.Warn("log forwarding: "+s.warning, "sink", s.cfg.Name)
	}
	defer func() {
		s.save(context.WithoutCancel(ctx), true)
		if s.snd != nil {
			s.snd.close()
		}
	}()
	// a panic in a cycle is a restart of the loop (the state of the sink is in its fields), not the end of the daemon
	supervise.Run(ctx, s.env.Log, "log-forward", s.loop)
}

func (s *sink) loop(ctx context.Context) {
	for {
		s.cycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-s.env.Clock.After(s.env.Poll):
		}
	}
}

// cycle is one round: refresh the sources when due, read what was
// appended, send while the sink accepts, save the offsets now and then.
func (s *sink) cycle(ctx context.Context) {
	if !s.loaded {
		m, err := s.env.Offsets.Load(ctx, s.cfg.Name)
		if err != nil {
			s.setErr("loading the offsets: " + err.Error())
			return
		}
		s.loaded, s.fresh = true, len(m) == 0
		maps.Copy(s.acked, m)
	}
	now := s.env.Clock.Now()
	if s.srcs == nil || now.Sub(s.refreshed) >= s.env.Refresh {
		s.refresh(ctx)
		s.refreshed = now
	}
	for _, src := range s.srcs {
		if ctx.Err() != nil {
			return
		}
		s.readSource(ctx, src)
	}
	if !now.Before(s.nextTry) {
		s.sendSome(ctx)
	}
	if s.dirty && s.env.Clock.Now().Sub(s.saved) >= 2*time.Second {
		s.save(ctx, false)
	}
}

func matchAll(labels, want map[string]string) bool {
	for k, v := range want {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func matchAny(labels, any map[string]string) bool {
	for k, v := range any {
		if l, ok := labels[k]; ok && l == v {
			return true
		}
	}
	return false
}

// Select picks the sources of a sink from the jails: the files named by
// the sink (default messages) of every jail it matches, the files their
// apps declare, and the audit log when asked. The list is sorted by key.
func Select(sel api.LogSinkSource, jails []Jail) []source {
	var out []source
	if !sel.NoJails {
		files := sel.Files
		if len(files) == 0 {
			files = []string{api.DefaultLogFile}
		}
		for _, j := range jails {
			if (len(sel.Projects) > 0 && !slices.Contains(sel.Projects, j.Project)) ||
				(len(sel.Jails) > 0 && !slices.Contains(sel.Jails, j.Name)) ||
				!matchAll(j.Labels, sel.Labels) || slices.Contains(sel.ExcludeJails, j.Name) || matchAny(j.Labels, sel.ExcludeLabels) {
				continue
			}
			fs := slices.Clone(files)
			if !sel.NoAppLogs {
				fs = append(fs, j.AppFiles...)
			}
			seen := map[string]bool{}
			for _, f := range fs {
				if seen[f] || api.ValidLogFileName(f) != nil {
					continue
				}
				seen[f] = true
				out = append(out, source{key: api.LogSourceKey(j.Project, j.Name, f), project: j.Project, jail: j.Name, app: j.App, file: f, path: path.Join(j.LogDir, f)})
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].key < out[b].key })
	if sel.Audit {
		out = append(out, source{key: api.LogSourceAudit, file: api.LogSourceAudit, audit: true})
	}
	return out
}

func (s *sink) refresh(ctx context.Context) {
	var jails []Jail
	if !s.cfg.Sources.NoJails {
		var err error
		if jails, err = s.env.Jails(ctx); err != nil {
			s.setErr("listing the jails: " + err.Error())
			if s.srcs == nil {
				s.srcs = []source{}
			}
			return
		}
	}
	srcs := Select(s.cfg.Sources, jails)
	if srcs == nil {
		srcs = []source{} // read once: a jail that appears later is new
	}
	over := 0
	if len(srcs) > s.env.MaxSources {
		over = len(srcs) - s.env.MaxSources
		srcs = srcs[:s.env.MaxSources]
	}
	first := s.srcs == nil
	for _, src := range srcs {
		if _, ok := s.read[src.key]; ok {
			continue
		}
		if off, ok := s.acked[src.key]; ok {
			s.read[src.key] = off
		} else if first && s.fresh || src.audit {
			s.read[src.key] = -1 // at the end
		} else {
			s.read[src.key] = 0 // a jail that appeared since: from its beginning
		}
	}
	s.srcs = srcs
	// a source that is gone (a deleted jail) leaves the tables once nothing of it is queued
	live := make(map[string]bool, len(srcs))
	for _, src := range srcs {
		live[src.key] = true
	}
	for k := range s.read {
		if !live[k] && s.pending[k] == 0 {
			delete(s.read, k)
			delete(s.acked, k)
			delete(s.pending, k)
		}
	}
	s.mu.Lock()
	s.nSources, s.overLimit = len(srcs), over
	s.mu.Unlock()
}

// readSource reads what was appended to one source and queues its complete lines.
func (s *sink) readSource(ctx context.Context, src source) {
	if src.audit {
		s.readAudit(ctx, src)
		return
	}
	off := s.read[src.key]
	if off < 0 {
		_, _, size, err := s.env.Reader.TailFile(ctx, src.path, 0, 1)
		if err == nil {
			s.read[src.key] = size
		}
		return
	}
	data, start, size, err := s.env.Reader.TailFile(ctx, src.path, off, api.MaxLogReadBytes)
	if err != nil {
		return // not mounted, no such file: nothing to read now
	}
	if off > size {
		off = 0 // rotated or truncated: the file starts over
	}
	if start > off {
		// more than the window was written since: what lies before it is lost
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			s.read[src.key] = start + int64(len(data))
			s.addSkipped(start + int64(len(data)) - off)
			return
		}
		s.addSkipped(start + int64(i) + 1 - off)
		data, start = data[i+1:], start+int64(i)+1
	}
	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		if int64(len(data)) < api.MaxLogReadBytes {
			return // an unfinished line: wait for its end
		}
		last = len(data) - 1 // a line longer than the window is taken as it is
	}
	now := s.env.Clock.Now()
	pos := start
	for _, b := range bytes.Split(data[:last+1], []byte("\n")) {
		if pos >= start+int64(last)+1 {
			break // the empty piece after the final newline
		}
		end := min(pos+int64(len(b))+1, start+int64(last)+1)
		text := string(b)
		t, ok := api.LogLineTime(text, now)
		if !ok {
			t = now
		}
		s.push(Entry{Time: t, Project: src.project, Jail: src.jail, App: src.app, File: src.file, Line: text, src: src.key, begin: pos, end: end})
		pos = end
	}
	s.read[src.key] = start + int64(last) + 1
}

func (s *sink) readAudit(ctx context.Context, src source) {
	if s.env.AuditAfter == nil {
		return
	}
	after := s.read[src.key]
	if after < 0 {
		if s.env.AuditLast == nil {
			return
		}
		id, err := s.env.AuditLast(ctx)
		if err == nil {
			s.read[src.key] = id
		}
		return
	}
	for range 4 {
		recs, err := s.env.AuditAfter(ctx, after, 500)
		if err != nil || len(recs) == 0 {
			return
		}
		for _, r := range recs {
			s.push(Entry{Time: r.Time, Project: r.Project, File: api.LogSourceAudit, Line: r.Line, src: src.key, begin: after, end: r.ID})
			after = r.ID
		}
		s.read[src.key] = after
	}
}

func (s *sink) addSkipped(n int64) {
	s.mu.Lock()
	s.skipped += n
	s.mu.Unlock()
}

func (s *sink) push(e Entry) {
	if s.pending[e.src] == 0 {
		s.acked[e.src] = e.begin
	}
	s.pending[e.src]++
	s.mu.Lock()
	d, dropped := s.q.push(e)
	s.mu.Unlock()
	if dropped {
		s.pending[d.src]--
		s.acked[d.src] = d.end // given up
		s.dirty = true
	}
}

func (s *sink) batchSize() int {
	if s.cfg.Type == api.LogSinkWebhook {
		return 200
	}
	return 100
}

// sendSome sends batches until the queue is empty, a send fails (then the
// next try waits for the backoff) or twenty batches went in this round.
func (s *sink) sendSome(ctx context.Context) {
	for range 20 {
		s.mu.Lock()
		batch := s.q.peek(s.batchSize())
		s.mu.Unlock()
		if len(batch) == 0 {
			return
		}
		if s.snd == nil {
			snd, err := newSender(s.cfg, s.env, s.api)
			if err != nil {
				s.fail(err)
				return
			}
			s.snd = snd
		}
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		err := s.snd.send(sctx, batch)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.fail(err)
			return
		}
		now := s.env.Clock.Now()
		s.mu.Lock()
		s.q.pop(len(batch))
		s.sent += int64(len(batch))
		s.lastSuccess, s.failingSince = now, time.Time{}
		s.mu.Unlock()
		for _, e := range batch {
			s.pending[e.src]--
			s.acked[e.src] = e.end
		}
		s.failures, s.dirty = 0, true
	}
}

func (s *sink) fail(err error) {
	now := s.env.Clock.Now()
	s.failures++
	s.nextTry = now.Add(backoff(s.failures, s.env.Jitter()))
	s.mu.Lock()
	s.lastErr = err.Error()
	if s.failingSince.IsZero() {
		s.failingSince = now
	}
	s.mu.Unlock()
	if s.failures == 1 {
		s.env.Log.Warn("log forwarding failed", "sink", s.cfg.Name, "err", err)
	}
}

func (s *sink) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.mu.Unlock()
}

// offsets is what save persists: for a source with queued lines the end of
// the last line delivered (or given up), for the others where reading
// continues. Sources that are gone are left out.
func (s *sink) offsets() map[string]int64 {
	out := map[string]int64{}
	for _, src := range s.srcs {
		r, ok := s.read[src.key]
		if !ok || r < 0 {
			continue
		}
		if s.pending[src.key] > 0 {
			out[src.key] = s.acked[src.key]
		} else {
			out[src.key] = r
		}
	}
	return out
}

func (s *sink) save(ctx context.Context, final bool) {
	if !s.loaded || (!s.dirty && !final) || s.srcs == nil {
		return
	}
	if err := s.env.Offsets.Save(ctx, s.cfg.Name, s.offsets()); err != nil {
		s.env.Log.Warn("log forwarding: saving the offsets failed", "sink", s.cfg.Name, "err", err)
		return
	}
	s.dirty, s.saved = false, s.env.Clock.Now()
}

func (s *sink) status() api.LogSinkStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := api.LogSinkStatus{Name: s.cfg.Name, Type: s.cfg.Type, To: s.cfg.To, Sources: s.nSources, Sent: s.sent, Queued: s.q.len(),
		Dropped: s.q.dropped, SkippedBytes: s.skipped, LastError: s.lastErr, Warning: s.warning}
	if s.overLimit > 0 {
		st.Warning = strings.TrimPrefix(st.Warning+"; ", "; ") + fmt.Sprintf("%d files over the limit of %d are not read; narrow the sources", s.overLimit, s.env.MaxSources)
	}
	if !s.lastSuccess.IsZero() {
		t := s.lastSuccess.UTC()
		st.LastSuccess = &t
	}
	if !s.failingSince.IsZero() {
		t := s.failingSince.UTC()
		st.FailingSince = &t
	}
	return st
}
