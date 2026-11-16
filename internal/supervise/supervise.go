// Package supervise runs the background loops of the programs so that a panic in one of them is a restart of that
// loop and not the end of the whole process.
//
// A loop that panics is logged with its stack, counted, and run again after a delay that doubles from one second to
// one minute; a loop that ran for five minutes before it panicked starts again from the short delay. A loop that returns
// is over: nothing is restarted when the context ended or the function returned on its own. The counters are what
// `jailops doctor` reports (daemon.loops).
package supervise

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"sort"
	"sync"
	"time"
)

const (
	// MinDelay is the wait before the first restart of a loop.
	MinDelay = time.Second
	// MaxDelay is the longest wait between two restarts.
	MaxDelay = time.Minute
	// Healthy is how long a loop has to run before its next panic counts as a first one again.
	Healthy = 5 * time.Minute
)

// Stats is what the supervisor knows of one loop.
type Stats struct {
	Name      string
	Restarts  int       // panics since the program started
	LastPanic string    // the value of the last panic
	LastAt    time.Time // when it happened
	Recent    int       // restarts in the last day (the doctor warns on this)
	times     []time.Time
}

var (
	mu    sync.Mutex
	loops = map[string]*Stats{}

	// now and sleep are replaced by the tests.
	now   = time.Now
	sleep = realSleep
)

func realSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run calls f until it returns or ctx ends; when f panics the panic is recorded and f is called again after a delay.
// It blocks, so it is called from the goroutine of the loop.
func Run(ctx context.Context, log *slog.Logger, name string, f func(ctx context.Context)) {
	if log == nil {
		log = slog.Default()
	}
	delay := MinDelay
	for {
		start := now()
		msg, panicked := call(ctx, f)
		if !panicked {
			return
		}
		record(name, msg)
		if ctx.Err() != nil {
			return
		}
		if now().Sub(start) >= Healthy {
			delay = MinDelay
		}
		wait := jitter(delay)
		log.Error("a background loop panicked and is started again", "loop", name, "panic", msg, "again_in", wait.Round(time.Millisecond).String())
		if !sleep(ctx, wait) {
			return
		}
		if delay *= 2; delay > MaxDelay {
			delay = MaxDelay
		}
	}
}

// Guard runs f in the calling goroutine and turns a panic in it into an error (it is logged with its stack and counted
// under name). It is for goroutines that run once, such as a worker or an operation: they are not restarted, but they
// do not end the program either.
func Guard(log *slog.Logger, name string, f func()) (err error) {
	if log == nil {
		log = slog.Default()
	}
	msg, panicked := call(context.Background(), func(context.Context) { f() })
	if !panicked {
		return nil
	}
	record(name, msg)
	first, _, _ := cutLine(msg)
	log.Error("a background task panicked", "task", name, "panic", msg)
	return fmt.Errorf("%s: panic: %s", name, first)
}

// Report records a recovered panic: `defer func() { supervise.Report(log, "name", recover()) }()` as the first deferred
// call of a goroutine keeps a panic in it from ending the program, for goroutines that are written with several defers.
func Report(log *slog.Logger, name string, r any) {
	if r == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	msg := fmt.Sprintf("%v\n%s", r, debug.Stack())
	record(name, msg)
	log.Error("a background task panicked", "task", name, "panic", msg)
}

// call runs f and reports whether it panicked, with the panic and the stack as text.
func call(ctx context.Context, f func(context.Context)) (msg string, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			msg, panicked = fmt.Sprintf("%v\n%s", r, debug.Stack()), true
		}
	}()
	f(ctx)
	return "", false
}

// jitter spreads the restarts of several loops that failed together by up to a fifth of the delay.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/5+1))
}

func record(name, msg string) {
	mu.Lock()
	defer mu.Unlock()
	s := loops[name]
	if s == nil {
		s = &Stats{Name: name}
		loops[name] = s
	}
	first, _, _ := cutLine(msg)
	s.Restarts++
	s.LastPanic, s.LastAt = first, now()
	s.times = append(s.times, s.LastAt)
}

// cutLine returns the first line of s.
func cutLine(s string) (first, rest string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// Loops reports the loops that were restarted, the most restarted first. Recent counts the restarts of the last day.
func Loops() []Stats {
	mu.Lock()
	defer mu.Unlock()
	cut := now().Add(-24 * time.Hour)
	out := make([]Stats, 0, len(loops))
	for _, s := range loops {
		keep := s.times[:0]
		for _, t := range s.times {
			if t.After(cut) {
				keep = append(keep, t)
			}
		}
		s.times = keep
		c := *s
		c.Recent, c.times = len(keep), nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Restarts != out[j].Restarts {
			return out[i].Restarts > out[j].Restarts
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Reset forgets every counter (tests).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	loops = map[string]*Stats{}
}
