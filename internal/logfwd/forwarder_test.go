package logfwd

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
)

// memReader serves log files from memory with the helper's tail semantics.
type memReader struct {
	mu    sync.Mutex
	files map[string]string
	reads int
}

func (m *memReader) set(p, s string) { m.mu.Lock(); m.files[p] = s; m.mu.Unlock() }
func (m *memReader) add(p, s string) { m.mu.Lock(); m.files[p] += s; m.mu.Unlock() }

func (m *memReader) TailFile(_ context.Context, p string, offset, limit int64) ([]byte, int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	s, ok := m.files[p]
	if !ok {
		return nil, 0, 0, api.Errorf(api.CodeNotFound, "jail root is missing").WithDetail("missing", "root")
	}
	size := int64(len(s))
	start := api.LogWindowStart(size, offset, limit)
	return []byte(s[start:]), start, size, nil
}

// memOffsets is the offset store of the tests.
type memOffsets struct {
	mu sync.Mutex
	m  map[string]map[string]int64
}

func (o *memOffsets) Load(_ context.Context, sink string) (map[string]int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return maps.Clone(o.m[sink]), nil
}
func (o *memOffsets) Save(_ context.Context, sink string, m map[string]int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[sink] = maps.Clone(m)
	return nil
}
func (o *memOffsets) Delete(_ context.Context, sink string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.m, sink)
	return nil
}
func (o *memOffsets) get(sink string) map[string]int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return maps.Clone(o.m[sink])
}

// fakeClock moves only when the test says so.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []chan time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) After(time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters = append(c.waiters, ch)
	return ch
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, w := range c.waiters {
		w <- c.now
	}
	c.waiters = nil
}

// recSender records batches, or fails while fail is set.
type recSender struct {
	mu    sync.Mutex
	lines []string
	fail  error
	calls int
}

func (r *recSender) send(_ context.Context, b []Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail != nil {
		return r.fail
	}
	for _, e := range b {
		r.lines = append(r.lines, e.Jail+"/"+e.File+": "+e.Line)
	}
	return nil
}
func (r *recSender) close() {}
func (r *recSender) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.lines
	r.lines = nil
	return l
}

type rig struct {
	rd    *memReader
	off   *memOffsets
	clock *fakeClock
	env   *Env
	jails []Jail
	snd   *recSender
}

func newRig() *rig {
	r := &rig{rd: &memReader{files: map[string]string{}}, off: &memOffsets{m: map[string]map[string]int64{}},
		clock: &fakeClock{now: t0}, snd: &recSender{}}
	r.jails = []Jail{
		{Project: "web", Name: "a", LogDir: "/j/web_a/var/log", Labels: map[string]string{"tier": "front"}},
		{Project: "web", Name: "b", LogDir: "/j/web_b/var/log", App: "nginx", AppFiles: []string{"nginx/error.log"}},
		{Project: "db", Name: "c", LogDir: "/j/db_c/var/log"},
	}
	r.env = &Env{Hostname: "host1", Reader: r.rd, Offsets: r.off, Clock: r.clock, Jitter: func() float64 { return 0 },
		Jails: func(context.Context) ([]Jail, error) { return r.jails, nil }}
	r.env.defaults()
	return r
}

// sink returns a sink that sends through the recorder.
func (r *rig) sink(k api.LogSink) *sink {
	if k.Type == "" {
		k.Type, k.To = api.LogSinkSyslog, "tcp://127.0.0.1:1514"
	}
	s := newSink(k, r.env)
	s.snd = r.snd
	return s
}

func TestSelect(t *testing.T) {
	r := newRig()
	keys := func(sel api.LogSinkSource) string {
		var out []string
		for _, s := range Select(sel, r.jails) {
			out = append(out, s.key)
		}
		return strings.Join(out, " ")
	}
	for _, c := range []struct {
		sel  api.LogSinkSource
		want string
	}{
		{api.LogSinkSource{}, "db/c/messages web/a/messages web/b/messages web/b/nginx/error.log"},
		{api.LogSinkSource{NoAppLogs: true}, "db/c/messages web/a/messages web/b/messages"},
		{api.LogSinkSource{Projects: []string{"web"}, Files: []string{"auth.log"}}, "web/a/auth.log web/b/auth.log web/b/nginx/error.log"},
		{api.LogSinkSource{Labels: map[string]string{"tier": "front"}}, "web/a/messages"},
		{api.LogSinkSource{ExcludeLabels: map[string]string{"tier": "front"}, ExcludeJails: []string{"c"}}, "web/b/messages web/b/nginx/error.log"},
		{api.LogSinkSource{Jails: []string{"c"}, Audit: true}, "db/c/messages audit"},
		{api.LogSinkSource{NoJails: true, Audit: true}, "audit"},
	} {
		if got := keys(c.sel); got != c.want {
			t.Errorf("%+v: %s, want %s", c.sel, got, c.want)
		}
	}
}

// A new sink starts at the end of the files (it sends what is written from
// now on); a jail that appears later is read from its beginning; offsets
// are saved and a restarted sink continues after the last delivered line.
func TestSinkOffsetsAndRestart(t *testing.T) {
	r := newRig()
	r.rd.set("/j/web_a/var/log/messages", "old 1\nold 2\n")
	r.rd.set("/j/web_b/var/log/messages", "Nov  1 09:00:00 b old\n")
	ctx := context.Background()
	k := api.LogSink{Name: "s", Sources: api.LogSinkSource{NoAppLogs: true}}
	s := r.sink(k)
	s.cycle(ctx) // resolves the ends
	if got := r.snd.take(); len(got) != 0 {
		t.Fatalf("a new sink sent old lines: %q", got)
	}
	r.rd.add("/j/web_a/var/log/messages", "new 1\nnew 2 unfinished")
	r.rd.add("/j/web_b/var/log/messages", "Nov  1 09:30:00 b new\n")
	r.clock.advance(2 * time.Second)
	s.cycle(ctx)
	if got := strings.Join(r.snd.take(), "|"); got != "a/messages: new 1|b/messages: Nov  1 09:30:00 b new" {
		t.Fatalf("%s", got)
	}
	want := map[string]int64{"web/a/messages": 18, "web/b/messages": 44}
	if got := r.off.get("s"); !maps.Equal(got, want) {
		t.Fatalf("offsets %v, want %v", got, want)
	}
	// the line ends; a new jail appears; the daemon stops and starts again
	r.rd.add("/j/web_a/var/log/messages", "\n")
	r.jails = append(r.jails, Jail{Project: "web", Name: "d", LogDir: "/j/web_d/var/log"})
	r.rd.set("/j/web_d/var/log/messages", "d from boot\n")
	s.save(ctx, true)
	s2 := r.sink(k)
	s2.cycle(ctx)
	if got := strings.Join(r.snd.take(), "|"); got != "a/messages: new 2 unfinished|d/messages: d from boot" {
		t.Fatalf("after restart: %s", got)
	}
}

// Rotation: a file shorter than the offset is read from its beginning, as the follow of 'jail logs' does.
func TestSinkRotation(t *testing.T) {
	r := newRig()
	p := "/j/db_c/var/log/messages"
	r.rd.set(p, "")
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Sources: api.LogSinkSource{Jails: []string{"c"}}})
	s.cycle(ctx)
	r.rd.add(p, "one\ntwo\nthree\n")
	s.cycle(ctx)
	r.rd.set(p, "rotated\n") // newsyslog moved it to messages.0
	s.cycle(ctx)
	if got := strings.Join(r.snd.take(), "|"); got != "c/messages: one|c/messages: two|c/messages: three|c/messages: rotated" {
		t.Fatalf("%s", got)
	}
	s.save(ctx, true)
	if got := r.off.get("s")["db/c/messages"]; got != 8 {
		t.Fatalf("offset %d", got)
	}
}

// More than the read window written between two reads: the rest is counted as skipped.
func TestSinkSkipped(t *testing.T) {
	r := newRig()
	p := "/j/db_c/var/log/messages"
	r.rd.set(p, "")
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Queue: 100000, Sources: api.LogSinkSource{Jails: []string{"c"}}})
	s.cycle(ctx)
	line := strings.Repeat("x", 99) + "\n"
	r.rd.set(p, strings.Repeat(line, 20000)) // 2,000,000 bytes
	s.cycle(ctx)
	st := s.status()
	if st.SkippedBytes == 0 || st.SkippedBytes+(st.Sent+int64(st.Queued))*100 != 2000000 {
		t.Fatalf("%+v", st)
	}
}

// A full queue drops the oldest lines and counts them; the offsets move past what was given up.
func TestSinkOverflow(t *testing.T) {
	r := newRig()
	p := "/j/db_c/var/log/messages"
	r.rd.set(p, "")
	r.snd.fail = errors.New("connection refused")
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Queue: 100, Sources: api.LogSinkSource{Jails: []string{"c"}}})
	s.cycle(ctx)
	var b strings.Builder
	for i := range 250 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	r.rd.add(p, b.String())
	s.cycle(ctx)
	st := s.status()
	if st.Queued != 100 || st.Dropped != 150 || st.Sent != 0 || st.LastError != "connection refused" || st.FailingSince == nil {
		t.Fatalf("%+v", st)
	}
	r.snd.fail = nil
	r.clock.advance(time.Minute)
	s.cycle(ctx)
	got := r.snd.take()
	if len(got) != 100 || got[0] != "c/messages: line 150" {
		t.Fatalf("%d %q", len(got), got[:1])
	}
	if st := s.status(); st.FailingSince != nil || st.Sent != 100 || st.LastSuccess == nil {
		t.Fatalf("%+v", st)
	}
}

// After a failure the sink waits for the backoff before it sends again; it keeps reading meanwhile.
func TestSinkBackoff(t *testing.T) {
	r := newRig()
	p := "/j/db_c/var/log/messages"
	r.rd.set(p, "")
	r.snd.fail = errors.New("down")
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Sources: api.LogSinkSource{Jails: []string{"c"}}})
	s.cycle(ctx)
	r.rd.add(p, "x\n")
	s.cycle(ctx) // first failure: next try in 500ms (jitter 0)
	if r.snd.calls != 1 || !s.nextTry.Equal(t0.Add(500*time.Millisecond)) {
		t.Fatalf("calls %d next %v", r.snd.calls, s.nextTry)
	}
	r.clock.advance(400 * time.Millisecond)
	s.cycle(ctx)
	if r.snd.calls != 1 {
		t.Fatalf("sent before the backoff ended")
	}
	r.clock.advance(100 * time.Millisecond)
	s.cycle(ctx) // second failure: one second
	if r.snd.calls != 2 || !s.nextTry.Equal(r.clock.Now().Add(time.Second)) {
		t.Fatalf("calls %d next %v", r.snd.calls, s.nextTry)
	}
	r.rd.add(p, "y\n")
	s.cycle(ctx)
	if st := s.status(); st.Queued != 2 || r.snd.calls != 2 {
		t.Fatalf("%+v calls %d", st, r.snd.calls)
	}
	// a sink failing for more than five minutes is what doctor reports
	r.clock.advance(6 * time.Minute)
	if st := s.status(); st.FailingSince == nil || r.clock.Now().Sub(*st.FailingSince) < 5*time.Minute {
		t.Fatalf("%+v", st)
	}
}

func TestSinkAudit(t *testing.T) {
	r := newRig()
	var recs []AuditRecord
	for i := int64(1); i <= 5; i++ {
		recs = append(recs, AuditRecord{ID: i, Time: t0, Project: "web", Line: fmt.Sprintf("entry %d", i)})
	}
	last := int64(3)
	r.env.AuditLast = func(context.Context) (int64, error) { return last, nil }
	r.env.AuditAfter = func(_ context.Context, after int64, limit int) ([]AuditRecord, error) {
		var out []AuditRecord
		for _, a := range recs[:last] {
			if a.ID > after && len(out) < limit {
				out = append(out, a)
			}
		}
		return out, nil
	}
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Sources: api.LogSinkSource{NoJails: true, Audit: true}})
	s.cycle(ctx)
	last = 5
	s.cycle(ctx)
	if got := strings.Join(r.snd.take(), "|"); got != "/audit: entry 4|/audit: entry 5" {
		t.Fatalf("%s", got)
	}
	s.save(ctx, true)
	if got := r.off.get("s"); got["audit"] != 5 {
		t.Fatalf("%v", got)
	}
}

// The forwarder's loops, status reads and reconfigurations run at once (go test -race).
func TestForwarderConcurrent(t *testing.T) {
	r := newRig()
	r.rd.set("/j/web_a/var/log/messages", "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	f := New(*r.env)
	k := api.LogSink{Name: "a", Type: api.LogSinkSyslog, To: "tcp://" + ln.Addr().String()}
	f.Apply([]api.LogSink{k})
	if st := f.Status(); len(st) != 1 || st[0].Name != "a" {
		t.Fatalf("before start: %+v", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.Start(ctx)
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				_ = f.Status()
				if i == 0 {
					r.rd.add("/j/web_a/var/log/messages", fmt.Sprintf("l %d\n", j))
					r.clock.advance(2 * time.Second)
				}
				if i == 1 && j%5 == 0 {
					k2 := k
					k2.Facility = fmt.Sprintf("local%d", j%8)
					f.Apply([]api.LogSink{k2, {Name: "b", Type: api.LogSinkSyslog, To: k.To}})
				}
			}
		}()
	}
	wg.Wait()
	f.Apply([]api.LogSink{{Name: "b", Type: api.LogSinkSyslog, To: k.To}})
	cancel()
	f.Wait()
	if _, ok := r.off.get("a")["web/a/messages"]; ok {
		t.Fatalf("offsets of a removed sink were kept: %v", r.off.m)
	}
}

// A sink that starts on a host without jails reads the first jail that appears from its beginning.
func TestSinkFirstJailAfterStart(t *testing.T) {
	r := newRig()
	jails := r.jails
	r.jails = nil
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Sources: api.LogSinkSource{NoAppLogs: true}})
	s.cycle(ctx)
	r.jails = jails[:1]
	r.rd.set("/j/web_a/var/log/messages", "booted\n")
	r.clock.advance(time.Minute)
	s.cycle(ctx)
	if got := strings.Join(r.snd.take(), "|"); got != "a/messages: booted" {
		t.Fatalf("%q", got)
	}
}

// The tables of a sink do not keep a jail that was deleted (a daemon that runs for a year makes and deletes many).
func TestSinkForgetsADeletedJail(t *testing.T) {
	r := newRig()
	r.rd.set("/j/web_a/var/log/messages", "old\n")
	r.rd.set("/j/web_b/var/log/messages", "old\n")
	ctx := context.Background()
	s := r.sink(api.LogSink{Name: "s", Sources: api.LogSinkSource{NoAppLogs: true}})
	s.cycle(ctx)
	r.rd.add("/j/web_a/var/log/messages", "new a\n")
	r.rd.add("/j/web_b/var/log/messages", "new b\n")
	r.clock.advance(2 * time.Second)
	s.cycle(ctx)
	r.snd.take()
	if _, ok := s.read["web/b/messages"]; !ok {
		t.Fatalf("read %v acked %v", s.read, s.acked)
	}
	var left []Jail
	for _, j := range r.jails {
		if j.Name != "b" {
			left = append(left, j)
		}
	}
	r.jails = left // jail b is deleted
	r.clock.advance(time.Minute)
	s.cycle(ctx)
	for _, m := range []map[string]int64{s.read, s.acked} {
		if _, ok := m["web/b/messages"]; ok {
			t.Fatalf("a deleted jail is still in the tables: read %v acked %v", s.read, s.acked)
		}
		if _, ok := m["web/a/messages"]; !ok {
			t.Fatalf("a live jail left the tables: read %v acked %v", s.read, s.acked)
		}
	}
	if _, ok := s.pending["web/b/messages"]; ok {
		t.Fatalf("pending %v", s.pending)
	}
}
