package devd

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParse(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		ok   bool
		want map[string]string
	}{
		"zfs":        {"!system=ZFS subsystem=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0\n", true, map[string]string{"system": "ZFS", "subsystem": "ZFS", "type": "ereport.fs.zfs.checksum", "pool": "tank", "vdev_path": "/dev/da0"}},
		"quoted":     {`!system=X name="a \"b\" \\ c" last=1`, true, map[string]string{"system": "X", "name": `a "b" \ c`, "last": "1"}},
		"empty val":  {"!system=ZFS pool= type=x", true, map[string]string{"system": "ZFS", "pool": "", "type": "x"}},
		"first wins": {"!a=1 a=2", true, map[string]string{"a": "1"}},
		"attach":     {"+em0 at pci0 on x", false, nil},
		"detach":     {"-em0 at pci0", false, nil},
		"nomatch":    {"?at vendor=0x8086", false, nil},
		"only bang":  {"!", false, nil},
		"empty":      {"", false, nil},
		"no key":     {"!=1", false, nil},
		"bad key":    {"!a b=1", false, nil},
		"key chars":  {"!a;b=1", false, nil},
		"open quote": {`!a="never closed`, false, nil},
		"control":    {"!a=1\x00b=2", false, nil},
		"escape":     {"!a=\x1b[31m", false, nil},
		"binary":     {"!a=\xff\xfe", false, nil},
		"too long":   {"!a=" + strings.Repeat("x", MaxRecord), false, nil},
	} {
		got, ok := Parse([]byte(tc.in))
		if ok != tc.ok {
			t.Errorf("%s: ok %v, want %v", name, ok, tc.ok)
			continue
		}
		for k, v := range tc.want {
			if got.Fields[k] != v {
				t.Errorf("%s: %s = %q, want %q", name, k, got.Fields[k], v)
			}
		}
		if ok && len(got.Fields) != len(tc.want) {
			t.Errorf("%s: fields %v, want %v", name, got.Fields, tc.want)
		}
	}
	var many strings.Builder
	many.WriteString("!")
	for i := 0; i < 70; i++ {
		many.WriteString("k" + strings.Repeat("a", i) + "=v ")
	}
	if _, ok := Parse([]byte(many.String())); ok {
		t.Error("a record with more than 64 fields was accepted")
	}
}

// FuzzParse checks that whatever the kernel or a hostile writer sends neither panics nor yields a field that is not
// printable text.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"!system=ZFS type=x", `!a="b\"`, "!a=1 b", "+x", "!", "!" + strings.Repeat("a=1 ", 100), "!a=\x00", "!\xff"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		rec, ok := Parse(in)
		if !ok {
			return
		}
		for k, v := range rec.Fields {
			if !utf8.ValidString(k) || !utf8.ValidString(v) || !validKey(k) {
				t.Fatalf("bad field %q=%q from %q", k, v, in)
			}
			for _, r := range v {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("control character in %q=%q", k, v)
				}
			}
		}
	})
}

func rec(t *testing.T, s string) Record {
	t.Helper()
	r, ok := Parse([]byte(s))
	if !ok {
		t.Fatalf("does not parse: %q", s)
	}
	return r
}

func testMapper() Mapper {
	return Mapper{
		Link: func(i string) (string, bool) {
			switch i {
			case "em0":
				return "uplink em0", true
			}
			return "", false
		},
		Jail: func(os string) (string, string, bool) {
			if os == "alpha_web" {
				return "alpha", "web", true
			}
			return "", "", false
		},
	}
}

func TestMap(t *testing.T) {
	m := testMapper()
	for name, tc := range map[string]struct {
		in   string
		want *Event
	}{
		"zfs checksum": {"!system=ZFS subsystem=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0 zio_offset=0x1",
			&Event{Action: "host-zfs-error", Source: "/api/v1/host", Detail: "pool tank: checksum on /dev/da0"}},
		"zfs vdev":    {"!system=ZFS type=ereport.fs.zfs.vdev.bad_label pool=tank", &Event{Action: "host-zfs-error", Source: "/api/v1/host", Detail: "pool tank: vdev.bad label"}},
		"zfs failure": {"!system=ZFS type=ereport.fs.zfs.io_failure pool=tank", &Event{Action: "host-zfs-error", Source: "/api/v1/host", Detail: "pool tank: io failure"}},
		"zfs delay":   {"!system=ZFS type=ereport.fs.zfs.delay pool=tank", nil},
		"zfs state":   {"!system=ZFS type=resource.fs.zfs.statechange pool_guid=123 vdev_guid=4", &Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: "pool 123: a device changed state"}},
		"zfs scrub":   {"!system=ZFS type=misc.fs.zfs.scrub_finish pool=tank", &Event{Action: "host-zfs-pool", Source: "/api/v1/host", Detail: "pool tank: scrub finished"}},
		"zfs other":   {"!system=ZFS type=misc.fs.zfs.history_event pool=tank", nil},
		"uplink down": {"!system=IFNET subsystem=em0 type=LINK_DOWN", &Event{Action: "host-link-down", Source: "/api/v1/host", Detail: "uplink em0 link down"}},
		"uplink up":   {"!system=IFNET subsystem=em0 type=LINK_UP", &Event{Action: "host-link-up", Source: "/api/v1/host", Detail: "uplink em0 link up"}},
		"unowned":     {"!system=IFNET subsystem=wlan0 type=LINK_DOWN", nil},
		"epair churn": {"!system=IFNET subsystem=jo0123456789a0a type=LINK_UP", nil},
		"attach":      {"!system=IFNET subsystem=em0 type=ATTACH", nil},
		"limit":       {"!system=RCTL subsystem=rule type=matched rule=jail:alpha_web:memoryuse:devctl=1073741824 pid=12 jail=alpha_web", &Event{Action: "jail-limit-hit", Source: "/api/v1/jails/web", Project: "alpha", Detail: "the limit memoryuse of the jail was reached"}},
		"limit rule":  {"!system=RCTL subsystem=rule type=matched rule=jail:alpha_web:maxproc:devctl=100", &Event{Action: "jail-limit-hit", Source: "/api/v1/jails/web", Project: "alpha", Detail: "the limit maxproc of the jail was reached"}},
		"limit other": {"!system=RCTL subsystem=rule type=matched rule=jail:zeta_db:memoryuse:devctl=1", nil},
		"limit user":  {"!system=RCTL subsystem=rule type=matched rule=user:joe:vmemoryuse:devctl=1", nil},
		"unknown":     {"!system=JAILOPS subsystem=test type=ping", nil},
	} {
		got, ok := m.Map(rec(t, tc.in))
		switch {
		case tc.want == nil && ok:
			t.Errorf("%s: mapped to %+v", name, got)
		case tc.want != nil && (!ok || got != *tc.want):
			t.Errorf("%s: got %+v (%v), want %+v", name, got, ok, *tc.want)
		}
	}
	if _, ok := (Mapper{}).Map(rec(t, "!system=IFNET subsystem=em0 type=LINK_DOWN")); ok {
		t.Error("a link event was mapped without a way to name the interface")
	}
	if _, ok := (Mapper{}).Map(rec(t, "!system=RCTL subsystem=rule type=matched rule=jail:alpha_web:maxproc:devctl=1")); ok {
		t.Error("a limit event was mapped without a way to find the jail")
	}
}

// A value from a record never leaves printable ASCII without spaces, whatever the writer sent.
func TestMapKeepsDetailsPlain(t *testing.T) {
	r := rec(t, `!system=ZFS type=ereport.fs.zfs.io pool="ta nké" vdev_path=`+strings.Repeat("/dev/x", 40))
	ev, ok := testMapper().Map(r)
	if !ok || len(ev.Detail) > 200 || strings.ContainsAny(ev.Detail, "\n\r\t") {
		t.Fatalf("%+v", ev)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(30*time.Second, 6)
	a := Event{Action: "a", Detail: "x"}
	if !l.allow(a, now) {
		t.Fatal("the first event was held back")
	}
	if l.allow(a, now.Add(10*time.Second)) {
		t.Error("an identical event inside the window was published")
	}
	if !l.allow(a, now.Add(31*time.Second)) {
		t.Error("an identical event after the window was held back")
	}
	// the rate: 6 a minute, a burst of 6, then one every 10 s
	l = newLimiter(time.Hour, 6)
	n := 0
	for i := 0; i < 20; i++ {
		if l.allow(Event{Action: "e", Detail: string(rune('a' + i))}, now) {
			n++
		}
	}
	if n != 6 {
		t.Errorf("%d events published in a burst, want 6", n)
	}
	if !l.allow(Event{Action: "e", Detail: "later"}, now.Add(11*time.Second)) {
		t.Error("no token came back after 11 s")
	}
}

// fakeDevd is a seqpacket socket like devd's: it sends one record per packet to whoever connects.
type fakeDevd struct {
	path string
	ln   *net.UnixListener
	mu   sync.Mutex
	conn *net.UnixConn
}

func newFakeDevd(t *testing.T, path string) *fakeDevd {
	t.Helper()
	ln, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDevd{path: path, ln: ln}
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conn = c
			f.mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeDevd) send(t *testing.T, rec string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		c := f.conn
		f.mu.Unlock()
		if c != nil {
			if _, err := c.Write([]byte(rec + "\n")); err != nil { // devd ends every record with a newline
				t.Fatal(err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("nobody connected")
}

func (f *fakeDevd) dropClient() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		_ = f.conn.Close()
		f.conn = nil
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWatcherReadsMapsAndReconnects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devd.pipe")
	var mu sync.Mutex
	var got []Event
	w := New(Config{Path: path, Mapper: testMapper(), MinRetry: 5 * time.Millisecond, MaxRetry: 20 * time.Millisecond,
		Sink: func(e Event) { mu.Lock(); got = append(got, e); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// the socket does not exist yet: the watcher waits and says why
	waitFor(t, "a status without a connection", func() bool { s := w.Status(); return !s.Connected && s.Err != "" })

	f := newFakeDevd(t, path)
	waitFor(t, "the connection", func() bool { return w.Status().Connected })
	f.send(t, "!system=IFNET subsystem=em0 type=LINK_DOWN")
	f.send(t, "!system=IFNET subsystem=em0 type=LINK_DOWN") // an identical event within the window
	f.send(t, "garbage \x00\xff")
	f.send(t, "+em0 at pci0")
	f.send(t, "!system=JAILOPS subsystem=test type=ping")
	f.send(t, "!system=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0")
	waitFor(t, "two events", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
	if got[0].Action != "host-link-down" || got[1].Action != "host-zfs-error" {
		t.Errorf("%+v", got)
	}
	if s := w.Status(); s.Published != 2 || s.Dropped != 1 {
		t.Errorf("%+v", s)
	}

	// devd goes away and comes back: the watcher reconnects by itself
	// (the watcher reconnects within milliseconds, so the test does not wait for the short time it is not connected:
	// a new connection is one whose Since is later than the old one's)
	before := w.Status().Since
	f.dropClient()
	waitFor(t, "the new connection", func() bool { s := w.Status(); return s.Connected && s.Since.After(before) })
	f.send(t, "!system=IFNET subsystem=em0 type=LINK_UP")
	waitFor(t, "an event after the reconnect", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 })
}

func TestWatcherStopsWhileWaiting(t *testing.T) {
	w := New(Config{Path: filepath.Join(t.TempDir(), "none"), MinRetry: time.Hour, MaxRetry: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	waitFor(t, "a status", func() bool { return w.Status().Err != "" })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context ended")
	}
}

// Records that arrive in one read (FreeBSD merges queued packets that the sender did not end with a record mark) are
// still read one by one: devd ends every record with a newline.
func TestWatcherSplitsTheRecordsOfOnePacket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devd.pipe")
	var mu sync.Mutex
	var got []Event
	w := New(Config{Path: path, Mapper: testMapper(), MinRetry: 5 * time.Millisecond, MaxRetry: 20 * time.Millisecond,
		Sink: func(e Event) { mu.Lock(); got = append(got, e); mu.Unlock() }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	f := newFakeDevd(t, path)
	waitFor(t, "the connection", func() bool { return w.Status().Connected })
	f.send(t, "!system=IFNET subsystem=em0 type=LINK_DOWN\n!system=ZFS type=ereport.fs.zfs.checksum pool=tank vdev_path=/dev/da0\n\n")
	waitFor(t, "two events from one packet", func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 2 })
}
