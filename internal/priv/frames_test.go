package priv

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// gatedServer serves a helper whose zfs.receive waits for its context (or the
// gate), so a request stays in flight while the test sends frames for it.
func gatedServer(t *testing.T) (*fixture, chan struct{}) {
	t.Helper()
	e := newEnv(t)
	gate := make(chan struct{})
	l, err := NewLocal(e.cfg, Deps{ZFS: &gatedZFS{Fake: e.zfs, gate: gate}, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	e.local = l
	t.Cleanup(func() { close(gate) })
	return e.serve(t, selfPeers()), gate
}

// readUntilClosed reads frames until the server closes the connection; it
// fails when the connection stays open.
func readUntilClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := ReadFrame(c); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("the server kept the connection open")
			}
			return
		}
	}
}

func TestDataAfterEndClosesTheConnection(t *testing.T) {
	f, _ := gatedServer(t)
	c := rawConn(t, f.sock)
	WriteFrame(c, &Frame{Kind: KindHello, V: ProtocolVersion})
	if h, err := ReadFrame(c); err != nil || h.Err != nil {
		t.Fatalf("hello: %+v %v", h, err)
	}
	WriteFrame(c, &Frame{Kind: KindReq, ID: 1, Op: OpZFSReceive, Args: []byte(`{"Target":"tank/jailops/x"}`)})
	WriteFrame(c, &Frame{Kind: KindEnd, ID: 1})
	WriteFrame(c, &Frame{Kind: KindData, ID: 1, Data: []byte("late")})
	readUntilClosed(t, c)
	if !strings.Contains(f.audit.String(), "data after end") {
		t.Errorf("the violation is not in the audit log:\n%s", f.audit)
	}
	// the helper is alive and other connections work
	c2, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := c2.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("a fresh connection after the violation: %v", err)
	}
}

// socketPair returns the two ends of a unix stream socketpair.
func socketPair(t *testing.T) (srv, cli *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conv := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "pair")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conv(fds[0]), conv(fds[1])
}

// TestRandomFrameSequencesNeverPanic sends random frame sequences (known and
// unknown ids, every client frame kind, frames after a request finished) to
// the server's connection loop over a socketpair. The loop must never panic,
// must end when the client goes away, and a fresh connection must still work.
func TestRandomFrameSequencesNeverPanic(t *testing.T) {
	f, _ := gatedServer(t)
	srv := f.srv
	kinds := []string{KindReq, KindData, KindEnd, KindAck, KindCtl, KindCancel}
	ops := []struct{ op, args string }{
		{OpZFSReceive, `{"Target":"tank/jailops/x"}`}, // waits for its context
		{OpZFSExists, `{"name":"tank/jailops"}`},      // answers at once
		{"no.such.op", `{}`},
	}
	const rounds = 300
	for seed := int64(1); seed <= rounds; seed++ {
		rng := rand.New(rand.NewSource(seed))
		sc, cc := socketPair(t)
		done := make(chan any, 1)
		go func() {
			defer func() { done <- recover() }()
			srv.serveConn(sc)
		}()
		WriteFrame(cc, &Frame{Kind: KindHello, V: ProtocolVersion})
		if h, err := ReadFrame(cc); err != nil || h.Err != nil {
			t.Fatalf("seed %d: hello %+v %v", seed, h, err)
		}
		// drain what the server sends, so its writes never block
		go func() {
			for {
				if _, err := ReadFrame(cc); err != nil {
					return
				}
			}
		}()
		n := 1 + rng.Intn(40)
		for i := 0; i < n; i++ {
			fr := &Frame{Kind: kinds[rng.Intn(len(kinds))], ID: uint64(rng.Intn(4))}
			switch fr.Kind {
			case KindReq:
				o := ops[rng.Intn(len(ops))]
				fr.Op, fr.Args = o.op, []byte(o.args)
			case KindData:
				fr.Data = make([]byte, rng.Intn(3)) // empty data is a violation too
			case KindCtl:
				fr.Op, fr.Args = "resize", []byte(`{"rows":1,"cols":1}`)
			}
			if WriteFrame(cc, fr) != nil {
				break // the server closed the connection
			}
			if rng.Intn(8) == 0 {
				time.Sleep(time.Millisecond) // let requests finish in between
			}
		}
		cc.Close()
		select {
		case p := <-done:
			if p != nil {
				t.Fatalf("seed %d: the connection loop panicked: %v", seed, p)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("seed %d: the connection loop did not end", seed)
		}
	}
	c, err := Dial(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ZFS().Exists(context.Background(), "tank/jailops"); err != nil {
		t.Errorf("a fresh connection after %d random sequences: %v", rounds, err)
	}
}
