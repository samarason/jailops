package daemon_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/leakcheck"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// listJails lists the jails the way a client does (the SDK iterates pages).
func listJails(ctx context.Context, c *sdk.Client) error {
	for _, err := range c.Jails().List(ctx) {
		if err != nil {
			return err
		}
	}
	return nil
}

// A daemon that is started and stopped leaves nothing running: every loop, listener and watcher ends with the
// daemon's context.
func TestLeakDaemonStartStop(t *testing.T) {
	e := dtest.New(t, dtest.Options{NoStart: true})
	e.Start() // the first start pays for lazily started package-level things
	e.Stop()
	base := leakcheck.Take()
	for i := 0; i < 12; i++ {
		e.Start()
		e.Stop()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base.Verify(t, "12 daemon start/stop cycles", 3, 4)
}

// Plain requests, good and refused ones, leave no goroutine or descriptor behind and the heap does not grow with
// their number.
func TestLeakRequestCycles(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	for i := 0; i < 50; i++ { // warm up: connection pools, caches
		if err := listJails(ctx, e.Admin); err != nil {
			t.Fatal(err)
		}
	}
	anon := e.Anonymous()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base := leakcheck.Take()
	const n = 3000
	for i := 0; i < n; i++ {
		if err := listJails(ctx, e.Admin); err != nil {
			t.Fatal(err)
		}
		if i%6 == 0 {
			if err := listJails(ctx, anon); err == nil {
				t.Fatal("an anonymous request was served")
			}
		}
		if i%10 == 0 {
			if code, _ := e.Raw("GET", "/api/v1/nothing-here", e.Token(api.PermAdmin), ""); code != 404 {
				t.Fatalf("unknown route: %d", code)
			}
		}
	}
	_ = anon.Close()
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	growth := base.Verify(t, fmt.Sprintf("%d request cycles", n), 6, 6)
	if growth > 8<<20 {
		t.Errorf("the heap grew by %d bytes over %d requests", growth, n)
	}
}

// Creating and deleting jails over and over leaves no goroutine, descriptor or (much) memory behind: operations,
// per-jail maps and watchers of deleted jails are released.
func TestLeakJailCycles(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	cycle := func(i int) {
		name := fmt.Sprintf("w%d", i)
		op, err := e.Admin.Jails().Create(ctx, dtest.WebJail(name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		so, err := e.Admin.Jails().Start(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := so.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		es, err := e.Admin.Jails().Exec(ctx, name, []string{"echo", "x"}, sdk.ExecOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, es.Stdout())
		_, _ = es.Wait()
		_ = es.Close()
		xo, err := e.Admin.Jails().Stop(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := xo.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		do, err := e.Admin.Jails().Delete(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := do.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		cycle(i)
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base := leakcheck.Take()
	const n = 80
	for i := 5; i < 5+n; i++ {
		cycle(i)
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	growth := base.Verify(t, fmt.Sprintf("%d create/start/stop/delete cycles", n), 6, 6)
	if growth > 24<<20 {
		t.Errorf("the heap grew by %d bytes over %d jail cycles", growth, n)
	}
}

// Event streams that clients open and drop leave no goroutine in the bus, the server or the client.
func TestLeakEventStreams(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	one := func() {
		ctx, cancel := context.WithCancel(context.Background())
		ch := e.Events(ctx, e.Admin)
		_ = listJails(context.Background(), e.Admin)
		cancel()
		for range ch { // drain until the stream ends
		}
	}
	for i := 0; i < 5; i++ {
		one()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base := leakcheck.Take()
	for i := 0; i < 300; i++ {
		one()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base.Verify(t, "300 event streams opened and dropped", 6, 6)
}

// An exec session whose client never reads the output and just closes: the client's reader goroutine must end
// (the SDK reads the connection in a goroutine that writes into an unbuffered pipe).
func TestLeakExecClientAbandonsOutput(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	op, err := e.Admin.Jails().Create(ctx, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	so, err := e.Admin.Jails().Start(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base := leakcheck.Take()
	for i := 0; i < 100; i++ {
		s, err := e.Admin.Jails().Exec(ctx, "web", []string{"echo", "some output the client never reads"}, sdk.ExecOptions{})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		_ = s.Close() // no Wait, no read
	}
	base.Verify(t, "100 exec sessions closed without reading the output", 6, 6)
}

// Exec sessions that run to the end and are read leave nothing behind.
func TestLeakExecSessions(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	op, err := e.Admin.Jails().Create(ctx, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	so, err := e.Admin.Jails().Start(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	run := func() {
		s, err := e.Admin.Jails().Exec(ctx, "web", []string{"echo", "x"}, sdk.ExecOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, s.Stdout())
		_, _ = s.Wait()
		_ = s.Close()
	}
	for i := 0; i < 5; i++ {
		run()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base := leakcheck.Take()
	for i := 0; i < 300; i++ {
		run()
	}
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	base.Verify(t, "300 exec sessions run to the end", 6, 6)
}
