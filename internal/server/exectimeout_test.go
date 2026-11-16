package server_test

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// An exec session over the daemon's own listener outlives the listener's read timeout: the upgraded connection
// does not keep the deadline of the request that opened it. (The read timeout is 2 minutes; the test makes it 1s.)
func TestExecOverTheListenerOutlivesTheReadTimeout(t *testing.T) {
	e := dtest.New(t, dtest.Options{Listen: true, ReadTimeout: time.Second})
	e.Seed()
	startedWeb(t, e)
	c, err := sdk.Connect(context.Background(), sdk.Local(sdk.WithSocket(filepath.Join(e.Dir, "jailops.sock")),
		sdk.WithToken(e.Token(api.PermAdmin)), sdk.WithProject(dtest.SeedProject)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := c.Jails().Exec(context.Background(), "web", []string{"cat"}, sdk.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	go func() {
		defer s.Stdin().Close()
		for time.Since(start) < 2500*time.Millisecond {
			if _, err := s.Stdin().Write([]byte("ping\n")); err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	if s.Stderr() != nil {
		go func() { _, _ = io.Copy(io.Discard, s.Stderr()) }()
	}
	n, _ := io.Copy(io.Discard, s.Stdout())
	code, _ := s.Wait()
	if code != 0 || time.Since(start) < 2500*time.Millisecond || n < 5*12 {
		t.Errorf("the session ended after %v with %d and %d bytes", time.Since(start).Round(time.Millisecond), code, n)
	}
}
