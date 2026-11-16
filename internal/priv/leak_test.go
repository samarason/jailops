//go:build linux

package priv

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/leakcheck"
)

// children lists the processes whose parent is this process, with their state letter (Z is a zombie). Linux only.
func children(t *testing.T) (live, zombies int) {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Skip("no /proc")
	}
	me := strconv.Itoa(os.Getpid())
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndex(s, ") ")
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+2:])
		if len(f) < 2 || f[1] != me {
			continue
		}
		live++
		if f[0] == "Z" {
			zombies++
		}
	}
	return
}

// Sessions of the helper that end in every way a client can end them leave no goroutine, descriptor, process or
// zombie behind: read to the end, abandoned without reading, closed in the middle, killed with a signal, with and
// without a terminal.
func TestLeakExecSessions(t *testing.T) {
	execHosts(t, func(t *testing.T, h Host, e *env) {
		ctx := context.Background()
		finish := func(s ExecSession) {
			go io.Copy(io.Discard, s.Stdout())
			if er := s.Stderr(); er != nil {
				go io.Copy(io.Discard, er)
			}
			s.Wait()
		}
		kinds := map[string]func(){
			"read to the end": func() {
				s, err := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo out; echo err >&2"}, ExecOpts{})
				if err != nil {
					t.Fatal(err)
				}
				finish(s)
			},
			"tty read to the end": func() {
				s, err := h.Exec(ctx, "alpha_web", []string{"sh", "-c", "echo out"}, ExecOpts{TTY: true, Rows: 24, Cols: 80})
				if err != nil {
					t.Fatal(err)
				}
				finish(s)
			},
			"context ended while running": func() {
				cctx, cancel := context.WithCancel(ctx)
				s, err := h.Exec(cctx, "alpha_web", []string{"sleep", "30"}, ExecOpts{})
				if err != nil {
					t.Fatal(err)
				}
				go io.Copy(io.Discard, s.Stdout())
				go io.Copy(io.Discard, s.Stderr())
				cancel()
				s.Wait()
			},
			"tty context ended while running": func() {
				cctx, cancel := context.WithCancel(ctx)
				s, err := h.Exec(cctx, "alpha_web", []string{"sleep", "30"}, ExecOpts{TTY: true})
				if err != nil {
					t.Fatal(err)
				}
				go io.Copy(io.Discard, s.Stdout())
				cancel()
				s.Wait()
			},
			"killed by a signal": func() {
				s, err := h.Exec(ctx, "alpha_web", []string{"sleep", "30"}, ExecOpts{})
				if err != nil {
					t.Fatal(err)
				}
				go io.Copy(io.Discard, s.Stdout())
				go io.Copy(io.Discard, s.Stderr())
				_ = s.Signal(9)
				s.Wait()
			},
			"stdin closed on cat": func() {
				s, err := h.Exec(ctx, "alpha_web", []string{"cat"}, ExecOpts{})
				if err != nil {
					t.Fatal(err)
				}
				go io.Copy(io.Discard, s.Stdout())
				go io.Copy(io.Discard, s.Stderr())
				s.Stdin().Write([]byte("hello"))
				s.Stdin().Close()
				s.Wait()
			},
		}
		for name, run := range kinds {
			for i := 0; i < 3; i++ { // warm up
				run()
			}
			base := leakcheck.Take()
			l0, _ := children(t)
			for i := 0; i < 40; i++ {
				run()
			}
			// the children are reaped soon after the sessions end
			var live, zom int
			for i := 0; i < 100; i++ {
				live, zom = children(t)
				if live <= l0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if zom > 0 || live > l0 {
				t.Errorf("%s: child processes %d -> %d (zombies %d)", name, l0, live, zom)
			}
			base.Verify(t, name, 4, 4)
		}
	})
}
