package priv

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// A short command run with a terminal must deliver its whole output however fast it exits (FreeBSD hangs a terminal up
// when its session leader exits and dropped the output of `echo hi` in 3 to 30% of the runs; session_leader.go).
func TestTTYSessionDeliversTheOutputOfAShortCommand(t *testing.T) {
	const runs = 300
	lost := 0
	for i := 0; i < runs; i++ {
		s, err := startSession(context.Background(), "/bin/echo", []string{"hello-from-the-tty"}, ExecOpts{TTY: true}, func() {})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan string, 1)
		go func() { b, _ := io.ReadAll(s.Stdout()); done <- string(b) }()
		_, _ = s.Wait()
		select {
		case out := <-done:
			if !strings.Contains(out, "hello-from-the-tty") {
				lost++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the output never ended")
		}
		_ = s.Close()
	}
	if lost > 0 {
		t.Fatalf("the output was lost in %d of %d runs", lost, runs)
	}
}
