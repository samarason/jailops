package server

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// a command that does not read: Write waits until released or closed
type blockedStdin struct {
	mu      sync.Mutex
	got     bytes.Buffer
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockedStdin() *blockedStdin {
	return &blockedStdin{release: make(chan struct{}), closed: make(chan struct{})}
}

func (b *blockedStdin) Write(p []byte) (int, error) {
	select {
	case <-b.release:
	case <-b.closed:
		return 0, errors.New("closed")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.got.Write(p)
}

func (b *blockedStdin) Close() error { b.once.Do(func() { close(b.closed) }); return nil }

func (b *blockedStdin) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.got.String() }

func TestStdinPumpNeverBlocksTheFrameLoop(t *testing.T) {
	w := newBlockedStdin()
	p := newStdinPump(w)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ { // the command does not read at all: pushing must not wait
			if !p.push(bytes.Repeat([]byte("x"), 1000)) {
				t.Error("the backlog limit was reached too early")
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("push waited for a command that does not read")
	}
	// the session ends (Ctrl-C was seen): the blocked write returns and the pump ends
	p.stop()
	select {
	case <-w.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not close the command's stdin")
	}
}

func TestStdinPumpDeliversInOrderAndClosesAfterTheQueue(t *testing.T) {
	w := newBlockedStdin()
	close(w.release) // the command reads
	p := newStdinPump(w)
	for _, s := range []string{"one ", "two ", "three"} {
		p.push([]byte(s))
	}
	p.closeInput()
	select {
	case <-w.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("stdin was not closed after the queued input")
	}
	if got := w.text(); got != "one two three" {
		t.Fatalf("got %q", got)
	}
}

func TestStdinPumpBacklogIsBounded(t *testing.T) {
	w := newBlockedStdin()
	p := newStdinPump(w)
	defer p.stop()
	chunk := bytes.Repeat([]byte("y"), 64<<10)
	n := 0
	for p.push(chunk) {
		if n++; n > 1000 {
			t.Fatal("the backlog has no limit")
		}
	}
	if n < maxStdinBacklog/len(chunk)-1 {
		t.Fatalf("limit reached after %d chunks", n)
	}
}
