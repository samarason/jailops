package server

import (
	"io"
	"sync"
)

// maxStdinBacklog is how much input of a client may wait for a command that does not read its stdin.
const maxStdinBacklog = 1 << 20

// stdinPump writes the stdin frames of a client into the command from a goroutine of its own. The loop that reads the
// client's frames must never wait for the command to read: a full pipe would hide the next frame, so that a signal (the
// client's Ctrl-C) or the client's departure would only be seen when the command reads again.
type stdinPump struct {
	w io.WriteCloser

	mu      sync.Mutex
	cond    *sync.Cond
	queue   [][]byte
	size    int
	closing bool // the client closed its stdin: close the command's when the queue is written
	stopped bool // the session is over
}

func newStdinPump(w io.WriteCloser) *stdinPump {
	p := &stdinPump{w: w}
	p.cond = sync.NewCond(&p.mu)
	go p.run()
	return p
}

// push queues input for the command; false when the backlog exceeds the limit (the command has not read for a long time).
func (p *stdinPump) push(b []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.closing {
		return true // the command no longer reads, or the client closed stdin: input is dropped as before
	}
	if p.size+len(b) > maxStdinBacklog {
		return false
	}
	p.queue = append(p.queue, append([]byte(nil), b...))
	p.size += len(b)
	p.cond.Signal()
	return true
}

// closeInput closes the command's stdin once what was queued is written.
func (p *stdinPump) closeInput() {
	p.mu.Lock()
	p.closing = true
	p.cond.Signal()
	p.mu.Unlock()
}

// stop ends the pump: queued input is dropped and the command's stdin is closed.
func (p *stdinPump) stop() {
	p.mu.Lock()
	p.stopped = true
	p.queue, p.size = nil, 0
	p.cond.Signal()
	p.mu.Unlock()
	_ = p.w.Close() // a write that waits for the command returns with an error
}

func (p *stdinPump) run() {
	for {
		p.mu.Lock()
		for len(p.queue) == 0 && !p.closing && !p.stopped {
			p.cond.Wait()
		}
		if p.stopped {
			p.mu.Unlock()
			return
		}
		if len(p.queue) == 0 { // closing, and everything is written
			p.mu.Unlock()
			_ = p.w.Close()
			return
		}
		b := p.queue[0]
		p.queue = p.queue[1:]
		p.size -= len(b)
		p.mu.Unlock()
		if _, err := p.w.Write(b); err != nil {
			p.mu.Lock()
			p.queue, p.size = nil, 0 // the command no longer reads
			p.mu.Unlock()
		}
	}
}
