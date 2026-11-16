package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// The browser console. The exec protocol is an HTTP upgrade, which a browser cannot open, so the web console
// uses a session instead: POST /api/v1/jails/<n>/console starts a command with a terminal and returns an id,
// GET .../console/<id>/output streams what it prints as server-sent events, POST .../input, POST .../resize and
// DELETE do the rest. The session is the same service.StartExec as the upgrade route (same project rules, same
// per-jail limits, same audit entries) and belongs to the identity that opened it.

const (
	// consoleBuffer is how much output a session keeps for a client that reconnects (Last-Event-ID).
	consoleBuffer = 1 << 20
	consoleChunk  = 16 << 10
	// maxConsoleInput bounds one input request.
	maxConsoleInput = 64 << 10
	// perIdentity and total bound the open console sessions.
	maxConsolesPerIdentity = 8
	maxConsoles            = 64
)

type consoleEvent struct {
	seq  int64
	data []byte
	exit *int
}

type consoleSession struct {
	id string
	// owner is the identity that opened the session: the kind of its credential and its name.
	owner   string
	project string
	jail    string
	st      *service.ExecStart
	cancel  context.CancelFunc

	mu     sync.Mutex
	cond   *sync.Cond
	events []consoleEvent
	size   int
	next   int64
	done   bool
	last   time.Time
}

type consoleRegistry struct {
	mu   sync.Mutex
	byID map[string]*consoleSession
}

func (r *consoleRegistry) add(cs *consoleSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = map[string]*consoleSession{}
	}
	n := 0
	for _, o := range r.byID {
		if o.owner == cs.owner {
			n++
		}
	}
	switch {
	case n >= maxConsolesPerIdentity:
		return api.Errorf(api.CodeBusy, "%s already has %d console sessions open", cs.owner, maxConsolesPerIdentity).WithHint("close one first")
	case len(r.byID) >= maxConsoles:
		return api.Errorf(api.CodeBusy, "the host has %d console sessions open", maxConsoles)
	}
	r.byID[cs.id] = cs
	return nil
}

func (r *consoleRegistry) get(id string) *consoleSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byID[id]
}

func (r *consoleRegistry) remove(id string) {
	r.mu.Lock()
	delete(r.byID, id)
	r.mu.Unlock()
}

// consoleRef stands for a session id in logs, audit entries and errors: whoever holds the id may drive the session
// (with the owner's credential), so only a short hash of it is written down.
func consoleRef(id string) string {
	h := sha256.Sum256([]byte(id))
	return "#" + hex.EncodeToString(h[:4])
}

// consoleObject is the audit object of a request about a console session.
func consoleObject(jail, id string) string {
	return "/api/v1/jails/" + jail + "/console/" + consoleRef(id)
}

// redactConsolePath replaces the session id in a console path by its reference, for the request log.
func redactConsolePath(p string) string {
	rest, ok := strings.CutPrefix(p, "/api/v1/jails/")
	if !ok {
		return p
	}
	jail, after, ok := strings.Cut(rest, "/console/")
	if !ok || strings.Contains(jail, "/") || after == "" {
		return p
	}
	id, tail, _ := strings.Cut(after, "/")
	out := consoleObject(jail, id)
	if tail != "" {
		out += "/" + tail
	}
	return out
}

func newConsoleID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (cs *consoleSession) push(data []byte, exit *int) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.next++
	cs.events = append(cs.events, consoleEvent{seq: cs.next, data: data, exit: exit})
	cs.size += len(data)
	for cs.size > consoleBuffer && len(cs.events) > 1 {
		cs.size -= len(cs.events[0].data)
		cs.events = cs.events[1:]
	}
	if exit != nil {
		cs.done = true
	}
	cs.cond.Broadcast()
}

func (cs *consoleSession) touch() {
	cs.mu.Lock()
	cs.last = time.Now()
	cs.mu.Unlock()
}

// consoleFor returns the session of the request: it must exist, belong to the caller and to this jail and project.
func (s *Server) consoleFor(c *rc) (*consoleSession, error) {
	cs := s.consoles.get(c.pathArg("id"))
	c.object = consoleObject(c.pathArg("name"), c.pathArg("id"))
	if cs == nil || cs.owner != identityKey(c.actor) || cs.jail != c.pathArg("name") || cs.project != service.ProjectFrom(c.r.Context()) {
		// the same answer for a session that does not exist and for somebody else's
		return nil, api.Errorf(api.CodeNotFound, "console session %s does not exist", consoleRef(c.pathArg("id")))
	}
	return cs, nil
}

// handleConsoleOpen implements POST /api/v1/jails/<n>/console.
func (s *Server) handleConsoleOpen(c *rc) error {
	var req api.ExecRequest
	if err := c.decodeOptional(&req); err != nil {
		return err
	}
	req.TTY = true
	if len(req.Argv) == 0 {
		req.Shell = true
	}
	name := c.pathArg("name")
	c.object = "/api/v1/jails/" + name
	// the session outlives this request
	ctx, cancel := context.WithCancel(context.WithoutCancel(c.r.Context()))
	st, err := s.svc.StartExec(ctx, name, req)
	if err != nil {
		cancel()
		return err
	}
	cs := &consoleSession{id: newConsoleID(), owner: identityKey(c.actor), project: st.Project, jail: name, st: st, cancel: cancel, last: time.Now()}
	cs.cond = sync.NewCond(&cs.mu)
	if err := s.consoles.add(cs); err != nil {
		_ = st.Session.Signal(9)
		st.Release()
		cancel()
		return err
	}
	argv := fmt.Sprintf("%q", st.Argv)
	c.detail = "console argv=" + argv
	s.svc.Audit(context.WithoutCancel(c.r.Context()), storeEntry(c, "EXEC", st.Project, "console start argv="+argv))
	go func() {
		defer func() { supervise.Report(nil, "console-session", recover()) }()
		s.runConsole(cs)
	}()
	c.sync(200, map[string]string{"id": cs.id}, 0)
	return nil
}

// runConsole pumps the command's output into the session and ends it: idle, too long, or finished.
func (s *Server) runConsole(cs *consoleSession) {
	lim := s.svc.ExecLimitsOf()
	sess := cs.st.Session
	out := make(chan struct{})
	go func() {
		defer close(out)
		buf := make([]byte, consoleChunk)
		for {
			n, err := sess.Stdout().Read(buf)
			if n > 0 {
				cs.push(append([]byte(nil), buf[:n]...), nil)
			}
			if err != nil {
				return
			}
		}
	}()
	exited := make(chan int, 1)
	go func() {
		code, err := sess.Wait()
		if err != nil {
			code = -1
		}
		exited <- code
	}()
	maxT := time.NewTimer(lim.Max)
	defer maxT.Stop()
	tick := time.NewTicker(lim.Idle/4 + time.Millisecond)
	defer tick.Stop()
	var code int
loop:
	for {
		select {
		case code = <-exited:
			break loop
		case <-maxT.C:
			_ = sess.Signal(9)
		case <-tick.C:
			cs.mu.Lock()
			idle := time.Since(cs.last) > lim.Idle
			cs.mu.Unlock()
			if idle {
				_ = sess.Signal(9)
			}
		}
	}
	select {
	case <-out:
	case <-time.After(2 * time.Second):
	}
	cs.push(nil, &code)
	_ = sess.Stdin().Close()
	cs.st.Release()
	cs.cancel()
	// the session stays for a short while so that a client that was reading can fetch the exit status
	time.AfterFunc(2*time.Minute, func() { s.consoles.remove(cs.id) })
}

// handleConsoleOutput implements GET /api/v1/jails/<n>/console/<id>/output: the output as server-sent events whose
// metadata is {"data": <base64>} or {"exit": <status>}. Last-Event-ID resumes after a reconnect.
func (s *Server) handleConsoleOutput(c *rc) error {
	cs, err := s.consoleFor(c)
	if err != nil {
		return err
	}
	fl, ok := c.w.(http.Flusher)
	if !ok {
		return api.Errorf(api.CodeInternal, "streaming is not supported on this connection")
	}
	after := int64(0)
	if h := c.r.Header.Get("Last-Event-ID"); h != "" {
		n, err := strconv.ParseInt(h, 10, 64)
		if err != nil || n < 0 {
			return api.Errorf(api.CodeInvalid, "invalid Last-Event-ID %q", h)
		}
		after = n
	}
	_ = http.NewResponseController(c.w).SetWriteDeadline(time.Time{})
	h := c.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	c.w.WriteHeader(http.StatusOK)
	c.status = 200
	fmt.Fprint(c.w, "retry: 1000\n\n")
	fl.Flush()
	ctx := c.r.Context()
	// wake the wait below when the request ends
	stop := context.AfterFunc(ctx, func() { cs.mu.Lock(); cs.cond.Broadcast(); cs.mu.Unlock() })
	defer stop()
	ka := time.NewTicker(s.cfg.KeepAlive)
	defer ka.Stop()
	var revoked atomic.Bool
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ka.C:
			}
			// a credential revoked or changed since the session began ends the stream and the session
			if !s.stillAuthorized(c) {
				revoked.Store(true)
				_ = cs.st.Session.Signal(9)
			}
			cs.mu.Lock()
			cs.cond.Broadcast()
			cs.mu.Unlock()
		}
	}()
	for {
		cs.mu.Lock()
		var batch []consoleEvent
		for {
			for _, e := range cs.events {
				if e.seq > after {
					batch = append(batch, e)
				}
			}
			if revoked.Load() {
				cs.mu.Unlock()
				return nil
			}
			if len(batch) > 0 || ctx.Err() != nil {
				break
			}
			cs.cond.Wait()
			if _, err := fmt.Fprint(c.w, ": ping\n\n"); err != nil {
				cs.mu.Unlock()
				return nil
			}
			fl.Flush()
		}
		cs.mu.Unlock()
		if ctx.Err() != nil {
			return nil
		}
		for _, e := range batch {
			var meta []byte
			if e.exit != nil {
				meta, _ = json.Marshal(map[string]int{"exit": *e.exit})
			} else {
				meta, _ = json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(e.data)})
			}
			ev, _ := json.Marshal(api.Event{Type: "console", Timestamp: time.Now().UTC(), Metadata: meta})
			if _, err := fmt.Fprintf(c.w, "id: %d\ndata: %s\n\n", e.seq, ev); err != nil {
				return nil
			}
			after = e.seq
			if e.exit != nil {
				fl.Flush()
				return nil
			}
		}
		fl.Flush()
	}
}

// handleConsoleInput implements POST /api/v1/jails/<n>/console/<id>/input: {"data": "<utf-8 text>"}.
func (s *Server) handleConsoleInput(c *rc) error {
	cs, err := s.consoleFor(c)
	if err != nil {
		return err
	}
	var in struct {
		Data string `json:"data"`
	}
	c.r.Body = http.MaxBytesReader(c.w, c.r.Body, maxConsoleInput+1024)
	if err := c.decode(&in); err != nil {
		return err
	}
	if len(in.Data) > maxConsoleInput {
		return api.Errorf(api.CodeInvalid, "input of %d bytes exceeds %d", len(in.Data), maxConsoleInput)
	}
	cs.touch()
	if _, err := io.WriteString(cs.st.Session.Stdin(), in.Data); err != nil {
		return api.Errorf(api.CodeBusy, "the console session has ended")
	}
	c.sync(200, struct{}{}, 0)
	return nil
}

// handleConsoleResize implements POST /api/v1/jails/<n>/console/<id>/resize: {"cols": n, "rows": n}.
func (s *Server) handleConsoleResize(c *rc) error {
	cs, err := s.consoleFor(c)
	if err != nil {
		return err
	}
	var in struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	if err := c.decode(&in); err != nil {
		return err
	}
	if in.Cols < 1 || in.Rows < 1 || in.Cols > 1000 || in.Rows > 1000 {
		return api.Errorf(api.CodeInvalid, "the terminal size must be between 1 and 1000")
	}
	cs.touch()
	_ = cs.st.Session.Resize(in.Rows, in.Cols)
	c.sync(200, struct{}{}, 0)
	return nil
}

// handleConsoleClose implements DELETE /api/v1/jails/<n>/console/<id>.
func (s *Server) handleConsoleClose(c *rc) error {
	cs, err := s.consoleFor(c)
	if err != nil {
		return err
	}
	_ = cs.st.Session.Signal(9)
	_ = cs.st.Session.Stdin().Close() // and the end of its input, for a command that ignores the signal
	s.svc.Audit(context.WithoutCancel(c.r.Context()), storeEntry(c, "EXEC", cs.project, "console closed by the client"))
	c.sync(200, struct{}{}, 0)
	return nil
}
