package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// handleExec implements POST /api/v1/jails/<n>/exec: the request is checked like
// any jail route, then the connection is upgraded to the framed stream of
// api/exec.go. Everything before the upgrade answers with an ordinary error.
func (s *Server) handleExec(c *rc) error {
	var req api.ExecRequest
	if err := c.decodeOptional(&req); err != nil {
		return err
	}
	if !strings.EqualFold(c.r.Header.Get("Upgrade"), api.ExecProtocol) || !headerHasToken(c.r.Header, "Connection", "upgrade") {
		return api.Errorf(api.CodeInvalid, "exec needs an HTTP upgrade").WithHint("send Connection: Upgrade and Upgrade: " + api.ExecProtocol)
	}
	name := c.pathArg("name")
	c.object = "/api/v1/jails/" + name
	st, err := s.svc.StartExec(c.r.Context(), name, req)
	if err != nil {
		return err
	}
	defer st.Release()
	// Every exec is audited with its argument vector, when it starts and when it ends. Long arguments (a script passed on
	// the command line, a pasted secret) are cut: the entry says what was run, not everything that was typed.
	argv := fmt.Sprintf("%q", auditArgv(st.Argv))
	c.detail = "exec argv=" + argv
	s.svc.Audit(context.WithoutCancel(c.r.Context()), storeEntry(c, "EXEC", st.Project, "start argv="+argv+fmt.Sprintf(" tty=%v", req.TTY)))
	conn, brw, err := http.NewResponseController(c.w).Hijack()
	if err != nil {
		_ = st.Session.Signal(9)
		return api.Errorf(api.CodeInternal, "this connection cannot be upgraded: %v", err)
	}
	defer conn.Close()
	c.status = http.StatusSwitchingProtocols
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + api.ExecProtocol + "\r\n\r\n")
	if err := brw.Flush(); err != nil {
		_ = st.Session.Signal(9)
		return nil
	}
	code := s.pump(conn, brw.Reader, st, s.svc.ExecLimitsOf(), func() bool { return s.stillAuthorized(c) })
	c.detail += fmt.Sprintf(" exit=%d", code)
	return nil
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// pump moves frames between the connection and the session until the command
// ends, the client goes away, the stream idles or the session lives too long.
// It returns the exit status (-1 when the session was cut off). still is asked at every keepalive tick whether the
// caller's credential still holds; a revoked one ends the session.
func (s *Server) pump(conn net.Conn, rd *bufio.Reader, st *service.ExecStart, lim service.ExecLimits, still func() bool) int {
	sess := st.Session
	var wmu sync.Mutex
	write := func(t api.FrameType, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		return api.WriteFrame(conn, t, p)
	}
	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	killed := make(chan string, 1)
	kill := func(why string) {
		select {
		case killed <- why:
		default:
		}
		_ = sess.Signal(9)
	}
	done := make(chan struct{})
	defer close(done)
	maxT := time.AfterFunc(lim.Max, func() { kill("the session reached its maximum duration") })
	defer maxT.Stop()
	go func() {
		defer func() { supervise.Report(nil, "exec-session", recover()) }()
		t := time.NewTicker(lim.Idle/4 + time.Millisecond)
		defer t.Stop()
		ka := time.NewTicker(s.cfg.KeepAlive)
		defer ka.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > lim.Idle {
					kill("the session was idle too long")
					return
				}
			case <-ka.C:
				if still != nil && !still() {
					kill("the credential of this session was revoked")
					return
				}
			}
		}
	}()
	// Client to command.
	in := newStdinPump(sess.Stdin())
	go func() {
		defer func() { supervise.Report(nil, "exec-session", recover()) }()
		defer in.stop()
		for {
			t, p, err := api.ReadFrame(rd)
			if err != nil {
				kill("the client went away")
				return
			}
			touch()
			switch t {
			case api.FrameStdin:
				if len(p) == 0 {
					in.closeInput()
					continue
				}
				if !in.push(p) {
					kill("the command did not read its input")
					return
				}
			case api.FrameResize:
				if r, c, err := api.ParseResize(p); err == nil {
					_ = sess.Resize(r, c)
				}
			case api.FrameSignal:
				if n, err := api.ParseInt32(p); err == nil && n > 0 && n < 32 {
					_ = sess.Signal(int(n))
				}
			default:
				// Only the client's frame types are valid here.
				kill("the client sent a frame that only the server sends")
				return
			}
		}
	}()
	// Command output to client.
	var wg sync.WaitGroup
	copyOut := func(r io.Reader, t api.FrameType) {
		defer wg.Done()
		buf := make([]byte, api.MaxFrame)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				touch()
				if werr := write(t, buf[:n]); werr != nil {
					kill("the client went away")
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(1)
	go copyOut(sess.Stdout(), api.FrameStdout)
	if e := sess.Stderr(); e != nil {
		wg.Add(1)
		go copyOut(e, api.FrameStderr)
	}
	code, err := sess.Wait()
	wg.Wait()
	if err != nil {
		code = -1
	}
	select {
	case why := <-killed:
		_ = write(api.FrameStderr, []byte("jailops: "+why+"\n"))
		code = -1
	default:
	}
	_ = write(api.FrameExit, api.Int32Payload(int32(code)))
	return code
}

// auditArgvMax is how many bytes of one argument an audit entry keeps.
const auditArgvMax = 200

// auditArgv is the argument vector of an exec as the audit log keeps it: each argument cut to auditArgvMax bytes.
func auditArgv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if len(a) > auditArgvMax {
			a = a[:auditArgvMax] + fmt.Sprintf("...(%d bytes more)", len(a)-auditArgvMax)
		}
		out[i] = a
	}
	return out
}
