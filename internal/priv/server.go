package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

// PeerPolicy says which peers may talk to the helper.
type PeerPolicy struct {
	// UIDs and GIDs are the accepted uids and gids (primary or supplementary).
	UIDs []uint32
	GIDs []uint32
	// DenyRoot refuses uid 0 as well (default: root is accepted, it could do
	// anything anyway).
	DenyRoot bool
}

// Allow reports whether the peer may connect.
func (p PeerPolicy) Allow(c auth.Cred) bool {
	if c.UID == 0 && !p.DenyRoot {
		return true
	}
	for _, u := range p.UIDs {
		if c.UID == u {
			return true
		}
	}
	for _, g := range p.GIDs {
		if c.InGroup(g) {
			return true
		}
	}
	return false
}

// ServerOptions configures a Server.
type ServerOptions struct {
	Peers PeerPolicy
	Audit *Auditor
	// PeerCred reads peer credentials; auth.PeerCred when nil.
	PeerCred func(*net.UnixConn) (auth.Cred, error)
	// Version is reported in the hello reply.
	Version string
}

// Server serves a Host over unix socket connections.
type Server struct {
	host    Host
	lim     Limits
	opts    ServerOptions
	audit   *Auditor
	baseCtx context.Context
	stop    context.CancelFunc

	mu     sync.Mutex
	ln     net.Listener
	conns  map[*fdConn]struct{}
	closed bool // set by Shutdown under mu: no connection is added to wg after that
	wg     sync.WaitGroup
	nextID atomic.Uint64
	slots  chan struct{}
}

// NewServer returns a Server for l.
func NewServer(l *Local, opts ServerOptions) *Server {
	if opts.PeerCred == nil {
		opts.PeerCred = auth.PeerCred
	}
	ctx, cancel := context.WithCancel(context.Background())
	lim := l.cfg.Limits
	return &Server{
		host: l, lim: lim, opts: opts, audit: opts.Audit, baseCtx: ctx, stop: cancel,
		conns: map[*fdConn]struct{}{}, slots: make(chan struct{}, lim.MaxConns),
	}
}

// Serve accepts connections until the listener closes or Shutdown is called.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.baseCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.audit.Note("priv.connection.refused", "reason", "too many connections")
			uc.Close()
			continue
		}
		// wg.Add must not run concurrently with the wg.Wait of Shutdown: both happen under mu, and Shutdown sets closed first
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.slots
			uc.Close()
			return nil
		}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			defer func() { supervise.Report(nil, "helper-connection", recover()) }()
			s.serveConn(uc)
		}()
	}
}

// Shutdown stops accepting, cancels running requests and waits for the
// connections to finish or ctx to expire.
func (s *Server) Shutdown(ctx context.Context) error {
	s.stop()
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.conns {
		c.c.Close()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type request struct {
	id     uint64
	cancel context.CancelFunc
	in     chan []byte
	// inClosed is set under session.mu when the client ended the request
	// stream and r.in is closed; data after it is a protocol violation.
	inClosed bool
	window   chan struct{} // tokens for data frames the server may send
	ctl      chan *Frame   // control frames of a session request
}

type session struct {
	s    *Server
	fc   *fdConn
	conn uint64
	cred auth.Cred
	mu   sync.Mutex
	reqs map[uint64]*request
}

func (s *Server) serveConn(uc *net.UnixConn) {
	fc := newFDConn(uc)
	defer fc.close()
	conn := s.nextID.Add(1)
	cred, err := s.opts.PeerCred(uc)
	if err != nil || !s.opts.Peers.Allow(cred) {
		s.audit.Log(AuditEvent{Conn: conn, UID: cred.UID, PID: cred.PID, Op: "connect", Outcome: string(api.CodeForbidden), Err: fmt.Sprint("peer refused: ", err)})
		_ = fc.write(&Frame{Kind: KindHello, V: ProtocolVersion, Err: &WireError{Code: api.CodeForbidden, Message: "peer is not allowed"}})
		return
	}
	s.mu.Lock()
	s.conns[fc] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.conns, fc); s.mu.Unlock() }()

	// Hello: bounded wait so an idle connect cannot hold a slot.
	_ = uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, _, err := fc.read()
	_ = uc.SetReadDeadline(time.Time{})
	if err != nil || h.Kind != KindHello {
		return
	}
	if h.V != ProtocolVersion {
		_ = fc.write(&Frame{Kind: KindHello, V: ProtocolVersion, Err: &WireError{Code: api.CodeVersionSkew, Message: fmt.Sprintf("protocol version %d is not supported (server speaks %d)", h.V, ProtocolVersion)}})
		return
	}
	if err := fc.write(&Frame{Kind: KindHello, V: ProtocolVersion, Info: map[string]string{"version": s.opts.Version, "window": fmt.Sprint(Window)}}); err != nil {
		return
	}
	s.audit.Note("priv.connection", "conn", conn, "uid", cred.UID, "pid", cred.PID)

	ctx, cancel := context.WithCancel(s.baseCtx)
	defer cancel()
	sess := &session{s: s, fc: fc, conn: conn, cred: cred, reqs: map[uint64]*request{}}
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	// violation notes a protocol violation; the caller then closes the connection
	violation := func(reason string, id uint64) {
		s.audit.Note("priv.protocol.violation", "conn", conn, "req", id, "reason", reason)
	}
	for {
		f, files, err := fc.read()
		if err != nil {
			if !isClosedErr(err) && ctx.Err() == nil {
				s.audit.Note("priv.connection.error", "conn", conn, "error", err.Error())
			}
			return
		}
		for _, fl := range files {
			fl.Close() // clients never send descriptors
		}
		if f.NFds != 0 {
			violation("descriptors from a client", f.ID)
			return
		}
		switch f.Kind {
		case KindReq:
			wg.Add(1)
			if !sess.start(ctx, f, &wg) {
				wg.Done()
			}
		case KindData:
			r, open := sess.input(f.ID)
			if r == nil {
				continue // the request already finished
			}
			if !open {
				violation("data after end", f.ID)
				return
			}
			if len(f.Data) == 0 || len(f.Data) > ChunkSize {
				violation("bad data frame", f.ID)
				return
			}
			// only this loop closes r.in (endInput), so the stream is still open here
			select {
			case r.in <- f.Data:
			default:
				violation("data beyond the window", f.ID)
				return
			}
		case KindEnd:
			sess.endInput(f.ID)
		case KindAck:
			// r.window and r.ctl are never closed: a frame for a request
			// that finishes meanwhile lands in a buffer nobody reads
			if r := sess.get(f.ID); r != nil {
				select {
				case r.window <- struct{}{}:
				default:
					violation("ack beyond the window", f.ID)
					return
				}
			}
		case KindCtl:
			if r := sess.get(f.ID); r != nil {
				select {
				case r.ctl <- f:
				default:
					violation("too many control frames", f.ID)
					return
				}
			}
		case KindCancel:
			if r := sess.get(f.ID); r != nil {
				r.cancel() // idempotent, also after the request finished
			}
		default:
			violation("unknown frame kind", f.ID)
			return
		}
	}
}

func (ss *session) get(id uint64) *request {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.reqs[id]
}

// input returns request id and whether its request stream is still open.
func (ss *session) input(id uint64) (*request, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	r := ss.reqs[id]
	return r, r != nil && !r.inClosed
}

// endInput closes the request stream of id once; an unknown id is ignored.
func (ss *session) endInput(id uint64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if r := ss.reqs[id]; r != nil && !r.inClosed {
		r.inClosed = true
		close(r.in)
	}
}

func (ss *session) reply(f *Frame, files ...*os.File) {
	_ = ss.fc.write(f, files...)
}

// start registers a request and runs it. It reports whether a goroutine was
// started (the caller's WaitGroup entry then belongs to it).
func (ss *session) start(parent context.Context, f *Frame, wg *sync.WaitGroup) bool {
	s := ss.s
	refuse := func(code api.Code, format string, a ...any) bool {
		ss.reply(&Frame{Kind: KindRes, ID: f.ID, Err: &WireError{Code: code, Message: fmt.Sprintf(format, a...)}})
		return false
	}
	if f.ID == 0 {
		return refuse(api.CodeInvalid, "request id must not be 0")
	}
	op := opTable[f.Op]
	if op == nil {
		ss.audit(f, "", string(api.CodeUnsupported), "unknown operation", 0)
		return refuse(api.CodeUnsupported, "unknown operation %q", f.Op)
	}
	ss.mu.Lock()
	if _, dup := ss.reqs[f.ID]; dup {
		ss.mu.Unlock()
		return refuse(api.CodeInvalid, "duplicate request id")
	}
	if len(ss.reqs) >= s.lim.MaxInflight {
		ss.mu.Unlock()
		ss.audit(f, "", string(api.CodeBusy), "too many requests in flight", 0)
		return refuse(api.CodeBusy, "too many requests in flight (limit %d)", s.lim.MaxInflight)
	}
	max := s.lim.MaxTimeout
	if op.stream {
		max = s.lim.MaxStreamTimeout
	}
	timeout := s.lim.DefaultTimeout
	if op.stream {
		timeout = max
	}
	if f.Deadline > 0 {
		timeout = time.Until(time.UnixMilli(f.Deadline))
	}
	if timeout > max {
		timeout = max
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	r := &request{id: f.ID, cancel: cancel, in: make(chan []byte, Window), window: make(chan struct{}, Window), ctl: make(chan *Frame, 16)}
	for i := 0; i < Window; i++ {
		r.window <- struct{}{}
	}
	ss.reqs[f.ID] = r
	ss.mu.Unlock()

	admin := ""
	if f.Admin != nil && f.Admin.User != "" {
		ctx = WithAdmin(ctx, f.Admin.User)
		admin = f.Admin.User
	}
	go func() {
		defer wg.Done()
		defer cancel()
		defer func() { ss.mu.Lock(); delete(ss.reqs, f.ID); ss.mu.Unlock() }()
		started := time.Now()
		target := auditTarget(f.Op, f.Args)
		ss.s.audit.Log(AuditEvent{Conn: ss.conn, UID: ss.cred.UID, PID: ss.cred.PID, Req: f.ID, Op: f.Op, Admin: admin, Target: target, Outcome: "start"})
		cio := &callIO{In: &inReader{ctx: ctx, r: r, ss: ss}, Out: &outWriter{ctx: ctx, r: r, ss: ss},
			ErrOut: &outWriter{ctx: ctx, r: r, ss: ss, ch: "e"}, Ctl: r.ctl,
			Send: func(m *Frame) error { m.ID = r.id; return ss.fc.write(m) }}
		res, err := ss.run(ctx, op, f, cio)
		out := &Frame{Kind: KindRes, ID: f.ID}
		if res != nil && (err == nil || op.stream) {
			if b, merr := marshalResult(res); merr == nil {
				out.Result = b
			} else if err == nil {
				err = api.Errorf(api.CodeInternal, "encode result: %v", merr)
			}
		}
		out.Err = toWire(err)
		ev := AuditEvent{Conn: ss.conn, UID: ss.cred.UID, PID: ss.cred.PID, Req: f.ID, Op: f.Op, Admin: admin, Target: target, Outcome: "ok", Dur: time.Since(started)}
		if err != nil {
			ev.Outcome, ev.Err = string(out.Err.Code), err.Error()
			if out.Err.Exit != nil {
				ev.Outcome = "exit"
			}
		}
		s.audit.Log(ev)
		ss.reply(out, cio.Files...)
		for _, fl := range cio.Files {
			fl.Close()
		}
	}()
	return true
}

func (ss *session) audit(f *Frame, admin, outcome, msg string, d time.Duration) {
	ss.s.audit.Log(AuditEvent{Conn: ss.conn, UID: ss.cred.UID, PID: ss.cred.PID, Req: f.ID, Op: f.Op, Admin: admin, Outcome: outcome, Err: msg, Dur: d})
}

// run calls the handler and converts a panic into an error.
func (ss *session) run(ctx context.Context, op *opDef, f *Frame, cio *callIO) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			ss.s.audit.Note("priv.panic", "op", op.name, "panic", fmt.Sprint(p), "stack", clip(string(debug.Stack()), 2000))
			res, err = nil, api.Errorf(api.CodeInternal, "internal error in %s", op.name)
		}
	}()
	return op.fn(ctx, ss.s.host, f.Args, cio)
}

// inReader feeds the request stream to a handler and acknowledges chunks.
type inReader struct {
	ctx  context.Context
	r    *request
	ss   *session
	left []byte
}

func (ir *inReader) Read(p []byte) (int, error) {
	if len(ir.left) == 0 {
		select {
		case b, ok := <-ir.r.in:
			if !ok {
				return 0, io.EOF
			}
			ir.left = b
			ir.ss.reply(&Frame{Kind: KindAck, ID: ir.r.id})
		case <-ir.ctx.Done():
			return 0, ir.ctx.Err()
		}
	}
	n := copy(p, ir.left)
	ir.left = ir.left[n:]
	return n, nil
}

// outWriter sends handler output as data frames within the window.
type outWriter struct {
	ctx context.Context
	r   *request
	ss  *session
	ch  string
}

func (ow *outWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > ChunkSize {
			n = ChunkSize
		}
		select {
		case <-ow.r.window:
		case <-ow.ctx.Done():
			return total, ow.ctx.Err()
		}
		if err := ow.ss.fc.write(&Frame{Kind: KindData, ID: ow.r.id, Ch: ow.ch, Data: append([]byte(nil), p[:n]...)}); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func marshalResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFrame-4096 {
		return nil, errors.New("result too large")
	}
	return b, nil
}
