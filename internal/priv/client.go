package priv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Client talks to a Server. One connection carries many concurrent requests.
// If the connection is lost the next call dials again.
type Client struct {
	socket string

	mu     sync.Mutex
	conn   *clientConn
	closed bool
}

var _ Host = (*Client)(nil)

// Dial connects to the helper socket and performs the version handshake.
func Dial(socket string) (*Client, error) {
	c := &Client{socket: socket}
	if _, err := c.connection(); err != nil {
		return nil, err
	}
	return c, nil
}

// NewClient wraps an established connection (no redial).
func NewClient(uc *net.UnixConn) (*Client, error) {
	cc, err := newClientConn(uc)
	if err != nil {
		return nil, err
	}
	return &Client{conn: cc}, nil
}

// Close closes the connection; calls in flight fail.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.conn != nil {
		return c.conn.fc.close()
	}
	return nil
}

func (c *Client) connection() (*clientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, api.Errorf(api.CodeInternal, "priv client is closed")
	}
	if c.conn != nil && !c.conn.isDead() {
		return c.conn, nil
	}
	if c.socket == "" {
		return nil, api.Errorf(api.CodeInternal, "connection to the privileged helper was lost")
	}
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.socket, Net: "unix"})
	if err != nil {
		return nil, api.Errorf(api.CodeInternal, "cannot connect to the privileged helper at %s: %v", c.socket, err)
	}
	cc, err := newClientConn(uc)
	if err != nil {
		return nil, err
	}
	c.conn = cc
	return cc, nil
}

// ---- one connection ----

type clientConn struct {
	fc   *fdConn
	mu   sync.Mutex
	next uint64
	call map[uint64]*clientCall
	dead chan struct{}
	err  error
	// ServerInfo is the hello info of the server.
	info map[string]string
}

type reply struct {
	f     *Frame
	files []*os.File
}

type clientCall struct {
	id     uint64
	res    chan reply
	out    chan []byte   // chunks from the server, nil when unused
	errOut chan []byte   // stderr chunks of a session, nil when unused
	ctl    chan *Frame   // control frames from the server (session started)
	window chan struct{} // tokens for data frames the client may send
}

func newClientConn(uc *net.UnixConn) (*clientConn, error) {
	fc := newFDConn(uc)
	if err := fc.write(&Frame{Kind: KindHello, V: ProtocolVersion}); err != nil {
		// A server that refuses the peer answers and closes at once; the
		// answer is still waiting to be read.
		_ = uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if h, _, rerr := fc.read(); rerr == nil && h.Kind == KindHello && h.Err != nil {
			fc.close()
			return nil, fromWire(h.Err)
		}
		fc.close()
		return nil, api.Errorf(api.CodeInternal, "helper handshake: %v", err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	h, _, err := fc.read()
	_ = uc.SetReadDeadline(time.Time{})
	if err != nil {
		fc.close()
		return nil, api.Errorf(api.CodeInternal, "helper handshake: %v", err)
	}
	if h.Kind != KindHello {
		fc.close()
		return nil, api.Errorf(api.CodeInternal, "helper handshake: unexpected %q frame", h.Kind)
	}
	if h.Err != nil {
		fc.close()
		return nil, fromWire(h.Err)
	}
	if h.V != ProtocolVersion {
		fc.close()
		return nil, api.Errorf(api.CodeVersionSkew, "helper speaks protocol %d, this client speaks %d", h.V, ProtocolVersion)
	}
	cc := &clientConn{fc: fc, call: map[uint64]*clientCall{}, dead: make(chan struct{}), info: h.Info}
	go cc.readLoop()
	return cc, nil
}

func (cc *clientConn) isDead() bool {
	select {
	case <-cc.dead:
		return true
	default:
		return false
	}
}

func (cc *clientConn) fail(err error) {
	cc.mu.Lock()
	if cc.err == nil {
		cc.err = err
		close(cc.dead)
	}
	cc.mu.Unlock()
	cc.fc.close()
}

func (cc *clientConn) lookup(id uint64) *clientCall {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.call[id]
}

func (cc *clientConn) readLoop() {
	for {
		f, files, err := cc.fc.read()
		if err != nil {
			cc.fail(api.Errorf(api.CodeInternal, "connection to the privileged helper lost: %v", err))
			return
		}
		call := cc.lookup(f.ID)
		switch f.Kind {
		case KindRes:
			if call == nil {
				closeFiles(files)
				continue
			}
			if call.out != nil {
				close(call.out)
			}
			if call.errOut != nil {
				close(call.errOut)
			}
			call.res <- reply{f, files}
		case KindData:
			closeFiles(files)
			dst := (chan []byte)(nil)
			if call != nil {
				dst = call.out
				if f.Ch == "e" {
					dst = call.errOut
				}
			}
			if dst == nil || len(f.Data) == 0 || len(f.Data) > ChunkSize {
				if call != nil {
					cc.fail(errors.New("protocol violation by the server"))
					return
				}
				continue
			}
			select {
			case dst <- f.Data:
			default:
				cc.fail(errors.New("protocol violation by the server: window exceeded"))
				return
			}
		case KindCtl:
			closeFiles(files)
			if call != nil && call.ctl != nil {
				select {
				case call.ctl <- f:
				default:
				}
			}
		case KindAck:
			closeFiles(files)
			if call != nil {
				select {
				case call.window <- struct{}{}:
				default:
				}
			}
		default:
			closeFiles(files)
			cc.fail(fmt.Errorf("protocol violation by the server: %q frame", f.Kind))
			return
		}
	}
}

func closeFiles(fs []*os.File) {
	for _, f := range fs {
		f.Close()
	}
}

// callOpts carries the streams of a call.
type callOpts struct {
	in  io.Reader
	out io.Writer
	// fill makes the request stream go out in full chunks. A bulk stream (a zfs send) arrives from its producer in
	// many small writes, and with a window of eight frames a frame per write is bounded by round trips, not by the
	// disk.
	fill bool
}

// do performs one call and returns the reply frame and any descriptors.
func (c *Client) do(ctx context.Context, op string, args any, o callOpts) (*Frame, []*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	cc, err := c.connection()
	if err != nil {
		return nil, nil, err
	}
	var raw json.RawMessage
	if args != nil {
		if raw, err = json.Marshal(args); err != nil {
			return nil, nil, err
		}
	}
	call := &clientCall{res: make(chan reply, 1), window: make(chan struct{}, Window)}
	for i := 0; i < Window; i++ {
		call.window <- struct{}{}
	}
	if o.out != nil {
		call.out = make(chan []byte, Window)
	}
	cc.mu.Lock()
	cc.next++
	call.id = cc.next
	cc.call[call.id] = call
	cc.mu.Unlock()
	defer func() { cc.mu.Lock(); delete(cc.call, call.id); cc.mu.Unlock() }()

	req := &Frame{Kind: KindReq, ID: call.id, Op: op, Args: raw}
	if dl, ok := ctx.Deadline(); ok {
		req.Deadline = dl.UnixMilli()
	}
	if a := AdminFrom(ctx); a != nil {
		req.Admin = &Admin{User: a.User}
	}
	if err := cc.fc.write(req); err != nil {
		cc.fail(err)
		return nil, nil, api.Errorf(api.CodeInternal, "send to the privileged helper: %v", err)
	}
	cancelCall := func() { _ = cc.fc.write(&Frame{Kind: KindCancel, ID: call.id}) }

	stop := make(chan struct{})
	var streamErr error
	var smu sync.Mutex
	setErr := func(err error) {
		smu.Lock()
		if streamErr == nil {
			streamErr = err
		}
		smu.Unlock()
	}
	if o.in != nil {
		go func() {
			buf := make([]byte, ChunkSize)
			for {
				var n int
				var rerr error
				if o.fill {
					n, rerr = io.ReadFull(o.in, buf)
					if rerr == io.ErrUnexpectedEOF {
						rerr = io.EOF
					}
				} else {
					n, rerr = o.in.Read(buf)
				}
				if n > 0 {
					select {
					case <-call.window:
					case <-stop:
						return
					case <-cc.dead:
						return
					}
					if werr := cc.fc.write(&Frame{Kind: KindData, ID: call.id, Data: append([]byte(nil), buf[:n]...)}); werr != nil {
						return
					}
				}
				if rerr != nil {
					if rerr == io.EOF {
						_ = cc.fc.write(&Frame{Kind: KindEnd, ID: call.id})
					} else {
						setErr(rerr)
						cancelCall()
					}
					return
				}
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	var cwg sync.WaitGroup
	if o.out != nil {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			failed := false
			for {
				select {
				case chunk, ok := <-call.out:
					if !ok {
						return
					}
					if !failed {
						if _, werr := o.out.Write(chunk); werr != nil {
							failed = true
							setErr(werr)
							cancelCall()
						}
					}
					_ = cc.fc.write(&Frame{Kind: KindAck, ID: call.id})
				case <-stop:
					return
				}
			}
		}()
	}
	finish := func() { close(stop); cwg.Wait() }

	select {
	case r := <-call.res:
		cwg.Wait() // all output chunks are delivered before the reply
		close(stop)
		smu.Lock()
		se := streamErr
		smu.Unlock()
		if r.f.Err != nil {
			closeFiles(r.files)
			if cerr := ctx.Err(); cerr != nil {
				return r.f, nil, cerr
			}
			return r.f, nil, fromWire(r.f.Err)
		}
		if se != nil {
			closeFiles(r.files)
			return r.f, nil, se
		}
		return r.f, r.files, nil
	case <-ctx.Done():
		cancelCall()
		finish()
		return nil, nil, ctx.Err()
	case <-cc.dead:
		finish()
		cc.mu.Lock()
		err := cc.err
		cc.mu.Unlock()
		return nil, nil, err
	}
}

// callJSON runs a call and decodes its result into R.
func callJSON[R any](ctx context.Context, c *Client, op string, args any, o callOpts) (R, error) {
	var r R
	f, files, err := c.do(ctx, op, args, o)
	closeFiles(files)
	if err != nil {
		return r, err
	}
	if len(f.Result) > 0 {
		if err := json.Unmarshal(f.Result, &r); err != nil {
			return r, api.Errorf(api.CodeInternal, "bad reply from the helper: %v", err)
		}
	}
	return r, nil
}

func callNone(ctx context.Context, c *Client, op string, args any) error {
	_, err := callJSON[empty](ctx, c, op, args, callOpts{})
	return err
}

// ---- Host methods that are not an adapter ----

// ReadFile implements Host.
func (c *Client) ReadFile(ctx context.Context, path string) ([]byte, error) {
	r, err := callJSON[dataRes](ctx, c, OpFSRead, ReadFileReq{Path: path}, callOpts{})
	return r.V, err
}

// WriteFile implements Host.
func (c *Client) WriteFile(ctx context.Context, q WriteFileReq) error {
	return callNone(ctx, c, OpFSWrite, q)
}

// MkdirAll implements Host.
func (c *Client) MkdirAll(ctx context.Context, q MkdirReq) error {
	return callNone(ctx, c, OpFSMkdir, q)
}

// SetVolumeOwner implements Host.
func (c *Client) SetVolumeOwner(ctx context.Context, q VolumeOwnerReq) error {
	return callNone(ctx, c, OpFSVolOwner, q)
}

// ProbeSource implements Host.
func (c *Client) ProbeSource(ctx context.Context, q SourceProbeReq) (SourceProbe, error) {
	return callJSON[SourceProbe](ctx, c, OpFSSourceProbe, q, callOpts{})
}

// StaleMounts implements Host.
func (c *Client) StaleMounts(ctx context.Context) ([]StaleMount, error) {
	r, err := callJSON[StaleMountsRes](ctx, c, OpMountsStale, empty{}, callOpts{})
	return r.Mounts, err
}

// HealJail implements Host.
func (c *Client) HealJail(ctx context.Context, jail string) (HealJailRes, error) {
	return callJSON[HealJailRes](ctx, c, OpJailHeal, HealJailReq{Jail: jail}, callOpts{})
}

// DNSUnbound implements Host.
func (c *Client) DNSUnbound(ctx context.Context, apply bool) (UnboundRes, error) {
	return callJSON[UnboundRes](ctx, c, OpDNSUnbound, DNSUnboundReq{Apply: apply}, callOpts{})
}

// HealNetwork implements Host.
func (c *Client) HealNetwork(ctx context.Context) (HealNetRes, error) {
	return callJSON[HealNetRes](ctx, c, OpNetHeal, empty{}, callOpts{})
}

// Remove implements Host.
func (c *Client) Remove(ctx context.Context, path string) error {
	return callNone(ctx, c, OpFSRemove, RemoveReq{Path: path})
}

// RemoveAll implements Host.
func (c *Client) RemoveAll(ctx context.Context, path string) error {
	return callNone(ctx, c, OpFSRemoveAll, RemoveReq{Path: path})
}

// ListLogs implements Host.
func (c *Client) ListLogs(ctx context.Context, dir string) ([]api.JailLogFile, bool, error) {
	r, err := callJSON[ListLogsRes](ctx, c, OpFSListLogs, listLogsArgs{Dir: dir}, callOpts{})
	return r.Files, r.Truncated, err
}

// TailFile implements Host.
func (c *Client) TailFile(ctx context.Context, path string, offset, limit int64) ([]byte, int64, int64, error) {
	r, err := callJSON[TailFileRes](ctx, c, OpFSTailFile, TailFileReq{Path: path, Offset: offset, Max: limit}, callOpts{})
	return r.Data, r.Start, r.Size, err
}

// Mount implements Host.
func (c *Client) Mount(ctx context.Context, dataset string) error {
	return callNone(ctx, c, OpZFSMount, nameArgs{dataset})
}

// Unmount implements Host.
func (c *Client) Unmount(ctx context.Context, dataset string) error {
	return callNone(ctx, c, OpZFSUnmount, nameArgs{dataset})
}

// Sysctl implements Host.
func (c *Client) Sysctl(ctx context.Context, name string) (string, error) {
	r, err := callJSON[strRes](ctx, c, OpSysctl, nameArgs{name}, callOpts{})
	return r.V, err
}

// NDPOpen implements Host: the helper opens the capture and passes the descriptor over the socket (SCM_RIGHTS).
func (c *Client) NDPOpen(ctx context.Context, uplink string, promisc bool) (*os.File, error) {
	_, files, err := c.do(ctx, OpNDPOpen, ndpArgs{Uplink: uplink, Promisc: promisc}, callOpts{})
	if err != nil {
		return nil, err
	}
	if len(files) != 1 {
		closeFiles(files)
		return nil, api.Errorf(api.CodeInternal, "helper returned %d descriptors, want 1", len(files))
	}
	return files[0], nil
}

// NDPAnswer implements Host.
func (c *Client) NDPAnswer(ctx context.Context, q NDPAnswerReq) error {
	return callNone(ctx, c, OpNDPAnswer, q)
}

// FSAgent implements Host: the helper starts the agent and passes the daemon's end of the connection over
// the socket (SCM_RIGHTS).
func (c *Client) FSAgent(ctx context.Context, mode, root string) (*os.File, error) {
	_, files, err := c.do(ctx, OpFSAgent, agentArgs{Mode: mode, Root: root}, callOpts{})
	if err != nil {
		return nil, err
	}
	if len(files) != 1 {
		closeFiles(files)
		return nil, api.Errorf(api.CodeInternal, "helper returned %d descriptors, want 1", len(files))
	}
	return files[0], nil
}

// ---- Runner and Jails.Exec helpers ----

// collector gathers stdout up to a limit.
type collector struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *collector) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - c.buf.Len(); len(p) > room {
		c.truncated = true
		p = p[:max(room, 0)]
	}
	c.buf.Write(p)
	return n, nil
}

type runnerAdapter struct{ c *Client }

// Runner returns a run.Runner that executes only what CommandRules allows,
// inside the helper.
func (c *Client) Runner() run.Runner { return runnerAdapter{c} }

func (a runnerAdapter) Run(ctx context.Context, cmd run.Cmd) (run.Result, error) {
	if cmd.Env != nil || cmd.Dir != "" {
		return run.Result{}, invalid("env and dir cannot be set")
	}
	args := runArgs{Name: cmd.Name, Args: cmd.Args, Stdin: cmd.Stdin != nil, MaxOutput: cmd.MaxOutput}
	if cmd.Timeout > 0 {
		args.TimeoutMs = cmd.Timeout.Milliseconds()
	}
	return a.c.exec(ctx, OpRun, args, cmd.Stdin, cmd.Stdout, cmd.MaxOutput)
}

// exec runs a streaming command operation and rebuilds run.Result.
func (c *Client) exec(ctx context.Context, op string, args any, in io.Reader, out io.Writer, maxOut int) (run.Result, error) {
	var col *collector
	w := out
	if w == nil {
		if maxOut <= 0 {
			maxOut = run.DefaultMaxStdout
		}
		col = &collector{max: maxOut}
		w = col
	}
	f, files, err := c.do(ctx, op, args, callOpts{in: in, out: w})
	closeFiles(files)
	var res run.Result
	if f != nil && len(f.Result) > 0 {
		_ = json.Unmarshal(f.Result, &res)
	}
	if col != nil {
		res.Stdout = col.buf.Bytes()
		res.Truncated = res.Truncated || col.truncated
	}
	return res, err
}

// ---- storage, tree copy, MTU and NDP routes ----

// RegisterStorage implements Host. It needs the admin assertion in ctx
// (WithAdmin).
func (c *Client) RegisterStorage(ctx context.Context, dataset string) error {
	return callNone(ctx, c, OpStorageRegister, storageArgs{dataset})
}

// UnregisterStorage implements Host. It needs the admin assertion in ctx.
func (c *Client) UnregisterStorage(ctx context.Context, dataset string) error {
	return callNone(ctx, c, OpStorageUnregister, storageArgs{dataset})
}

// Storages implements Host: the active storage roots, sorted.
func (c *Client) Storages(ctx context.Context) ([]string, error) {
	r, err := callJSON[strsRes](ctx, c, OpStorageList, empty{}, callOpts{})
	return r.V, err
}

// SetMTU implements Host.
func (c *Client) SetMTU(ctx context.Context, iface string, mtu int) error {
	return callNone(ctx, c, OpNetSetMTU, mtuArgs{iface, mtu})
}

// NDPRouteAdd implements Host.
func (c *Client) NDPRouteAdd(ctx context.Context, addr netip.Addr, iface string) error {
	return callNone(ctx, c, OpNDPRouteAdd, ndpRouteArgs{addr, iface})
}

// NDPRouteDelete implements Host.
func (c *Client) NDPRouteDelete(ctx context.Context, addr netip.Addr, iface string) error {
	return callNone(ctx, c, OpNDPRouteDelete, ndpRouteArgs{addr, iface})
}

// progressWriter turns the JSON lines of fs.copy_tree into callbacks.
type progressWriter struct {
	fn  func(CopyProgress)
	buf []byte
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(w.buf)+len(p) <= 4096 {
				w.buf = append(w.buf, p...)
			} else {
				w.buf = w.buf[:0]
			}
			break
		}
		line := append(w.buf, p[:i]...)
		w.buf = w.buf[:0]
		p = p[i+1:]
		var cp CopyProgress
		if w.fn != nil && len(line) <= 4096 && json.Unmarshal(line, &cp) == nil {
			w.fn(cp)
		}
	}
	return n, nil
}

// CopyTree implements Host; o.Progress receives the progress lines.
func (c *Client) CopyTree(ctx context.Context, src, dst string, o CopyOpts) (CopyResult, error) {
	fn := o.Progress
	o.Progress = nil
	return callJSON[CopyResult](ctx, c, OpFSCopyTree, copyArgs{src, dst, o}, callOpts{out: &progressWriter{fn: fn}})
}

// SeedKeys implements Host.
func (c *Client) SeedKeys(ctx context.Context, root string) (CopyResult, error) {
	return callJSON[CopyResult](ctx, c, OpFSSeedKeys, nameArgs{root}, callOpts{out: &progressWriter{}})
}
