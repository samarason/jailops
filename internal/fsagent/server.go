package fsagent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/internal/repo/catalog"
)

// Config configures an agent.
type Config struct {
	Mode Mode
	// Root is the directory every path is below ("/" in the chrooted agent of jailops-priv). The tests
	// use a directory and no chroot.
	Root string
	// Attrs collects and applies extended attributes (nil = the platform's).
	Attrs catalog.Attrs
	// MaxRequests bounds the requests a read agent works on at once (default 64).
	MaxRequests int
	// Special lets a write agent make device nodes and setuid or setgid files. The helper sets it only for a tree
	// a jail controls (its root or a volume mounted in it), which no user of the host can reach; elsewhere such a
	// file is refused (a device node) or written without the bits.
	Special bool
}

// Serve answers the client on rw until it hangs up (nil) or sends something it must not (an error).
func Serve(rw io.ReadWriter, cfg Config) error {
	if cfg.Root == "" {
		cfg.Root = "/"
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 64
	}
	switch cfg.Mode {
	case ModeRead:
		return serveRead(rw, cfg)
	case ModeWrite:
		return serveWrite(rw, cfg)
	}
	return fmt.Errorf("fsagent: unknown mode %q", cfg.Mode)
}

// abs maps a path of the client's view to the agent's: below Root, never above it.
func (c Config) abs(p string) string {
	return filepath.Join(c.Root, filepath.Clean("/"+p))
}

type sender struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *sender) send(f frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFrame(s.w, f)
}

func (s *sender) fail(id uint32, err error) error {
	return s.send(frame{kind: kindError, id: id, body: encodeErr(err, errors.Is(err, catalog.ErrSocket))})
}

func (s *sender) reply(id uint32, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return s.fail(id, err)
	}
	return s.send(frame{kind: kindReply, id: id, body: b})
}

// ---- read agent ----

type stream struct {
	mu      sync.Mutex
	cond    *sync.Cond
	credit  int
	aborted bool
}

func newStream(window int) *stream {
	s := &stream{credit: window}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stream) grant(n int) {
	s.mu.Lock()
	s.credit += n
	s.mu.Unlock()
	s.cond.Broadcast()
}

func (s *stream) abort() {
	s.mu.Lock()
	s.aborted = true
	s.mu.Unlock()
	s.cond.Broadcast()
}

// take waits for credit for up to n bytes and returns how many may be sent (0 when aborted).
func (s *stream) take(n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.credit <= 0 && !s.aborted {
		s.cond.Wait()
	}
	if s.aborted {
		return 0
	}
	if n > s.credit {
		n = s.credit
	}
	s.credit -= n
	return n
}

func serveRead(rw io.ReadWriter, cfg Config) error {
	br := bufio.NewReaderSize(rw, 256<<10)
	out := &sender{w: rw}
	fsys := catalog.LocalFS(cfg.Attrs)
	var (
		mu      sync.Mutex
		streams = map[uint32]*stream{}
		wg      sync.WaitGroup
		sem     = make(chan struct{}, cfg.MaxRequests)
	)
	defer func() {
		mu.Lock()
		for _, s := range streams {
			s.abort()
		}
		mu.Unlock()
		wg.Wait()
	}()
	for {
		f, err := readFrame(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		switch f.kind {
		case kindCredit:
			if len(f.body) == 4 {
				mu.Lock()
				s := streams[f.id]
				mu.Unlock()
				if s != nil {
					s.grant(int(uint32(f.body[0])<<24 | uint32(f.body[1])<<16 | uint32(f.body[2])<<8 | uint32(f.body[3])))
				}
			}
		case kindAbort:
			mu.Lock()
			s := streams[f.id]
			mu.Unlock()
			if s != nil {
				s.abort()
			}
		case kindQuery:
			var req request
			if err := json.Unmarshal(f.body, &req); err != nil {
				_ = out.fail(f.id, fmt.Errorf("bad request: %w", err))
				continue
			}
			var st *stream
			if req.Op == opOpen {
				w := req.Window
				if w <= 0 || w > 8<<20 {
					w = DefaultWindow
				}
				st = newStream(w)
				mu.Lock()
				streams[f.id] = st
				mu.Unlock()
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(id uint32, req request, st *stream) {
				defer wg.Done()
				defer func() { <-sem }()
				if st != nil {
					defer func() { mu.Lock(); delete(streams, id); mu.Unlock() }()
				}
				handleRead(out, cfg, fsys, id, req, st)
			}(f.id, req, st)
		default:
			return fmt.Errorf("fsagent: a read agent got a %q frame", f.kind)
		}
	}
}

func handleRead(out *sender, cfg Config, fsys catalog.ScanFS, id uint32, req request, st *stream) {
	switch req.Op {
	case opStat:
		e, nlink, dev, err := fsys.StatEntry(cfg.abs(req.Path), req.Name)
		if err != nil {
			_ = out.fail(id, err)
			return
		}
		b, err := json.Marshal(e)
		if err != nil {
			_ = out.fail(id, err)
			return
		}
		_ = out.reply(id, statReply{Entry: b, Nlink: nlink, Dev: dev})
	case opNames:
		names, err := fsys.ReadNames(cfg.abs(req.Path))
		if err != nil {
			_ = out.fail(id, err)
			return
		}
		_ = out.reply(id, namesReply{Names: names})
	case opOpen:
		f, err := openRegular(cfg.abs(req.Path))
		if err != nil {
			_ = out.fail(id, err)
			return
		}
		defer f.Close()
		if err := out.reply(id, struct{}{}); err != nil {
			return
		}
		buf := make([]byte, ChunkSize)
		for {
			n := st.take(len(buf))
			if n == 0 {
				return // aborted
			}
			m, rerr := f.Read(buf[:n])
			if m > 0 {
				// give back what was not used
				if m < n {
					st.grant(n - m)
				}
				if err := out.send(frame{kind: kindData, id: id, body: append([]byte(nil), buf[:m]...)}); err != nil {
					return
				}
			} else {
				st.grant(n)
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					_ = out.send(frame{kind: kindEnd, id: id})
				} else {
					_ = out.send(frame{kind: kindError, id: id, body: encodeErr(rerr, false)})
				}
				return
			}
		}
	default:
		_ = out.fail(id, fmt.Errorf("a read agent does not do %q", req.Op))
	}
}

// openRegular opens a regular file for reading without following a symlink and without ever blocking on a
// fifo or a device.
func openRegular(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: path, Err: errors.New("not a regular file")}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ---- write agent ----

func serveWrite(rw io.ReadWriter, cfg Config) error {
	br := bufio.NewReaderSize(rw, 256<<10)
	out := &sender{w: rw}
	sink := catalog.LocalSink(cfg.Root, cfg.Attrs)
	for {
		f, err := readFrame(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		if f.kind != kindQuery {
			return fmt.Errorf("fsagent: a write agent got a %q frame between requests", f.kind)
		}
		var req request
		if err := json.Unmarshal(f.body, &req); err != nil {
			_ = out.fail(f.id, fmt.Errorf("bad request: %w", err))
			continue
		}
		if err := handleWrite(out, br, sink, f.id, req, cfg.Special); err != nil {
			return err // the stream is out of step: end the session
		}
	}
}

// handleWrite does one request. It returns an error only when the connection can no longer be trusted
// to be in step; the operation's own failure is an X reply.
func handleWrite(out *sender, br *bufio.Reader, sink catalog.Sink, id uint32, req request, special bool) error {
	reply := func(err error, v any) error {
		if err != nil {
			return out.fail(id, err)
		}
		if v == nil {
			v = struct{}{}
		}
		return out.reply(id, v)
	}
	switch req.Op {
	case opBegin:
		return reply(sink.Begin(), nil)
	case opMkdir:
		return reply(sink.Mkdir(req.Rel), nil)
	case opSymlink:
		return reply(sink.Symlink(req.Rel, req.Target), nil)
	case opLink:
		return reply(sink.Link(req.Rel, req.Target), nil)
	case opMknod:
		if t := req.Mode & unix.S_IFMT; !special && (t == unix.S_IFCHR || t == unix.S_IFBLK) {
			return reply(fmt.Errorf("mknod %s: device nodes are restored only into a jail's root", req.Rel), nil)
		}
		return reply(sink.Mknod(req.Rel, req.Mode, req.Major, req.Minor), nil)
	case opApply:
		var e catalog.Entry
		if err := json.Unmarshal(req.Entry, &e); err != nil {
			return reply(fmt.Errorf("bad entry: %w", err), nil)
		}
		var dropped []string
		if bits := specialBits(&e); !special && e.Mode&bits != 0 {
			dropped = append(dropped, fmt.Sprintf("%s: mode %04o restored without setuid and setgid (not in a jail's root)", req.Rel, e.Mode&0o7777))
			e.Mode &^= bits
		}
		skipped, err := sink.Apply(req.Rel, &e, req.Link, catalog.MetaOptions{NoChown: req.NoChown, Lenient: req.Lenient})
		if err != nil {
			return reply(err, nil)
		}
		return reply(nil, applyReply{Skipped: append(dropped, skipped...)})
	case opWrite:
		in := &dataReader{br: br, id: id}
		err := sink.WriteFile(req.Rel, req.Size, req.Sum, in)
		// the client sends the whole stream before it waits: read what is left up to the end
		if derr := in.drain(); derr != nil {
			return derr
		}
		if err == nil && in.aborted {
			err = errors.New("the client abandoned the file")
		}
		return reply(err, nil)
	}
	return reply(fmt.Errorf("a write agent does not do %q", req.Op), nil)
}

// specialBits are the mode bits a write agent drops outside a jail's root: setuid, and setgid except on a
// directory (where it only steers the group of new files).
func specialBits(e *catalog.Entry) uint32 {
	if e.Kind == catalog.KDir {
		return 0o4000
	}
	return 0o6000
}

// dataReader reads the D frames of a write up to the E frame.
type dataReader struct {
	br      *bufio.Reader
	id      uint32
	cur     []byte
	done    bool
	aborted bool
	err     error
}

func (d *dataReader) Read(p []byte) (int, error) {
	for len(d.cur) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if d.err != nil {
			return 0, d.err
		}
		f, err := readFrame(d.br)
		if err != nil {
			d.err = err
			return 0, err
		}
		if f.id != d.id {
			d.err = fmt.Errorf("fsagent: data frame of request %d inside request %d", f.id, d.id)
			return 0, d.err
		}
		switch f.kind {
		case kindData:
			d.cur = f.body
		case kindEnd:
			d.done = true
		case kindAbort:
			d.done, d.aborted = true, true
		default:
			d.err = fmt.Errorf("fsagent: a %q frame inside a file", f.kind)
			return 0, d.err
		}
	}
	n := copy(p, d.cur)
	d.cur = d.cur[n:]
	return n, nil
}

// drain consumes the rest of the stream (a short write leaves frames behind).
func (d *dataReader) drain() error {
	var buf [ChunkSize]byte
	for !d.done {
		if _, err := d.Read(buf[:]); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}
