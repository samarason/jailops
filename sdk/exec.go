package sdk

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"jailops.net/jailops/sdk/api"
)

// ExecOptions are the options of Jails().Exec.
type ExecOptions struct {
	// TTY asks for a pseudo-terminal of Rows by Cols; stderr is then merged
	// into stdout.
	TTY        bool
	Rows, Cols uint16
	// Env adds NAME=value entries to the command's environment.
	Env []string
	// User runs the command as this user of the jail.
	User string
	// Shell runs the jail's shell instead of argv; ShellPath overrides which.
	Shell     bool
	ShellPath string
}

// ExecSession is a command running in a jail. Stdout and Stderr must be read
// (or drained) for Wait to return; Stderr is nil in TTY mode.
type ExecSession struct {
	conn   io.ReadWriteCloser
	wmu    sync.Mutex
	stdin  *execStdin
	outR   *io.PipeReader
	errR   *io.PipeReader
	done   chan struct{}
	code   int
	err    error
	closeO sync.Once
}

type execStdin struct{ s *ExecSession }

func (w execStdin) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		c := p
		if len(c) > api.MaxFrame {
			c = c[:api.MaxFrame]
		}
		if err := w.s.write(api.FrameStdin, c); err != nil {
			return n, err
		}
		n += len(c)
		p = p[len(c):]
	}
	return n, nil
}

// Close sends end of input.
func (w execStdin) Close() error { return w.s.write(api.FrameStdin, nil) }

func (s *ExecSession) write(t api.FrameType, p []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return api.WriteFrame(s.conn, t, p)
}

// Stdin is the input of the command; closing it ends the input.
func (s *ExecSession) Stdin() io.WriteCloser { return s.stdin }

// Stdout is the output of the command.
func (s *ExecSession) Stdout() io.Reader { return s.outR }

// Stderr is the error output; nil in TTY mode.
func (s *ExecSession) Stderr() io.Reader {
	if s.errR == nil {
		return nil
	}
	return s.errR
}

// Resize tells a terminal session its new size.
func (s *ExecSession) Resize(rows, cols uint16) error {
	return s.write(api.FrameResize, api.ResizePayload(rows, cols))
}

// Signal sends a signal to the command.
func (s *ExecSession) Signal(sig int) error {
	return s.write(api.FrameSignal, api.Int32Payload(int32(sig)))
}

// Wait returns the exit status once the command has ended and its output was
// read. A session the server cut off (idle, too long) returns -1.
func (s *ExecSession) Wait() (int, error) {
	<-s.done
	return s.code, s.err
}

// Close drops the connection; the server ends the command.
func (s *ExecSession) Close() error {
	err := s.conn.Close()
	// The goroutine that reads the connection writes into unbuffered pipes: when nobody reads them it would wait for
	// ever on its first frame. Closing the reading ends makes that write fail and the goroutine end.
	if s.outR != nil {
		_ = s.outR.Close()
	}
	if s.errR != nil {
		_ = s.errR.Close()
	}
	return err
}

// Exec runs argv in a running jail over an upgraded connection. The same
// authentication, project and role rules as every jail route apply; the
// request fails with an ordinary error (not_found, busy, ...) before the
// stream starts.
func (j *JailClient) Exec(ctx context.Context, name string, argv []string, o ExecOptions) (*ExecSession, error) {
	if err := j.c.need("jail_exec"); err != nil {
		_ = err // servers that predate the extension answer unsupported themselves
	}
	body, _ := json.Marshal(api.ExecRequest{Argv: argv, Shell: o.Shell, ShellPath: o.ShellPath, TTY: o.TTY, Rows: o.Rows, Cols: o.Cols, Env: o.Env, User: o.User})
	target := j.c.buildURL(j.r.item(name)+"/exec", nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	j.c.decorate(req, newRequestID())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", api.ExecProtocol)
	resp, err := j.c.streamClient().Do(req)
	if err != nil {
		if j.c.t.ctx.Err() != nil {
			return nil, ErrClosed
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_, derr := decodeResponse(resp.StatusCode, data)
		if derr == nil {
			derr = api.Errorf(api.CodeInternal, "the server did not upgrade the connection (status %d)", resp.StatusCode)
		}
		return nil, derr
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		return nil, api.Errorf(api.CodeInternal, "the connection cannot be upgraded here")
	}
	s := &ExecSession{conn: rwc, done: make(chan struct{})}
	s.stdin = &execStdin{s}
	outR, outW := io.Pipe()
	s.outR = outR
	var errW *io.PipeWriter
	if !o.TTY {
		s.errR, errW = io.Pipe()
	}
	go func() {
		defer close(s.done)
		defer outW.Close()
		if errW != nil {
			defer errW.Close()
		}
		rd := bufio.NewReader(rwc)
		for {
			t, p, err := api.ReadFrame(rd)
			if err != nil {
				if s.code == 0 {
					s.code = -1
				}
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
					s.err = err
				} else {
					s.err = fmt.Errorf("jailops: the exec connection ended without an exit status")
				}
				return
			}
			switch t {
			case api.FrameStdout:
				if _, err := outW.Write(p); err != nil {
					return
				}
			case api.FrameStderr:
				if errW != nil {
					if _, err := errW.Write(p); err != nil {
						return
					}
				} else if _, err := outW.Write(p); err != nil {
					return
				}
			case api.FrameExit:
				n, _ := api.ParseInt32(p)
				s.code = int(n)
				_ = rwc.Close()
				return
			}
		}
	}()
	return s, nil
}

// Run connects the session to stdin, stdout and stderr (any may be nil),
// waits for the command and returns its exit status.
func (s *ExecSession) Run(stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = io.Copy(stdout, s.Stdout()) }()
	if s.Stderr() != nil {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = io.Copy(stderr, s.Stderr()) }()
	}
	if stdin != nil {
		go func() { _, _ = io.Copy(s.Stdin(), stdin); _ = s.Stdin().Close() }()
	} else {
		_ = s.Stdin().Close()
	}
	wg.Wait()
	return s.Wait()
}
