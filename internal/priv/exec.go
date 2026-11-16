package priv

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"jailops.net/jailops/sdk/api"
)

// DefaultJexec is the fixed binary that enters a jail. UNVERIFIED on FreeBSD.
const DefaultJexec = "/usr/sbin/jexec"

// sessionCloser is implemented by sessions that hold descriptors; the server
// calls it when the request ends.
type sessionCloser interface{ Close() error }

// AllowedSignals is the list Signal accepts.
var AllowedSignals = map[int]string{
	int(unix.SIGINT): "INT", int(unix.SIGTERM): "TERM", int(unix.SIGHUP): "HUP",
	int(unix.SIGQUIT): "QUIT", int(unix.SIGKILL): "KILL", int(unix.SIGWINCH): "WINCH",
}

var (
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	userRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)
)

const (
	maxEnv      = 64
	maxEnvBytes = 4096
	maxWinsize  = 10000
)

func checkSignal(sig int) error {
	if _, ok := AllowedSignals[sig]; !ok {
		return forbidden("signal %d is not allowed (INT, TERM, HUP, QUIT, KILL, WINCH)", sig)
	}
	return nil
}

func checkWinsize(rows, cols uint16) error {
	if rows == 0 || cols == 0 || rows > maxWinsize || cols > maxWinsize {
		return invalid("invalid window size %dx%d", cols, rows)
	}
	return nil
}

// execArgv validates a session request and builds the jexec argument vector:
// jexec [-U user] <jail> [/usr/bin/env K=V...] argv...
func (c Config) execArgv(jail string, argv []string, o ExecOpts) ([]string, error) {
	if len(argv) == 0 || len(argv) > c.Limits.MaxArgv {
		return nil, invalid("expected between 1 and %d arguments", c.Limits.MaxArgv)
	}
	total := 0
	for _, a := range argv {
		total += len(a) + 1
		if containsNUL(a) {
			return nil, invalid("argument contains a NUL byte")
		}
	}
	if total > c.Limits.MaxArgvBytes {
		return nil, invalid("command line too long")
	}
	if argv[0] == "" || argv[0][0] == '-' || strings.Contains(argv[0], "=") {
		return nil, invalid("invalid command %q", argv[0])
	}
	if o.User != "" && !userRE.MatchString(o.User) {
		return nil, invalid("invalid user %q", o.User)
	}
	if len(o.Env) > maxEnv {
		return nil, invalid("too many environment variables")
	}
	envBytes := 0
	for _, e := range o.Env {
		k, v, ok := strings.Cut(e, "=")
		envBytes += len(e)
		if !ok || !envNameRE.MatchString(k) || containsNUL(v) || envBytes > maxEnvBytes {
			return nil, invalid("invalid environment entry")
		}
	}
	if o.TTY && (o.Rows != 0 || o.Cols != 0) {
		if err := checkWinsize(o.Rows, o.Cols); err != nil {
			return nil, err
		}
	}
	var out []string
	if o.User != "" {
		out = append(out, "-U", o.User)
	}
	out = append(out, jail)
	if len(o.Env) > 0 {
		out = append(out, "/usr/bin/env")
		out = append(out, o.Env...)
	}
	return append(out, argv...), nil
}

// acquire takes a session slot for jail; the returned function frees it.
func (l *Local) acquire(jail string) (func(), error) {
	l.execMu.Lock()
	defer l.execMu.Unlock()
	if l.execJail == nil {
		l.execJail = map[string]int{}
	}
	lim := l.cfg.Limits
	if l.execTotal >= lim.MaxExecTotal || l.execJail[jail] >= lim.MaxExecPerJail {
		return nil, api.Errorf(api.CodeBusy, "too many exec sessions (limit %d per jail, %d in total)", lim.MaxExecPerJail, lim.MaxExecTotal)
	}
	l.execTotal++
	l.execJail[jail]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.execMu.Lock()
			l.execTotal--
			if l.execJail[jail]--; l.execJail[jail] <= 0 {
				delete(l.execJail, jail)
			}
			l.execMu.Unlock()
		})
	}, nil
}

// Exec starts argv in the running jail jail (its key) through jexec(8), with
// a fixed binary and validated arguments, never a shell. The jail must have a
// conf file. ctx bounds the session: when it ends the session's process group
// is killed. The command is its own session leader and, with TTY, owns the
// pseudo-terminal as its controlling terminal.
// UNVERIFIED on FreeBSD: jexec behaviour, pty allocation.
func (l *Local) Exec(ctx context.Context, jail string, argv []string, o ExecOpts) (ExecSession, error) {
	jn, err := ParseJailName(jail)
	if err != nil {
		return nil, err
	}
	if err := (jailGuard{l}).managed(jn.Internal()); err != nil {
		return nil, err
	}
	args, err := l.cfg.execArgv(jn.Internal(), argv, o)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bin := l.d.Jexec
	if bin == "" {
		bin = DefaultJexec
	}
	release, err := l.acquire(jn.Internal())
	if err != nil {
		return nil, err
	}
	s, err := startSession(ctx, bin, args, o, release)
	if err != nil {
		release()
		return nil, err
	}
	return s, nil
}

type localSession struct {
	grace  time.Duration // sessionGrace when the session was made
	tty    bool
	cmd    *exec.Cmd
	pgid   int
	master *os.File // pty master, TTY mode
	mfd    int      // its descriptor, used under mu while not closed

	stdin          io.WriteCloser
	stdout, stderr io.Reader
	toClose        []*os.File

	// a session with a terminal runs under a leader process of the helper (session_leader.go)
	leaderRelease *os.File      // the helper's end of the pipe whose close releases the leader
	cmdDone       chan struct{} // closed when the leader reported the end of the command
	rmu           sync.Mutex
	rep           leaderReport

	done    chan struct{}
	code    int
	drained chan struct{} // closed when every output reader has seen its end
	drains  int
	mu      sync.Mutex
	closed  bool
	release func()
}

func startSession(ctx context.Context, bin string, args []string, o ExecOpts, release func()) (*localSession, error) {
	s := &localSession{grace: sessionGrace, tty: o.TTY, done: make(chan struct{}), drained: make(chan struct{}), cmdDone: make(chan struct{}), release: release}
	cmd := exec.Command(bin, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin"}
	s.cmd = cmd
	var childEnds []*os.File
	fail := func(err error) (*localSession, error) {
		for _, f := range append(childEnds, s.toClose...) {
			f.Close()
		}
		if s.master != nil {
			s.master.Close()
		}
		if s.leaderRelease != nil {
			s.leaderRelease.Close()
		}
		return nil, api.Errorf(api.CodeInternal, "start session: %v", err)
	}
	if o.TTY {
		master, slave, err := openPTY()
		if err != nil {
			return fail(err)
		}
		s.master = master
		s.mfd = int(master.Fd())
		childEnds = append(childEnds, slave)
		rows, cols := o.Rows, o.Cols
		if rows == 0 || cols == 0 {
			rows, cols = 24, 80
		}
		if err := unix.IoctlSetWinsize(s.mfd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil {
			return fail(err)
		}
		// The command runs under a leader of its own (session_leader.go): a new session whose controlling terminal is the
		// slave (fd 0), which lives until the output of the command was read.
		self, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		relR, relW, err := os.Pipe()
		if err != nil {
			return fail(err)
		}
		repR, repW, err := os.Pipe()
		if err != nil {
			relR.Close()
			relW.Close()
			return fail(err)
		}
		childEnds = append(childEnds, relR, repW)
		s.toClose = append(s.toClose, repR)
		s.leaderRelease = relW
		cmd = exec.Command(self, append([]string{sessionLeaderArg, bin}, args...)...)
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/sbin:/bin:/usr/sbin:/usr/bin"}
		s.cmd = cmd
		cmd.ExtraFiles = []*os.File{relR, repW}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		go readLeaderReport(repR, func(r leaderReport) {
			s.rmu.Lock()
			first := !s.rep.exited && r.exited
			s.rep = r
			s.rmu.Unlock()
			if first {
				close(s.cmdDone)
			}
		})
		s.stdin = &ttyStdin{f: master}
		s.stdout = ttyReader{f: master}
		s.drains = 1
	} else {
		inR, inW, err := os.Pipe()
		if err != nil {
			return fail(err)
		}
		childEnds = append(childEnds, inR)
		s.toClose = append(s.toClose, inW)
		outR, outW, err := os.Pipe()
		if err != nil {
			return fail(err)
		}
		childEnds = append(childEnds, outW)
		s.toClose = append(s.toClose, outR)
		errR, errW, err := os.Pipe()
		if err != nil {
			return fail(err)
		}
		childEnds = append(childEnds, errW)
		s.toClose = append(s.toClose, errR)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		s.stdin, s.stdout, s.stderr = inW, outR, errR
		s.drains = 2
	}
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	for _, f := range childEnds {
		f.Close()
	}
	s.pgid = cmd.Process.Pid
	var left = s.drains
	var dmu sync.Mutex
	wrap := func(r io.Reader) io.Reader {
		return &drainReader{r: r, end: func() {
			dmu.Lock()
			left--
			if left == 0 {
				close(s.drained)
			}
			dmu.Unlock()
		}}
	}
	s.stdout = wrap(s.stdout)
	if s.stderr != nil {
		s.stderr = wrap(s.stderr)
	}
	go s.reap(ctx)
	return s, nil
}

// daemonSetsid is how long what a command left in its group has to leave it (setsid) before the group is killed.
const daemonSetsid = 250 * time.Millisecond

// sessionGrace is how long the leader of a terminal session has to end after it was released, and how long the output of
// a finished session is waited for.
var sessionGrace = 10 * time.Second

// reap waits for the command, kills what it left behind, frees the slot and
// closes the descriptors once the output was read (or after a grace period).
func (s *localSession) reap(ctx context.Context) {
	waited := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.killGroup()
		case <-waited:
		}
	}()
	leaderDone := make(chan error, 1)
	go func() { leaderDone <- s.cmd.Wait() }()
	if s.leaderRelease != nil {
		// A terminal session: the leader reports the end of the command and stays; the output is read, then the leader is
		// released and the terminal ends with it.
		select {
		case <-s.cmdDone:
			s.waitOutputRead(ctx)
		case <-leaderDone:
			leaderDone <- nil
		case <-ctx.Done():
		}
		s.leaderRelease.Close()
	}
	var err error
	if s.leaderRelease != nil {
		// the leader of a terminal session was released: it ends within a grace period or is killed
		select {
		case err = <-leaderDone:
		case <-time.After(s.grace):
			s.killGroup()
			err = <-leaderDone
		}
	} else {
		// a command without a terminal runs as long as it runs; the end of the request (ctx) kills its group
		err = <-leaderDone
	}
	close(waited)
	// No process of the session outlives it. A daemon the command started is in the group of the command until it has
	// made a session of its own, which takes it a moment after its parent exited: killing the group at once would take
	// it too (one start in ten of `daemon -f`), so what is left is given that moment first.
	if syscall.Kill(-s.pgid, 0) == nil {
		time.Sleep(daemonSetsid)
	}
	s.killGroup()
	s.code = 0
	if ps := s.cmd.ProcessState; ps != nil {
		s.code = ps.ExitCode()
		if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			s.code = 128 + int(ws.Signal())
		}
	}
	if s.leaderRelease != nil {
		s.rmu.Lock()
		if s.rep.exited {
			s.code = s.rep.exitCode
		}
		s.rmu.Unlock()
	}
	_ = err
	close(s.done)
	s.release()
	select {
	case <-s.drained:
	case <-ctx.Done():
	case <-time.After(s.grace):
	}
	s.Close()
}

// waitOutputRead returns once the master of the terminal holds nothing that is not read (at most two seconds).
func (s *localSession) waitOutputRead(ctx context.Context) {
	deadline := time.Now().Add(2 * time.Second)
	quiet := 0
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if outputQueued(s.mfd) == 0 {
			if quiet++; quiet >= 3 {
				return
			}
		} else {
			quiet = 0
		}
		time.Sleep(3 * time.Millisecond)
	}
}

func (s *localSession) killGroup() {
	_ = syscall.Kill(-s.pgid, syscall.SIGKILL)
	if g := s.commandGroup(); g > 0 {
		_ = syscall.Kill(-g, syscall.SIGKILL)
	}
}

// commandGroup is the process group of the command of a terminal session (the leader reported it), or 0.
func (s *localSession) commandGroup() int {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	return s.rep.pgid
}

func (s *localSession) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *localSession) Stdin() io.WriteCloser { return s.stdin }
func (s *localSession) Stdout() io.Reader     { return s.stdout }
func (s *localSession) Stderr() io.Reader     { return s.stderr }

func (s *localSession) Resize(rows, cols uint16) error {
	if !s.tty {
		return invalid("the session has no terminal")
	}
	if err := checkWinsize(rows, cols); err != nil {
		return err
	}
	if s.isDone() {
		return api.Errorf(api.CodeNotFound, "the session has ended")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return api.Errorf(api.CodeNotFound, "the session has ended")
	}
	if err := unix.IoctlSetWinsize(s.mfd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}); err != nil {
		return api.Errorf(api.CodeInternal, "resize: %v", err)
	}
	return nil
}

func (s *localSession) Signal(sig int) error {
	if err := checkSignal(sig); err != nil {
		return err
	}
	if s.isDone() {
		return api.Errorf(api.CodeNotFound, "the session has ended")
	}
	target := -s.pgid
	if g := s.commandGroup(); g > 0 {
		target = -g // the command runs in a process group of its own, below its leader
	}
	if err := syscall.Kill(target, syscall.Signal(sig)); err != nil && !errors.Is(err, syscall.ESRCH) {
		return api.Errorf(api.CodeInternal, "signal: %v", err)
	}
	return nil
}

func (s *localSession) Wait() (int, error) {
	<-s.done
	return s.code, nil
}

// Close releases the descriptors. The command is killed if it still runs.
func (s *localSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if !s.isDone() {
		s.killGroup()
	}
	if s.master != nil {
		s.master.Close()
	}
	if s.leaderRelease != nil {
		s.leaderRelease.Close()
	}
	for _, f := range s.toClose {
		f.Close()
	}
	return nil
}

// ttyStdin writes to the pty master; Close sends end-of-file (^D) to the line
// discipline instead of closing the master, which would hang the terminal up.
type ttyStdin struct {
	f    *os.File
	once sync.Once
}

func (t *ttyStdin) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *ttyStdin) Close() error {
	t.once.Do(func() { _, _ = t.f.Write([]byte{0x04}) })
	return nil
}

// ttyReader reads the pty master; EIO means the slave side is gone.
type ttyReader struct{ f *os.File }

func (t ttyReader) Read(p []byte) (int, error) {
	n, err := t.f.Read(p)
	if err != nil && (errors.Is(err, syscall.EIO) || errors.Is(err, os.ErrClosed)) {
		err = io.EOF
	}
	return n, err
}

// drainReader reports the end of a stream once.
type drainReader struct {
	r    io.Reader
	end  func()
	once sync.Once
}

func (d *drainReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	if err != nil {
		d.once.Do(d.end)
	}
	return n, err
}
