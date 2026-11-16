package priv

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// sessionLeaderArg is the first argument with which the helper starts itself as the leader of a terminal session.
const sessionLeaderArg = "__jailops-session-leader"

// A command run with a terminal is not the session leader itself. FreeBSD hangs a terminal up when its session leader
// exits and drops the output the reader of the master has not taken yet, so a short command ("echo hi") lost its output
// in 3 to 30% of the runs (docs/design.md, section 16). The helper therefore starts itself as a small leader: it owns
// the terminal as its controlling terminal, runs the command in a process group of its own in the foreground, reports
// the group and the exit status on one pipe, and stays until the helper closes the other pipe, which happens once the
// output was read. The command itself sees an ordinary terminal and its own process group, as a shell does.
//
// File descriptors of the leader: 0, 1 and 2 are the terminal; 3 is the pipe the helper closes to release the leader;
// 4 is the pipe on which the leader writes "pgid N" when the command started and "exit N" when it ended.
func init() {
	if len(os.Args) > 2 && os.Args[1] == sessionLeaderArg {
		os.Exit(runSessionLeader(os.Args[2:]))
	}
}

func runSessionLeader(argv []string) int {
	release, report := os.NewFile(3, "release"), os.NewFile(4, "report")
	if release == nil || report == nil {
		return 125
	}
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = "/"
	cmd.Env = os.Environ()
	// the command's group is made the foreground group of the terminal before it runs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	code := 0
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\r\n", err)
		code = 127
	} else {
		fmt.Fprintf(report, "pgid %d\n", cmd.Process.Pid)
		done := make(chan struct{})
		go func() {
			for {
				select {
				case sig := <-signals:
					if s, ok := sig.(syscall.Signal); ok {
						_ = syscall.Kill(-cmd.Process.Pid, s)
					}
				case <-done:
					return
				}
			}
		}()
		_ = cmd.Wait()
		close(done)
		if ps := cmd.ProcessState; ps != nil {
			code = ps.ExitCode()
			if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		}
	}
	fmt.Fprintf(report, "exit %d\n", code)
	_, _ = io.Copy(io.Discard, release) // until the helper closes its end: the output has been read
	return code
}

// leaderReport is what the leader reported so far.
type leaderReport struct {
	pgid     int
	exitCode int
	exited   bool
}

// readLeaderReport reads the leader's reports until its pipe ends and calls on after each one.
func readLeaderReport(r io.Reader, on func(leaderReport)) {
	var rep leaderReport
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		n, err := strconv.Atoi(v)
		if !ok || err != nil {
			continue
		}
		switch k {
		case "pgid":
			rep.pgid = n
		case "exit":
			rep.exitCode, rep.exited = n, true
		}
		on(rep)
	}
}

// outputQueued says how many bytes wait to be read on the master of a terminal.
func outputQueued(fd int) int {
	n, err := unix.IoctlGetInt(fd, fionread)
	if err != nil {
		return 0
	}
	return n
}
