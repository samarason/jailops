// Package cli implements the jailops command line client.
//
// It imports only the SDK (sdk and sdk/api), the standard library and the
// dependencies allowed for the client (cobra, yaml.v3, x/term). arch_test.go
// enforces this.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"jailops.net/jailops/sdk"
)

// Env is everything the CLI takes from its process. Tests replace it.
type Env struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	// IsTTY reports whether w is an interactive terminal.
	IsTTY func(w any) bool
	Now   func() time.Time
	// Version is the client version, set by the linker.
	Version string
	// HomeDir returns the user's home directory.
	HomeDir func() string
	// SystemConfig is the path of the host-wide client configuration.
	SystemConfig string
	// ProbeCert fetches the leaf certificate a server presents.
	ProbeCert func(ctx context.Context, hostport string) (*CertProbe, error)
	// ReadSecret prompts on the terminal and reads one line without echoing it. Tests replace it.
	ReadSecret func(prompt string) (string, error)
	// RawTerminal puts a terminal in raw mode and returns the restore function.
	RawTerminal func(in any) (func(), error)
	// TermSize reports the size of a terminal.
	TermSize func(out any) (rows, cols uint16, ok bool)
	// ResizeSignal delivers a value whenever the window size may have changed.
	ResizeSignal func() (<-chan struct{}, func())
	// SDKOptions are added to every connection (tests use short backoffs).
	SDKOptions []sdk.Option
	// PollInterval is how often 'logs -f' asks for more (default one second).
	PollInterval time.Duration
}

// DefaultSystemConfig is the host-wide client configuration file.
const DefaultSystemConfig = "/usr/local/etc/jailops/client.yaml"

// DefaultEnv returns the environment of the running process.
func DefaultEnv() *Env {
	e := &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	e.fill()
	return e
}

func (e *Env) fill() {
	if e.Stdin == nil {
		e.Stdin = strings.NewReader("")
	}
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.IsTTY == nil {
		e.IsTTY = func(w any) bool {
			f, ok := w.(interface{ Fd() uintptr })
			return ok && term.IsTerminal(int(f.Fd()))
		}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Version == "" {
		e.Version = "dev"
	}
	if e.HomeDir == nil {
		e.HomeDir = func() string { h, _ := os.UserHomeDir(); return h }
	}
	if e.SystemConfig == "" {
		e.SystemConfig = DefaultSystemConfig
	}
	if e.RawTerminal == nil {
		e.RawTerminal = defaultRawTerminal
	}
	if e.TermSize == nil {
		e.TermSize = defaultTermSize
	}
	if e.ResizeSignal == nil {
		e.ResizeSignal = defaultResizeSignal
	}
	if e.ProbeCert == nil {
		e.ProbeCert = probeCert
	}
	if e.ReadSecret == nil {
		e.ReadSecret = func(prompt string) (string, error) { return readSecretFromTerminal(e, prompt) }
	}
	if e.PollInterval <= 0 {
		e.PollInterval = time.Second
	}
}

// app holds the state of one invocation.
type app struct {
	env *Env
	in  *bufio.Reader

	remote, host, output, configPath, project string
	dryRun, wait, noWait, yes                 bool
	noHeaders, quiet                          bool
	timeout                                   time.Duration

	format  format
	wide    bool // -o wide: every column of a list, on a terminal too
	compact bool // -o compact: the plain table of a pipe, on a terminal too
	started bool // a command body began: later errors are not usage errors
	partial bool // "set" builds an object from flags: the flags that create requires may be missing
	cmdPath string
	cl      *sdk.Client
	parent  *sdk.Client
	conn    *Connection
	// passFile is --passphrase-file of a jail creation (volkeys.go).
	passFile string
	// empty is what an empty list says instead of the generic "No resources found."
	empty string
}

// NewRootCommand returns the command tree for env. It exists for tests and
// documentation tools; Execute is the entry point of the program.
func NewRootCommand(env *Env) *cobra.Command {
	env.fill()
	a := &app{env: env, in: bufio.NewReader(env.Stdin)}
	return a.newRoot()
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, env *Env, args []string) int {
	env.fill()
	a := &app{env: env, in: bufio.NewReader(env.Stdin)}
	root := a.newRoot()
	if args == nil {
		args = []string{} // nil would make cobra read os.Args
	}
	if len(args) > 0 && args[0] == "--version" { // the version of this client, no server asked
		args = append([]string{"version", "--client"}, args[1:]...)
	}
	execFlags(root, args)
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	err := root.ExecuteContext(ctx)
	if a.parent != nil {
		_ = a.parent.Close()
	} else if a.cl != nil {
		_ = a.cl.Close()
	}
	if err == nil {
		return ExitOK
	}
	if !a.started {
		err = &usageError{err: err, hint: usageHint(root, args)}
	}
	a.printError(err)
	return ExitCode(err)
}

func usageHint(root *cobra.Command, args []string) string {
	c, _, _ := root.Find(args)
	if c == nil {
		c = root
	}
	return fmt.Sprintf("run '%s --help' for usage", c.CommandPath())
}

// usageError is a mistake in how the command was invoked.
type usageError struct {
	err  error
	hint string
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) *usageError {
	return &usageError{err: fmt.Errorf(format, args...)}
}

// withHint replaces the generic "run --help" hint of a usage error.
func (e *usageError) withHint(h string) *usageError {
	e.hint = h
	return e
}

// abortError means the user declined or mistyped a confirmation.
type abortError struct{ msg string }

func (e *abortError) Error() string { return e.msg }

var errNotConfirmed = errors.New("confirmation required")

// say prints a confirmation such as "jail/web started" on standard output,
// unless -q asked for silence. Errors never go through here.
func (a *app) say(format string, args ...any) {
	if a.quiet {
		return
	}
	fprintf(a.env.Stdout, format, args...)
}

// colour support -----------------------------------------------------------

func (a *app) colorOn(w io.Writer) bool {
	if a.env.Getenv("NO_COLOR") != "" || a.env.Getenv("TERM") == "dumb" {
		return false
	}
	return a.env.IsTTY(w)
}

// wantsDryRunOrConfirm helpers live in confirm.go.
