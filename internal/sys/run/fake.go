package run

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Wildcards for Rule.Args.
const (
	// AnyArg matches exactly one argument.
	AnyArg = "*"
	// RestArgs, as the last element, matches any remaining arguments
	// (including none).
	RestArgs = "**"
)

// Rule scripts a reply. A rule matches when Name equals the command name and
// Args match the argv (see AnyArg and RestArgs). The first unused matching
// rule wins; a rule with Times 0 never runs out.
type Rule struct {
	Name   string
	Args   []string
	Result Result
	// Err, when non-nil, is returned. A zero-code reply with Stderr should
	// use ExitCode != 0 and leave Err nil: Fake then builds the *ExitError.
	Err error
	// Fn, when non-nil, computes the reply from the call (it may read
	// c.Stdin or write c.Stdout) and overrides Result and Err.
	Fn    func(c Cmd) (Result, error)
	Times int
	used  int
}

// Call is a recorded invocation.
type Call struct {
	Cmd Cmd
	// StdinData is what was read from Cmd.Stdin, if it was non-nil and
	// Fake.CaptureStdin is true.
	StdinData []byte
}

// Fake is a Runner for tests. It records calls and answers from rules.
// A command that matches no rule fails with an error naming it, so tests
// cannot silently run unscripted commands.
type Fake struct {
	mu    sync.Mutex
	rules []*Rule
	calls []Call
	// CaptureStdin reads Stdin fully into the recorded Call. Do not use it
	// with huge streams.
	CaptureStdin bool
	// HangOn, when set and true for a command, makes Run wait until the context ends or the command's timeout passes,
	// as a command that never returns would.
	HangOn func(Cmd) bool
}

var _ Runner = (*Fake)(nil)

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{CaptureStdin: true} }

// On adds a rule that replies with stdout and exit status 0.
func (f *Fake) On(name string, args []string, stdout string) *Rule {
	return f.Add(Rule{Name: name, Args: args, Result: Result{Stdout: []byte(stdout)}})
}

// OnFail adds a rule that replies with a non-zero exit and stderr.
func (f *Fake) OnFail(name string, args []string, code int, stderr string) *Rule {
	return f.Add(Rule{Name: name, Args: args, Result: Result{ExitCode: code, Stderr: []byte(stderr)}})
}

// Add registers a rule and returns the stored copy.
func (f *Fake) Add(r Rule) *Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	rr := r
	f.rules = append(f.rules, &rr)
	return &rr
}

// Calls returns a copy of the recorded calls.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Argv returns the recorded calls as "name arg arg" strings.
func (f *Fake) Argv() []string {
	var out []string
	for _, c := range f.Calls() {
		out = append(out, strings.Join(append([]string{c.Cmd.Name}, c.Cmd.Args...), " "))
	}
	return out
}

// Reset forgets calls but keeps rules.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func matchArgs(pat, args []string) bool {
	for i, p := range pat {
		if p == RestArgs && i == len(pat)-1 {
			return len(args) >= i
		}
		if i >= len(args) {
			return false
		}
		if p != AnyArg && p != args[i] {
			return false
		}
	}
	return len(pat) == len(args)
}

// SetHangOn sets HangOn while the fake is in use by other goroutines (a daemon that runs in the test).
func (f *Fake) SetHangOn(fn func(Cmd) bool) {
	f.mu.Lock()
	f.HangOn = fn
	f.mu.Unlock()
}

// Run implements Runner.
func (f *Fake) Run(ctx context.Context, c Cmd) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	f.mu.Lock()
	hang := f.HangOn
	f.mu.Unlock()
	if hang != nil && hang(c) {
		// a command that never ends: only the request ending, or the command's own timeout, ends it
		var timer <-chan time.Time
		if c.Timeout > 0 {
			timer = time.After(c.Timeout)
		}
		f.mu.Lock()
		f.calls = append(f.calls, Call{Cmd: c})
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-timer:
			return Result{}, fmt.Errorf("%s: %w after %s", Redact(c), ErrTimeout, c.Timeout)
		}
	}
	call := Call{Cmd: c}
	if c.Stdin != nil && f.CaptureStdin {
		b, err := io.ReadAll(c.Stdin)
		if err != nil {
			return Result{}, err
		}
		call.StdinData = b
		c.Stdin = bytes.NewReader(b) // a rule's Fn may read it too
	}
	f.mu.Lock()
	f.calls = append(f.calls, call)
	var hit *Rule
	for _, r := range f.rules {
		if r.Name == c.Name && matchArgs(r.Args, c.Args) && (r.Times == 0 || r.used < r.Times) {
			r.used++
			hit = r
			break
		}
	}
	f.mu.Unlock()
	if hit == nil {
		return Result{ExitCode: -1}, fmt.Errorf("run.Fake: no rule for %s", Redact(c))
	}
	if hit.Fn != nil {
		return hit.Fn(c)
	}
	res, err := hit.Result, hit.Err
	if err == nil && res.ExitCode != 0 {
		err = &ExitError{Name: c.Name, Args: c.Args, Code: res.ExitCode, Stderr: string(res.Stderr)}
	}
	if c.Stdout != nil && len(res.Stdout) > 0 {
		if _, werr := c.Stdout.Write(res.Stdout); werr != nil {
			return res, werr
		}
		res.Stdout = nil
	}
	return res, err
}
