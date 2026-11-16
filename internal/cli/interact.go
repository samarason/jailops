package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// hintError is an error with advice for the user.
type hintError struct {
	err  error
	hint string
}

func (e *hintError) Error() string { return e.err.Error() }
func (e *hintError) Unwrap() error { return e.err }

// confirmation ---------------------------------------------------------------

func (a *app) readLine() (string, error) {
	line, err := a.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		fprintln(a.env.Stderr)
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readSecretFromTerminal reads a line from the terminal without echoing it. It refuses when standard input is not a terminal:
// a password never comes from a command line, so a script says --password-file -.
func readSecretFromTerminal(e *Env, prompt string) (string, error) {
	f, ok := e.Stdin.(*os.File)
	if !ok || !e.IsTTY(f) {
		return "", usagef("standard input is not a terminal: pass --password-file - and give the password on its first line")
	}
	fprintf(e.Stderr, "%s", prompt)
	b, err := term.ReadPassword(int(f.Fd()))
	fprintln(e.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// newPassword reads a password for a person: from the first line of a file with --password-file (- is standard
// input), else from a prompt asked twice. It is never
// an argument of the command line.
func (a *app) newPassword(file string) (string, error) {
	if file != "" {
		return a.readSecretFile("password", file)
	}
	first, err := a.env.ReadSecret("New password: ")
	if err != nil {
		return "", err
	}
	second, err := a.env.ReadSecret("Repeat the password: ")
	if err != nil {
		return "", err
	}
	if first == "" || first != second {
		return "", usagef("the passwords are empty or do not match")
	}
	return first, nil
}

// readSecretFile reads a secret from the first line of a file, or of standard input for "-". A file others may
// read is warned about.
func (a *app) readSecretFile(what, path string) (string, error) {
	if path == "-" {
		line, err := a.readLine()
		if err != nil || line == "" {
			return "", usagef("the %s is not on the first line of standard input", what)
		}
		return line, nil
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fprintf(a.env.Stderr, "warning: %s can be read by other users; keep a %s file at mode 0600\n", path, what)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", usagef("reading the %s file: %v", what, err)
	}
	line, rest, _ := strings.Cut(string(b), "\n")
	line = strings.TrimSuffix(line, "\r")
	if strings.TrimSpace(rest) != "" {
		return "", usagef("the %s file %s must hold one line", what, path)
	}
	if line == "" {
		return "", usagef("the %s file %s is empty", what, path)
	}
	return line, nil
}

// noAnswer is the error of a confirmation that got no answer: standard input ended, as it does in a script.
func (a *app) noAnswer(how string) error {
	what := "standard input gave no answer"
	if !a.env.IsTTY(a.env.Stdin) {
		what = "standard input is not a terminal and gave no answer"
	}
	return &usageError{err: fmt.Errorf("%w: %s", errNotConfirmed, what), hint: how}
}

// confirm asks a yes/no question unless -y was given.
func (a *app) confirm(prompt string) error {
	if a.yes {
		return nil
	}
	fprintf(a.env.Stderr, "%s [y/N]: ", prompt)
	ans, err := a.readLine()
	if err != nil {
		return a.noAnswer("answer y on standard input, or pass -y to confirm without a question")
	}
	switch strings.ToLower(ans) {
	case "y", "yes":
		return nil
	}
	return &abortError{"not confirmed, nothing was changed"}
}

// confirmTyped makes the user type name before something irreversible. -y
// does not satisfy it; only the explicit flag (flagOK) does.
func (a *app) confirmTyped(warning, name string, flagOK bool, flagName string) error {
	if flagOK {
		return nil
	}
	fprintln(a.env.Stderr, warning)
	fprintf(a.env.Stderr, "Type the name %q to confirm: ", name)
	ans, err := a.readLine()
	if err != nil {
		hint := "type the name on standard input, or pass " + flagName
		if flagName != "-y" {
			hint += " (-y does not answer this question)"
		}
		return a.noAnswer(hint)
	}
	if ans != name {
		return &abortError{"the name did not match, nothing was changed"}
	}
	return nil
}

// dry-run ----------------------------------------------------------------------

// dry reports what a mutating command would send and returns true when the
// global --dry-run is set. Nothing is sent to the server.
func (a *app) dry(action string, request any) (bool, error) {
	if !a.dryRun {
		return false, nil
	}
	if a.format == fmtJSON || a.format == fmtYAML {
		out := map[string]any{"dry_run": true, "action": action}
		if request != nil {
			out["request"] = request
		}
		return true, a.emit(out, nil, nil, nil)
	}
	fprintf(a.env.Stdout, "dry-run: would %s\n", action)
	if request != nil {
		b, err := toYAML(request)
		if err != nil {
			return true, err
		}
		_, _ = a.env.Stdout.Write(b)
	}
	return true, nil
}

// operations -------------------------------------------------------------------

type opHandle interface {
	Info() api.Operation
	Refresh(ctx context.Context) error
	WaitAny(ctx context.Context) (any, error)
}

type typedOp[T any] struct{ op *sdk.Operation[T] }

func (t typedOp[T]) Info() api.Operation                      { return t.op.Info() }
func (t typedOp[T]) Refresh(ctx context.Context) error        { return t.op.Refresh(ctx) }
func (t typedOp[T]) WaitAny(ctx context.Context) (any, error) { return t.op.Wait(ctx) }

func handle[T any](op *sdk.Operation[T], err error) (opHandle, error) {
	if err != nil || op == nil {
		return nil, err
	}
	return typedOp[T]{op}, nil
}

func (a *app) waiting() bool { return a.wait && !a.noWait }

func (a *app) waitTimeout() time.Duration {
	if a.timeout > 0 {
		return a.timeout
	}
	return 10 * time.Minute
}

// await waits for h with a progress line on a terminal.
func (a *app) await(ctx context.Context, h opHandle) (any, api.Operation, error) {
	info := h.Info()
	if info.ID == "" || info.Status.Final() {
		v, err := h.WaitAny(ctx)
		return v, h.Info(), err
	}
	wctx, cancel := context.WithTimeout(ctx, a.waitTimeout())
	defer cancel()
	type result struct {
		v   any
		err error
	}
	done := make(chan result, 1)
	go func() { v, err := h.WaitAny(wctx); done <- result{v, err} }()
	tty := a.env.IsTTY(a.env.Stderr) && a.env.Getenv("TERM") != "dumb"
	start := a.env.Now()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	spin := `|/-\`
	n := 0
	clear := func() {
		if tty {
			fprintf(a.env.Stderr, "\r\x1b[K")
		}
	}
	for {
		select {
		case r := <-done:
			clear()
			if r.err != nil {
				switch {
				case errors.Is(r.err, context.DeadlineExceeded):
					return nil, h.Info(), &hintError{
						err:  fmt.Errorf("timed out after %s waiting for operation %s", a.waitTimeout(), info.ID),
						hint: "the operation keeps running; follow it with 'jailops op wait " + info.ID + "'"}
				case errors.Is(r.err, context.Canceled):
					return nil, h.Info(), &hintError{
						err:  fmt.Errorf("interrupted while waiting for operation %s", info.ID),
						hint: "the operation keeps running; cancel it with 'jailops op cancel " + info.ID + "'"}
				}
			}
			return r.v, h.Info(), r.err
		case <-tick.C:
			if !tty {
				continue
			}
			rctx, c := context.WithTimeout(wctx, 2*time.Second)
			_ = h.Refresh(rctx)
			c()
			cur := h.Info()
			line := fmt.Sprintf("%c %s [%s", spin[n%len(spin)], dash(cur.Description), cur.Status)
			if cur.Progress > 0 {
				line += fmt.Sprintf(" %d%%", cur.Progress)
			}
			line += fmt.Sprintf("] %s", a.env.Now().Sub(start).Truncate(time.Second))
			fprintf(a.env.Stderr, "\r\x1b[K%s", line)
			n++
		}
	}
}

// finishOp waits for h (unless --no-wait) and prints the outcome as
// "<noun>/<name> <verb>". A nil handle means the server finished synchronously
// and obj is the result.
func (a *app) finishOp(ctx context.Context, h opHandle, noun, name, verb string, obj any) error {
	var (
		v   any = obj
		op  api.Operation
		err error
	)
	if h != nil {
		if !a.waiting() && h.Info().ID != "" {
			op = h.Info()
			return a.emit(op, nil, func() ([]string, [][]string) {
				return []string{"OPERATION", "STATUS", "DESCRIPTION"}, [][]string{{op.ID, string(op.Status), op.Description}}
			}, func() []string { return []string{op.ID} })
		}
		v, op, err = a.await(ctx, h)
		if err != nil {
			return err
		}
		if _, none := v.(sdk.None); none {
			v = nil
		}
	}
	if v == nil && (a.format == fmtJSON || a.format == fmtYAML) {
		if h != nil {
			v = op
		} else {
			v = map[string]string{"name": name, "result": verb}
		}
	}
	if a.format == fmtTable {
		a.say("%s/%s %s\n", noun, name, verb)
		return nil
	}
	return a.emit(v, nil, nil, func() []string { return []string{name} })
}
