package jailos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Command implements Jails over run.Runner (jail, jexec, jls).
type Command struct {
	R run.Runner
	// Timeouts; zero values use these defaults.
	StartTimeout time.Duration // default 120s (jail -c may run exec.start)
}

var _ Jails = (*Command)(nil)

// NewCommand returns a run-based implementation.
func NewCommand(r run.Runner) *Command { return &Command{R: r} }

func mapJailErr(name string, err error) error {
	if err == nil {
		return nil
	}
	ee, ok := run.IsExit(err)
	if !ok {
		return api.Errorf(api.CodeInternal, "jail: %v", err)
	}
	low := strings.ToLower(ee.Stderr)
	msg := strings.TrimSpace(ee.Stderr)
	switch {
	case strings.Contains(low, "not found"), strings.Contains(low, "no such jail"):
		return api.Errorf(api.CodeNotFound, "jail %s: %s", name, msg)
	case strings.Contains(low, "already exists"):
		return api.Errorf(api.CodeAlreadyExists, "jail %s: %s", name, msg)
	}
	return api.Errorf(api.CodeInternal, "jail %s: %s", name, msg)
}

// Create implements Controller.
func (c *Command) Create(ctx context.Context, confPath, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := validateConf(confPath); err != nil {
		return err
	}
	t := c.StartTimeout
	if t == 0 {
		t = 120 * time.Second
	}
	_, err := c.R.Run(ctx, run.Cmd{Name: "jail", Args: []string{"-f", confPath, "-c", name}, Timeout: t})
	return withConsoleLog(name, mapJailErr(name, err))
}

// withConsoleLog points at the file the jail's exec.* commands wrote to
// (exec.consolelog in jail.conf): jail(8) itself reports only which one failed.
func withConsoleLog(name string, err error) error {
	var ae *api.Error
	if err == nil || !errors.As(err, &ae) || ae.Hint != "" || ae.Code != api.CodeInternal {
		return err
	}
	return ae.WithHint("what the jail's start and stop commands printed is in /var/log/jailops/jail_" + name + "_console.log on the host")
}

// Remove implements Controller.
func (c *Command) Remove(ctx context.Context, confPath, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := validateConf(confPath); err != nil {
		return err
	}
	budget := stopRunTime(confPath)
	_, err := c.R.Run(ctx, run.Cmd{Name: "jail", Args: []string{"-f", confPath, "-r", name}, Timeout: budget})
	if errors.Is(err, run.ErrTimeout) && ctx.Err() == nil {
		// The jail's stop commands (exec.stop) did not return within the budget: nothing bounds them in jail(8) (its
		// exec.timeout would only refuse the removal). The jail is removed without them, which kills what is left, and
		// the console log of the jail says so.
		// what still runs in the jail is named before it is removed: the operator sees why the shutdown did not finish
		var running string
		if ps, perr := c.R.Run(ctx, run.Cmd{Name: "ps", Args: []string{"-J", name, "-o", "pid=", "-o", "comm="}, Timeout: 10 * time.Second}); perr == nil {
			var procs []string
			for _, l := range strings.Split(string(ps.Stdout), "\n") {
				if f := strings.Fields(l); len(f) > 0 {
					procs = append(procs, strings.Join(f, " "))
				}
			}
			running = strings.Join(procs, ", ")
		}
		if _, ferr := c.R.Run(ctx, run.Cmd{Name: "jail", Args: []string{"-R", name}, Timeout: 30 * time.Second}); ferr == nil {
			noteForcedStop(name, budget, running)
			msg := fmt.Sprintf("jail %s did not shut down within %s: it was removed without its stop commands and its processes were killed", name, budget)
			if running != "" {
				msg += " (still running: " + running + ")"
			}
			return api.Errorf(api.CodeStopForced, "%s", msg) // the jail is gone: the daemon takes it as a stop, with a warning
		}
	}
	return withConsoleLog(name, mapJailErr(name, err))
}

// noteForcedStop appends a line to the console log of the jail: the stop commands were cut off, and what still ran.
func noteForcedStop(name string, budget time.Duration, running string) {
	f, err := os.OpenFile("/var/log/jailops/jail_"+name+"_console.log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "jailops: the jail did not shut down within %s; it was removed and its processes were killed", budget)
	if running != "" {
		fmt.Fprintf(f, " (still running: %s)", running)
	}
	fmt.Fprintln(f)
}

// stopRunTime is how long jail -r may run: the stop commands (exec.stop) get the jail's stop timeout to shut a service down
// cleanly, the jail gets the same time again to exit after SIGTERM (stop.timeout), and five seconds go on top. After that
// the jail is removed without them, so that a stop is always bounded: boot.stop_timeout is the knob of both, and a jail
// without one has api.DefaultStopTimeout (30 s: 65 s in all).
func stopRunTime(confPath string) time.Duration {
	t := api.DefaultStopTimeout
	if b, err := os.ReadFile(confPath); err == nil {
		if m := stopTimeoutRE.FindSubmatch(b); m != nil {
			if n, err := strconv.Atoi(string(m[1])); err == nil && n > 0 && n <= api.MaxStopTimeout {
				t = n
			}
		}
	}
	return time.Duration(2*t+stopSlack) * time.Second
}

// stopSlack is the seconds that go on top of the budget of a stop.
var stopSlack = 5

var stopTimeoutRE = regexp.MustCompile(`(?m)^[ \t]*stop\.timeout[ \t]*=[ \t]*([0-9]+)[ \t]*;`)

// Exec implements Controller.
func (c *Command) Exec(ctx context.Context, name string, o ExecOpts) (run.Result, error) {
	if err := ValidateName(name); err != nil {
		return run.Result{}, err
	}
	if err := validateUser(o.User); err != nil {
		return run.Result{}, err
	}
	if len(o.Argv) == 0 || o.Argv[0] == "" || o.Argv[0][0] == '-' {
		return run.Result{}, api.Errorf(api.CodeInvalid, "exec needs a command")
	}
	args := []string{}
	if o.Login {
		args = append(args, "-l")
	}
	if o.User != "" {
		args = append(args, "-U", o.User)
	}
	args = append(args, name)
	args = append(args, o.Argv...)
	res, err := c.R.Run(ctx, run.Cmd{
		Name: "jexec", Args: args, Stdin: o.Stdin, Stdout: o.Stdout,
		Timeout: o.Timeout,
	})
	if err != nil {
		if ee, ok := run.IsExit(err); ok {
			// The command's own failure is the caller's business; keep the result.
			return res, ee
		}
		return res, api.Errorf(api.CodeInternal, "jexec: %v", err)
	}
	return res, nil
}

// List implements Observer. It asks jls for libxo JSON and falls back to
// the name=value format if that fails.
func (c *Command) List(ctx context.Context) ([]Jail, error) {
	res, err := c.R.Run(ctx, run.Cmd{Name: "jls", Args: []string{"-v", "--libxo=json"}, Timeout: 15 * time.Second})
	if err == nil {
		if js, perr := ParseJLSJSON(res.Stdout); perr == nil {
			sort.Slice(js, func(i, j int) bool { return js[i].JID < js[j].JID })
			return js, nil
		}
	}
	res, err = c.R.Run(ctx, run.Cmd{Name: "jls", Args: []string{"-n", "jid", "name", "path", "host.hostname", "vnet", "dying"}, Timeout: 15 * time.Second})
	if err != nil {
		return nil, mapJailErr("", err)
	}
	js := ParseJLSNamed(string(res.Stdout))
	sort.Slice(js, func(i, j int) bool { return js[i].JID < js[j].JID })
	return js, nil
}

// Get implements Observer.
func (c *Command) Get(ctx context.Context, name string) (Jail, bool, error) {
	if err := ValidateName(name); err != nil {
		return Jail{}, false, err
	}
	js, err := c.List(ctx)
	if err != nil {
		return Jail{}, false, err
	}
	for _, j := range js {
		if j.Name == name {
			return j, true, nil
		}
	}
	return Jail{}, false, nil
}
