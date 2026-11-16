package cli

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// unifiedOpts are the flags 'logs' adds to the jail logs command.
type unifiedOpts struct {
	jails       []string
	labels      []string
	app         string
	appLogs     bool
	allProjects bool
	file        string
}

func (u unifiedOpts) any() bool {
	return len(u.jails) > 0 || len(u.labels) > 0 || u.app != "" || u.appLogs || u.allProjects || u.file != ""
}

// logsCmd is the top-level 'logs': with a jail name it is 'jail logs';
// without one, or with a selection flag, it merges the logs of many jails.
// It also holds 'logs forward'.
func (a *app) logsCmd(d *kindDesc[api.Jail]) *cobra.Command {
	cmd, o := a.jailLogsCmd(d)
	single := cmd.RunE
	var u unifiedOpts
	cmd.Use = "logs [NAME [FILE]]"
	cmd.Short = "Read the logs of one jail, or of many merged by time"
	cmd.Long = `Without a jail name, read the end of one log file (messages, or --file) of every
jail of the project and merge the lines into one stream ordered by their
timestamps. Each line starts with jail/file (project/jail/file with
--all-projects), coloured per jail on a terminal. --jail (repeatable), -l
KEY=VALUE (repeatable) and --app narrow the jails; --app-logs adds the log files
installed apps declare. --tail, --since and --grep apply to every file before
the merge. A line without a timestamp of its own (a continued line) stays
after the line before it. At most 50 files are read and 2000 lines printed;
-f follows all of them. -o json prints one JSON object per line: time,
project, jail, app, file and line. Files that cannot be read (a jail that is
not mounted) are named on standard error.

With NAME, the logs of that one jail, as 'jailops jail logs':
` + cmd.Long + `

'jailops logs forward' sends the logs elsewhere (a syslog server, a webhook).
A jail named forward is read with 'jailops jail logs forward'.`
	cmd.Example = `jailops logs
jailops logs -f
jailops logs --jail web --jail db --since 15m
jailops logs -l tier=front --grep error
jailops logs --app postgresql --app-logs
jailops logs --all-projects --tail 20 -o json
jailops logs web messages
jailops logs forward status`
	cmd.Args = cobra.RangeArgs(0, 2)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || u.any() {
			if len(args) > 0 {
				return usagef("a jail name and --jail, --label, --app, --app-logs, --all-projects or --file do not go together: name the jails with --jail")
			}
			if o.events {
				return usagef("--events needs a jail name")
			}
			if !u.allProjects {
				if err := a.requireProject(); err != nil {
					return err
				}
			}
			return a.readUnified(cmd.Context(), u, *o)
		}
		if err := a.requireProject(); err != nil {
			return err
		}
		return single(cmd, args)
	}
	f := cmd.Flags()
	f.StringArrayVar(&u.jails, "jail", nil, "merge the logs of this jail (repeatable; default every jail)")
	f.StringArrayVarP(&u.labels, "label", "l", nil, "merge the logs of the jails with this label KEY=VALUE (repeatable)")
	f.StringVar(&u.app, "app", "", "merge the logs of the jails installed from this app")
	f.BoolVar(&u.appLogs, "app-logs", false, "add the log files the installed apps declare below /var/log")
	f.BoolVar(&u.allProjects, "all-projects", false, "read every project you may use, not only the current one")
	f.StringVar(&u.file, "file", "", "the file to read of every jail (default messages)")
	_ = cmd.RegisterFlagCompletionFunc("jail", completeKind(a, d))
	_ = cmd.RegisterFlagCompletionFunc("app", a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		l, err := c.Apps().List(ctx)
		var n []string
		for _, s := range l {
			n = append(n, s.Name)
		}
		return n, err
	}))
	_ = cmd.RegisterFlagCompletionFunc("file", completeNone)
	cmd.AddCommand(a.logForwardCmd())
	return cmd
}

// jailPalette are the colours of the jail prefixes: none is red (errors) or
// faint, all read on dark and light terminals.
var jailPalette = []string{"36", "32", "33", "35", "34", "96", "92", "93", "95", "94"}

// jailColour picks a colour by name, the same one in every run.
func jailColour(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return jailPalette[h.Sum32()%uint32(len(jailPalette))]
}

func (a *app) readUnified(ctx context.Context, u unifiedOpts, o logOpts) error {
	if o.tail < 1 || o.tail > api.MaxLogTail {
		return usagef("--tail takes between 1 and %d lines", api.MaxLogTail)
	}
	if len(o.grep) > api.MaxLogGrep {
		return usagef("--grep takes at most %d bytes", api.MaxLogGrep)
	}
	if _, err := api.ParseLogSince(o.since, a.env.Now()); err != nil {
		return usagef("--since takes an RFC 3339 time or a duration such as 15m, 2h or 1d")
	}
	q := api.LogsQuery{Jails: u.jails, App: u.app, AppLogs: u.appLogs, File: u.file, Tail: o.tail, Since: o.since, Grep: o.grep}
	for _, l := range u.labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return usagef("--label takes KEY=VALUE, not %q", l)
		}
		if q.Labels == nil {
			q.Labels = map[string]string{}
		}
		q.Labels[k] = v
	}
	if _, err := q.Normalize(); err != nil {
		return asUsage(err)
	}
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	colour := a.format != fmtJSON && a.format != fmtYAML && a.colorOn(a.env.Stdout)
	warned := map[string]bool{}
	first := true
	for {
		r, err := c.Logs().Read(ctx, q, u.allProjects)
		if err != nil {
			if o.follow && (errors.Is(err, context.Canceled) || ctx.Err() != nil) {
				return nil
			}
			return err
		}
		for _, s := range r.Sources {
			if s.Error != nil && !warned[s.Key] {
				warned[s.Key] = true
				msg := "jailops: " + s.Jail + "/" + s.File + ": " + s.Error.Message
				if s.Error.Hint != "" {
					msg += " (" + s.Error.Hint + ")"
				}
				fprintln(a.env.Stderr, msg)
			}
			if s.Error == nil && s.Rotated && !first {
				fprintln(a.env.Stderr, "jailops: "+s.Jail+"/"+s.File+" was rotated, reading from its beginning")
			}
		}
		if err := a.printUnified(r, u.allProjects, colour); err != nil {
			return err
		}
		if first && !o.follow && r.Truncated && a.format != fmtJSON && a.format != fmtYAML {
			fprintln(a.env.Stderr, "jailops: some lines were left out (at most 50 files and 2000 lines; --tail, --since, --grep and --jail choose what)")
		}
		if !o.follow {
			return nil
		}
		first = false
		q.Cursor, q.Tail = r.Next, api.MaxLogTail
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(a.env.PollInterval):
		}
	}
}

func (a *app) printUnified(r api.LogsRead, withProject, colour bool) error {
	switch a.format {
	case fmtJSON:
		for _, l := range r.Lines {
			b, err := json.Marshal(l)
			if err != nil {
				return err
			}
			fprintln(a.env.Stdout, string(b))
		}
		return nil
	case fmtYAML:
		if len(r.Lines) == 0 {
			return nil
		}
		return a.emit(r.Lines, nil, nil, nil)
	}
	width := 0
	prefix := func(l api.LogEntry) string {
		p := l.Jail + "/" + l.File
		if withProject {
			p = l.Project + "/" + p
		}
		return p
	}
	for _, s := range r.Sources {
		if s.Error != nil {
			continue
		}
		width = max(width, len(prefix(api.LogEntry{Project: s.Project, Jail: s.Jail, File: s.File})))
	}
	for _, l := range r.Lines {
		p := termText(prefix(l), false)
		pad := strings.Repeat(" ", max(width-len(p), 0))
		if colour {
			p = "\x1b[" + jailColour(l.Project+"/"+l.Jail) + "m" + p + "\x1b[0m"
		}
		fprintln(a.env.Stdout, colored(p+pad+"  "+terminalSafe(l.Line)))
	}
	return nil
}
