package cli

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// logOpts are the flags of 'jail logs'.
type logOpts struct {
	tail   int
	since  string
	grep   string
	follow bool
	// events streams the log events of the server instead (the former
	// meaning of the command), with count and sinceID.
	events  bool
	count   int
	sinceID string
}

func (a *app) jailLogs(d *kindDesc[api.Jail]) *cobra.Command {
	cmd, _ := a.jailLogsCmd(d)
	return cmd
}

// jailLogsCmd builds 'jail logs' and returns its flags, which 'logs' shares.
func (a *app) jailLogsCmd(d *kindDesc[api.Jail]) (*cobra.Command, *logOpts) {
	var o logOpts
	cmd := &cobra.Command{
		Use:   "logs NAME [FILE]",
		Short: "Read the log files of a jail",
		Long: `Read the log files below /var/log of a jail, running or stopped, through the
server: no SSH and no shell in the jail. Without FILE the files are listed
(rotated copies included; compressed ones are listed but not readable). With
FILE, a name relative to /var/log such as messages or nginx/error.log, the
last lines of the file are printed as plain text, so the output pipes into
grep or less. --tail chooses how many lines (at most 5000), --since keeps the
lines whose timestamp is not older than a time or a duration such as 15m, and
--grep keeps the lines containing a text (a plain substring, no pattern).
-f keeps reading what is appended, once a second, until interrupted, and
starts over when the file is rotated. -o json prints the server's reply.

A stopped jail's root is mounted only while it runs: reading the logs of a
stopped jail answers busy with the dataset to mount. Reading a log needs the
operator role (logs hold what services print) and is audited.

--events restores the former meaning of this command: it streams the log
events the server publishes for the jail until interrupted, from now on or
from an event id with --since-id, and keeps no history.`,
		Example: `jailops jail logs web
jailops jail logs web messages
jailops jail logs web messages --tail 50 --since 15m
jailops jail logs web nginx/error.log --grep "upstream" -f
jailops logs web messages -o json
jailops jail logs web --events --since-id 120 --count 50`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeArgs(completeKind(a, d), a.completeLogFiles()),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.events {
				if len(args) > 1 {
					return usagef("--events streams the events of the jail; it takes no file")
				}
				return a.streamEvents(cmd.Context(), []api.EventType{api.EventLogging}, args[0], o.sinceID, o.count)
			}
			if len(args) == 1 {
				return a.listLogs(cmd.Context(), args[0])
			}
			return a.readLog(cmd.Context(), args[0], args[1], o)
		},
	}
	f := cmd.Flags()
	f.IntVarP(&o.tail, "tail", "n", api.DefaultLogTail, "number of lines from the end of the file")
	f.StringVar(&o.since, "since", "", "keep the lines not older than this: an RFC 3339 time or a duration such as 15m, 2h or 1d")
	f.StringVar(&o.grep, "grep", "", "keep the lines containing this text (case-insensitive substring)")
	f.BoolVarP(&o.follow, "follow", "f", false, "keep printing what is appended to the file until interrupted")
	f.BoolVar(&o.events, "events", false, "stream the log events the server publishes for the jail instead of reading files")
	f.IntVar(&o.count, "count", 0, "with --events: stop after this many events")
	f.StringVar(&o.sinceID, "since-id", "", "with --events: resume after this event id")
	return cmd, &o
}

// completeLogFiles completes the FILE argument from the server's listing.
func (a *app) completeLogFiles() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) != 1 {
			return nil, nil
		}
		files, err := c.Jails().Logs(ctx, args[0])
		var out []string
		for _, f := range files {
			if !f.Compressed {
				out = append(out, f.Name)
			}
		}
		return out, err
	})
}

func (a *app) listLogs(ctx context.Context, jail string) error {
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	files, err := c.Jails().Logs(ctx, jail)
	if err != nil {
		return err
	}
	return a.emit(files, nil, func() ([]string, [][]string) {
		var rows [][]string
		for _, f := range files {
			kind := string(f.Kind)
			if f.Compressed {
				kind += " (compressed)"
			}
			rows = append(rows, []string{f.Name, humanBytes(f.Size), age(a.env.Now(), f.ModifiedAt), kind})
		}
		return []string{"FILE", "SIZE", "MODIFIED", "KIND"}, rows
	}, func() []string {
		var n []string
		for _, f := range files {
			n = append(n, f.Name)
		}
		return n
	})
}

// readLog prints the end of a log file, and with follow what is appended
// afterwards: every poll continues at the offset of the previous reply, and a
// file that was rotated is read from its beginning again.
func (a *app) readLog(ctx context.Context, jail, file string, o logOpts) error {
	if o.tail < 1 || o.tail > api.MaxLogTail {
		return usagef("--tail takes between 1 and %d lines", api.MaxLogTail)
	}
	if len(o.grep) > api.MaxLogGrep {
		return usagef("--grep takes at most %d bytes", api.MaxLogGrep)
	}
	if _, err := api.ParseLogSince(o.since, a.env.Now()); err != nil {
		return usagef("--since takes an RFC 3339 time or a duration such as 15m, 2h or 1d")
	}
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	q := api.JailLogQuery{Tail: o.tail, Since: o.since, Grep: o.grep}
	for {
		r, err := c.Jails().Log(ctx, jail, file, q)
		if err != nil {
			if o.follow && (errors.Is(err, context.Canceled) || ctx.Err() != nil) {
				return nil
			}
			return err
		}
		if q.Offset > 0 && r.Rotated {
			fprintln(a.env.Stderr, "jailops: "+file+" was rotated, reading from its beginning")
		}
		switch a.format {
		case fmtJSON, fmtYAML:
			if err := a.emit(r, nil, nil, nil); err != nil {
				return err
			}
		default:
			// the default window cut the file: say so once, where it does not reach a pipe
			if q.Offset == 0 && r.Truncated && !o.follow && o.tail == api.DefaultLogTail && len(r.Lines) == o.tail {
				fprintln(a.env.Stderr, "jailops: showing the last "+strconv.Itoa(len(r.Lines))+" lines (--tail chooses how many, --since and --grep what)")
			}
			for _, l := range r.Lines {
				fprintln(a.env.Stdout, terminalSafe(l.Text))
			}
		}
		if !o.follow {
			return nil
		}
		// continue where this reply ended, and keep every line appended since (the
		// server's largest window) instead of the last --tail of them
		q.Offset, q.Tail = r.NextOffset, api.MaxLogTail
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(a.env.PollInterval):
		}
	}
}

// terminalSafe cleans one log line: what a jail writes into its logs must not drive the reader's terminal.
func terminalSafe(s string) string { return termText(s, false) }
