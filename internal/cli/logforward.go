package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

var facilityNames = []string{"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}

func (a *app) logForwardCmd() *cobra.Command {
	fc := group("forward", "Send the logs of the jails to a syslog server or a webhook",
		`jailopsd sends the log lines of the jails (messages, and the files installed
apps declare) and, when asked, its audit log to sinks: syslog servers (RFC 5424
over udp, tcp or tls; tls verifies the server) and https webhooks (JSON lines,
an optional bearer token read from a root-owned file). A sink reads each file
from where it stopped, keeps up to --queue lines while the receiver is away
(the oldest are dropped and counted beyond that) and retries with backoff;
delivery is at least once. A new sink starts at the end of the files.

The list comes from logging.forward of jailopsd.yaml until an administrator
changes it here or in the console; the stored list then replaces the file's
until 'logs forward reset'. Every command here needs a global administrator.`,
		`jailops logs forward add logs --url tls://logs.example.com:6514 --facility local3
jailops logs forward add alerts --url https://hooks.example.com/jailops --token-file /usr/local/etc/jailops/sinks/hook.token --audit
jailops logs forward test logs
jailops logs forward status`)
	fc.AddCommand(a.logForwardList(), a.logForwardAdd(), a.logForwardSet(), a.logForwardRemove(), a.logForwardTest(), a.logForwardStatus(), a.logForwardReset())
	return fc
}

// completeSinks completes sink names.
func (a *app) completeSinks() completer {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		f, err := c.Logs().Forward(ctx)
		var n []string
		for _, k := range f.Spec.Sinks {
			n = append(n, k.Name)
		}
		return n, err
	})
}

// describeSources says in a few words what a sink receives.
func describeSources(s api.LogSinkSource) string {
	var parts []string
	if !s.NoJails {
		files := s.Files
		if len(files) == 0 {
			files = []string{api.DefaultLogFile}
		}
		w := strings.Join(files, ",")
		if !s.NoAppLogs {
			w += "+apps"
		}
		var sel []string
		if len(s.Projects) > 0 {
			sel = append(sel, "projects="+strings.Join(s.Projects, ","))
		}
		if len(s.Jails) > 0 {
			sel = append(sel, "jails="+strings.Join(s.Jails, ","))
		}
		sel = append(sel, labelPairs("", s.Labels)...)
		if len(s.ExcludeJails) > 0 {
			sel = append(sel, "not "+strings.Join(s.ExcludeJails, ","))
		}
		sel = append(sel, labelPairs("not ", s.ExcludeLabels)...)
		if len(sel) == 0 {
			sel = []string{"all jails"}
		}
		parts = append(parts, w+" of "+strings.Join(sel, " "))
	}
	if s.Audit {
		parts = append(parts, "audit")
	}
	return strings.Join(parts, "; ")
}

func labelPairs(prefix string, m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, prefix+k+"="+v)
	}
	sort.Strings(out)
	return out
}

func (a *app) logForwardList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the sinks",
		Long: `List the sinks in force: where each sends, the facility of a syslog sink and
what it receives. Standard error says whether the list is the one of
jailopsd.yaml or one stored through the API.`,
		Example: "jailops logs forward list\njailops logs forward list -o yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			f, err := c.Logs().Forward(cmd.Context())
			if err != nil {
				return err
			}
			if a.format == fmtTable {
				a.originNote(f)
			}
			return a.emit(f.Spec.Sinks, nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, k := range f.Spec.Sinks {
					fac := "-"
					if k.Type == api.LogSinkSyslog {
						fac = k.Facility
						if fac == "" {
							fac = "local0"
						}
					}
					rows = append(rows, []string{k.Name, string(k.Type), k.To, fac, describeSources(k.Sources)})
				}
				return []string{"NAME", "TYPE", "TO", "FACILITY", "SOURCES"}, rows
			}, func() []string {
				var n []string
				for _, k := range f.Spec.Sinks {
					n = append(n, k.Name)
				}
				return n
			})
		},
	}
}

func (a *app) originNote(f api.LogForward) {
	if f.Status.Origin == api.LogForwardFromAPI {
		fprintln(a.env.Stderr, "jailops: the list stored through the API is in force (generation "+strconv.FormatInt(f.Status.Generation, 10)+"); 'logs forward reset' returns to jailopsd.yaml")
	} else {
		fprintln(a.env.Stderr, "jailops: the list of jailopsd.yaml (logging.forward) is in force")
	}
}

// sinkFlags are the flags of add and edit.
type sinkFlags struct {
	name, to, facility, ca, token string
	queue                         int
	projects, jails, labels       []string
	exJails, exLabels, files      []string
	noAppLogs, audit, auditOnly   bool
}

func (s *sinkFlags) register(a *app, cmd *cobra.Command, add bool) {
	f := cmd.Flags()
	f.StringVar(&s.to, "url", "", "where to send: udp://, tcp:// or tls://HOST[:PORT] for a syslog sink, an https:// URL for a webhook")
	f.StringVar(&s.facility, "facility", "", "syslog facility, local0 (default) to local7")
	f.StringVar(&s.ca, "ca", "", "PEM file of the CA that signed the receiver's certificate (tls and webhook; default: the host's roots)")
	f.StringVar(&s.token, "token-file", "", "root-owned file whose first line is the webhook's bearer token")
	f.IntVar(&s.queue, "queue", 0, "lines kept while the receiver is away (default 10000)")
	f.StringArrayVar(&s.projects, "from-project", nil, "only the jails of this project (repeatable)")
	f.StringArrayVar(&s.jails, "jail", nil, "only this jail (repeatable)")
	f.StringArrayVarP(&s.labels, "label", "l", nil, "only jails with this label KEY=VALUE (repeatable)")
	f.StringArrayVar(&s.exJails, "exclude-jail", nil, "leave out this jail (repeatable)")
	f.StringArrayVar(&s.exLabels, "exclude-label", nil, "leave out jails with this label KEY=VALUE (repeatable)")
	f.StringArrayVar(&s.files, "file", nil, "file below /var/log to send of every jail instead of messages (repeatable)")
	f.BoolVar(&s.noAppLogs, "no-app-logs", false, "leave out the log files installed apps declare")
	f.BoolVar(&s.audit, "audit", false, "send the daemon's audit log too")
	f.BoolVar(&s.auditOnly, "audit-only", false, "send the audit log and no jail logs")
	enumFlag(cmd, "facility", facilityNames...)
	_ = cmd.RegisterFlagCompletionFunc("ca", completeFiles)
	_ = cmd.RegisterFlagCompletionFunc("token-file", completeFiles)
	_ = cmd.RegisterFlagCompletionFunc("from-project", a.completeProjects())
	_ = cmd.RegisterFlagCompletionFunc("jail", completeKind(a, a.jailDesc()))
	_ = cmd.RegisterFlagCompletionFunc("exclude-jail", completeKind(a, a.jailDesc()))
	for _, n := range []string{"url", "queue", "label", "exclude-label", "file"} {
		_ = cmd.RegisterFlagCompletionFunc(n, completeNone)
	}
}

func parseSinkLabels(flag string, l []string) (map[string]string, error) {
	var out map[string]string
	for _, p := range l {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, usagef("--%s takes KEY=VALUE, not %q", flag, p)
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out, nil
}

// apply writes the flags that were given into k.
func (s *sinkFlags) apply(cmd *cobra.Command, k *api.LogSink) error {
	ch := func(n string) bool { return cmd.Flags().Changed(n) }
	if ch("url") {
		k.To = s.to
	}
	if ch("facility") {
		k.Facility = s.facility
	}
	if ch("ca") {
		k.CAFile = s.ca
	}
	if ch("token-file") {
		k.TokenFile = s.token
	}
	if ch("queue") {
		k.Queue = s.queue
	}
	src := &k.Sources
	if ch("from-project") {
		src.Projects = s.projects
	}
	if ch("jail") {
		src.Jails = s.jails
	}
	if ch("exclude-jail") {
		src.ExcludeJails = s.exJails
	}
	if ch("file") {
		src.Files = s.files
	}
	var err error
	if ch("label") {
		if src.Labels, err = parseSinkLabels("label", s.labels); err != nil {
			return err
		}
	}
	if ch("exclude-label") {
		if src.ExcludeLabels, err = parseSinkLabels("exclude-label", s.exLabels); err != nil {
			return err
		}
	}
	if ch("no-app-logs") {
		src.NoAppLogs = s.noAppLogs
	}
	if ch("audit") {
		src.Audit = s.audit
	}
	if ch("audit-only") {
		src.NoJails = s.auditOnly
		if s.auditOnly {
			src.Audit = true
		}
	}
	return nil
}

// changeSinks reads the list, lets change edit it and stores it, or with
// --dry-run prints what would be sent.
func (a *app) changeSinks(ctx context.Context, action string, show func(api.LogForwardSpec) any, change func(*api.LogForwardSpec) error) (api.LogForward, bool, error) {
	c, err := a.connect(ctx)
	if err != nil {
		return api.LogForward{}, false, err
	}
	f, err := c.Logs().Forward(ctx)
	if err != nil {
		return api.LogForward{}, false, err
	}
	spec := api.LogForwardSpec{Sinks: slices.Clone(f.Spec.Sinks)}
	if err := change(&spec); err != nil {
		return api.LogForward{}, false, err
	}
	if err := spec.Validate(); err != nil {
		return api.LogForward{}, false, asUsage(err)
	}
	if done, err := a.dry(action, show(spec)); done {
		return api.LogForward{}, true, err
	}
	out, err := c.Logs().SetForward(ctx, spec, f.Status.Generation)
	return out, false, err
}

func findSink(spec *api.LogForwardSpec, name string) (int, error) {
	i := slices.IndexFunc(spec.Sinks, func(k api.LogSink) bool { return k.Name == name })
	if i < 0 {
		return -1, api.Errorf(api.CodeNotFound, "sink %q not found", name).WithHint("list them with: jailops logs forward list")
	}
	return i, nil
}

func sinkByName(name string) func(api.LogForwardSpec) any {
	return func(s api.LogForwardSpec) any {
		for _, k := range s.Sinks {
			if k.Name == name {
				return k
			}
		}
		return nil
	}
}

// warnSink repeats what the server says about a stored sink.
func (a *app) warnSink(f api.LogForward, name string) {
	for _, st := range f.Status.Sinks {
		if st.Name == name && st.Warning != "" {
			fprintln(a.env.Stderr, "warning: "+st.Warning)
		}
	}
}

func (a *app) logForwardAdd() *cobra.Command {
	var s sinkFlags
	cmd := &cobra.Command{
		Use:   "add NAME --url URL",
		Short: "Add a sink",
		Long: `Add a sink. Its type follows from the URL: udp://, tcp:// and tls:// make a syslog sink, https:// a
webhook. A syslog sink sends RFC 5424 messages
with APP-NAME jailops, this host's name and the structured data
[jailops project="" jail="" app="" file=""]; --url tls://HOST[:6514] verifies
the server (the host's roots, or --ca), tcp:// and udp:// (port 514) send in
the clear and are for a receiver on this host or a trusted network. A webhook
receives POSTs of JSON lines (time, host, project, jail, app, file, line);
--token-file names a file owned by root (0640 root:jailops) whose first line
is the bearer token, which never enters the configuration.

Without --jail, --label or --from-project the sink takes every jail. --file
replaces messages; --no-app-logs leaves out the files installed apps declare;
--audit adds the daemon's audit log. The sink starts at the end of the files.`,
		Example: `jailops logs forward add logs --url tls://logs.example.com:6514 --facility local3
jailops logs forward add local --url tcp://127.0.0.1:1514 --jail web --jail db
jailops logs forward add front --url tls://logs.example.com --ca /usr/local/etc/jailops/logs-ca.pem -l tier=front
jailops logs forward add alerts --url https://hooks.example.com/jailops --token-file /usr/local/etc/jailops/sinks/hook.token --audit-only`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			if s.to == "" {
				return usagef("--url is required: where the sink sends (tls://logs.example.com:6514, https://hooks.example.com/x)")
			}
			typ := api.LogSinkSyslog
			if strings.HasPrefix(s.to, "https://") {
				typ = api.LogSinkWebhook
			}
			s.name = args[0]
			k := api.LogSink{Type: typ}
			if err := s.apply(cmd, &k); err != nil {
				return err
			}
			f, dry, err := a.changeSinks(cmd.Context(), "add log sink", func(sp api.LogForwardSpec) any { return sp.Sinks[len(sp.Sinks)-1] }, func(sp *api.LogForwardSpec) error {
				k.Name = s.name
				if slices.ContainsFunc(sp.Sinks, func(t api.LogSink) bool { return t.Name == k.Name }) {
					return api.Errorf(api.CodeAlreadyExists, "sink %q already exists", k.Name).WithHint("change it with: jailops logs forward set " + k.Name)
				}
				sp.Sinks = append(sp.Sinks, k)
				return nil
			})
			if err != nil || dry {
				return err
			}
			a.warnSink(f, k.Name)
			a.say("log-sink/%s added (%s %s)\n", k.Name, k.Type, k.To)
			return nil
		},
	}
	s.register(a, cmd, true)
	return cmd
}

func (a *app) logForwardSet() *cobra.Command {
	var s sinkFlags
	cmd := &cobra.Command{
		Use:   "set NAME",
		Short: "Change a sink",
		Long: `Change the flags given and keep the rest of the sink. A list flag (--jail,
--label, --file, ...) replaces that list. To start a selection over, remove
the sink and add it again.`,
		Example: `jailops logs forward set logs --facility local5
jailops logs forward set logs --url tls://logs2.example.com:6514 --ca /usr/local/etc/jailops/logs-ca.pem
jailops logs forward set alerts --audit=false`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeArgs(a.completeSinks(), completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().NFlag() == 0 {
				return usagef("nothing to change: give the flags to change")
			}
			name := args[0]
			f, dry, err := a.changeSinks(cmd.Context(), "change log sink "+name, sinkByName(name), func(sp *api.LogForwardSpec) error {
				i, err := findSink(sp, name)
				if err != nil {
					return err
				}
				k := sp.Sinks[i]
				k.Sources.Projects, k.Sources.Jails, k.Sources.ExcludeJails, k.Sources.Files =
					slices.Clone(k.Sources.Projects), slices.Clone(k.Sources.Jails), slices.Clone(k.Sources.ExcludeJails), slices.Clone(k.Sources.Files)
				if err := s.apply(cmd, &k); err != nil {
					return err
				}
				sp.Sinks[i] = k
				return nil
			})
			if err != nil || dry {
				return err
			}
			a.warnSink(f, name)
			a.say("log-sink/%s updated\n", name)
			return nil
		},
	}
	s.register(a, cmd, false)
	return cmd
}

func (a *app) logForwardRemove() *cobra.Command {
	return &cobra.Command{
		Use:               "remove NAME...",
		Aliases:           []string{"rm"},
		Short:             "Remove sinks",
		Long:              `Remove sinks. Their queued lines are dropped and their offsets forgotten. The command asks for confirmation unless -y is given.`,
		Example:           "jailops logs forward remove logs\njailops logs forward remove -y logs alerts\njailops logs forward remove logs alerts --dry-run",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: a.completeSinks(),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, dry, err := a.changeSinks(cmd.Context(), "remove log sink "+strings.Join(args, ", "), func(api.LogForwardSpec) any { return nil },
				func(sp *api.LogForwardSpec) error {
					for _, n := range args {
						i, err := findSink(sp, n)
						if err != nil {
							return err
						}
						sp.Sinks = slices.Delete(sp.Sinks, i, i+1)
					}
					if a.dryRun {
						return nil
					}
					return a.confirm(fmt.Sprintf("Remove log sink %s? Its queued lines are dropped.", strings.Join(args, ", ")))
				})
			if err != nil || dry {
				return err
			}
			for _, n := range args {
				a.say("log-sink/%s removed\n", n)
			}
			return nil
		},
	}
}

func (a *app) logForwardTest() *cobra.Command {
	return &cobra.Command{
		Use:   "test NAME",
		Short: "Send one tagged line to a sink",
		Long: `Send one line, "jailops log forwarding test ID from HOST", to the sink, with a
connection of its own, and print whether it was delivered (written to the
socket for syslog, answered with 2xx by a webhook). Search the receiver for
the ID. The command fails when the line was not delivered.`,
		Example:           "jailops logs forward test logs",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeArgs(a.completeSinks(), completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			r, err := c.Logs().TestForward(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if a.format == fmtJSON || a.format == fmtYAML {
				if err := a.emit(r, nil, nil, nil); err != nil {
					return err
				}
			} else if r.OK {
				fprintf(a.env.Stdout, "sent to %s in %d ms: %s\n", r.Sink, r.Millis, r.Line)
			}
			if !r.OK {
				return &hintError{err: fmt.Errorf("sink %q did not take the test line: %s", r.Sink, r.Error),
					hint: "check the receiver and the address; jailops logs forward status shows the sink's own state"}
			}
			return nil
		},
	}
}

func (a *app) logForwardStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show how each sink is doing",
		Long: `For each sink: the files it reads, the lines sent, queued and dropped, the last
delivery, since when it fails and the last error. doctor warns (logs.forward)
about a sink that has failed for more than five minutes.`,
		Example: "jailops logs forward status\njailops logs forward status -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			f, err := c.Logs().Forward(cmd.Context())
			if err != nil {
				return err
			}
			now := a.env.Now()
			when := func(t *time.Time) string {
				if t == nil {
					return "-"
				}
				return age(now, *t)
			}
			if a.format == fmtTable {
				for _, st := range f.Status.Sinks {
					if st.Warning != "" {
						fprintln(a.env.Stderr, "warning: "+st.Name+": "+st.Warning)
					}
				}
			}
			return a.emit(f.Status.Sinks, nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, st := range f.Status.Sinks {
					state := "ok"
					switch {
					case st.FailingSince != nil:
						state = "failing"
					case st.LastSuccess == nil:
						state = "idle"
					}
					dropped := strconv.FormatInt(st.Dropped, 10)
					if st.SkippedBytes > 0 {
						dropped += " (+" + humanBytes(st.SkippedBytes) + " unread)"
					}
					rows = append(rows, []string{st.Name, state, st.To, strconv.Itoa(st.Sources), strconv.FormatInt(st.Sent, 10), strconv.Itoa(st.Queued),
						dropped, when(st.LastSuccess), when(st.FailingSince), dash(st.LastError)})
				}
				return []string{"NAME", "STATE", "TO", "FILES", "SENT", "QUEUED", "DROPPED", "LAST SENT", "FAILING SINCE", "LAST ERROR"}, rows
			}, func() []string {
				var n []string
				for _, st := range f.Status.Sinks {
					n = append(n, st.Name)
				}
				return n
			})
		},
	}
}

func (a *app) logForwardReset() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Return to the sinks of jailopsd.yaml",
		Long: `Delete the list stored through the API or the console: logging.forward of
jailopsd.yaml is in force again. The command asks for confirmation unless -y is given.`,
		Example: "jailops logs forward reset\njailops logs forward reset -y\njailops logs forward reset --dry-run",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if done, err := a.dry("return to the log sinks of jailopsd.yaml", nil); done {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			cur, err := c.Logs().Forward(cmd.Context())
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Delete the stored list of %d log sinks and return to jailopsd.yaml?", len(cur.Spec.Sinks))); err != nil {
				return err
			}
			f, err := c.Logs().ResetForward(cmd.Context())
			if err != nil {
				return err
			}
			a.say("log-forward reset: jailopsd.yaml is in force again (%s)\n", count(len(f.Spec.Sinks), "sink", "sinks"))
			return nil
		},
	}
}

// asUsage turns an invalid error found before anything was sent into a usage error.
func asUsage(err error) error {
	var ae *api.Error
	if errors.As(err, &ae) && ae.Code == api.CodeInvalid {
		return usagef("%s", ae.Message)
	}
	return err
}
