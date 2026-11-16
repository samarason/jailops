package cli

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The host firewall module and commit confirmed (docs/appliance.md): 'host firewall show|set|apply|diff' and
// 'host pending|confirm|revert'. Every firewall change waits for a confirmation and reverts itself without one.

// confirmWithin turns --confirm-within (seconds, or a duration such as 90s or 5m) into seconds.
func confirmWithin(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		d, derr := time.ParseDuration(v)
		if derr != nil || d%time.Second != 0 {
			return 0, usagef("--confirm-within is seconds or a duration such as 120s or 5m, not %q", v)
		}
		n = int(d / time.Second)
	}
	if _, err := api.ConfirmWindow(n); err != nil || n == 0 {
		return 0, usagef("--confirm-within is %d to %d seconds, not %q", api.MinConfirmWithin, api.MaxConfirmWithin, v)
	}
	return n, nil
}

// sources reads a repeated source flag; "any" alone means anywhere.
func sources(v []string) []string {
	var out []string
	for _, s := range v {
		for _, x := range strings.Split(s, ",") {
			if x = strings.TrimSpace(x); x != "" && x != "any" {
				out = append(out, x)
			}
		}
	}
	return out
}

func (a *app) hostFirewallCmd() *cobra.Command {
	fc := group("firewall", "Manage this host's packet filter (/etc/pf.conf)",
		`The firewall module: with it enabled in jailopsd.yaml and priv.conf, JailOps owns
/etc/pf.conf as a whole file, rendered by the privileged helper from a few
settings: a template (default, open or custom-rules), the ssh ports and who may
use them, who may reach the console, more ports to open (custom-rules), address
sets, ping and logging. The jails' anchor lines are always in it, as are
neighbour discovery and path MTU discovery. Every change reverts itself unless
it is confirmed in time ('jailops host confirm'); a change that would shut out
the address the request comes from is refused. Without the module JailOps never
touches pf.conf.`,
		"jailops host firewall show\njailops host firewall set --ssh-from 192.0.2.0/24 --dry-run\njailops host firewall apply -f firewall.yaml --confirm-within 5m")
	fc.AddCommand(a.hostFirewallShowCmd(), a.hostFirewallSetCmd(), a.hostFirewallAllowCmd(), a.hostFirewallSetsCmd(), a.hostFirewallApplyCmd(), a.hostFirewallDiffCmd())
	return fc
}

func (a *app) hostFirewallShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the host firewall: what was applied, its rules, drift and pf",
		Long: `Show the settings JailOps applied (or, before any apply, the default it would
apply), the rules they make in plain words, whether pf runs, drift and the
change that waits for a confirmation. -o json and -o yaml print the object.`,
		Example: "jailops host firewall show\njailops host firewall show -o yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			fw, err := c.HostSystem().Firewall().Get(cmd.Context())
			if err != nil {
				return err
			}
			if a.format != fmtTable {
				return a.emit(fw, nil, nil, func() []string { return []string{fw.Spec.Template} })
			}
			w, st := a.env.Stdout, fw.Status
			a.printTable(w, []string{"ACTION", "DIR", "PROTO", "PORTS", "FROM", "WHAT"}, fwRuleRows(fw.Status.Rules), nil)
			fprintln(w)
			managed := "no"
			switch {
			case st.Managed:
				managed = "yes (module firewall)"
			case st.ConfigEnabled:
				managed = "no: jailopsd.yaml enables firewall, priv.conf does not (host-manage = firewall)"
			case st.HelperEnabled:
				managed = "no: priv.conf enables firewall, jailopsd.yaml does not (host.manage.modules)"
			}
			fprintf(w, "Managed:     %s\n", managed)
			fprintf(w, "Template:    %s\n", fw.Spec.Template)
			pf := "unknown (pfctl did not answer)"
			if st.PFEnabled != nil {
				pf = map[bool]string{true: "running", false: "not running"}[*st.PFEnabled]
			}
			fprintf(w, "pf:          %s\n", pf)
			file := "absent"
			if st.FileExists {
				file = "the administrator's"
				if st.FileManaged {
					file = "managed by jailops"
				}
			}
			fprintf(w, "pf.conf:     %s\n", file)
			if st.AppliedAt != nil {
				fprintf(w, "Applied:     %s\n", st.AppliedAt.UTC().Format("2006-01-02 15:04:05Z"))
			}
			if len(st.Drift) > 0 {
				fprintf(w, "Drift:       %s (changed outside JailOps; see 'jailops host firewall diff')\n", strings.Join(st.Drift, ", "))
			} else if st.Applied != nil {
				fprintf(w, "Drift:       none\n")
			}
			if p := st.Pending; p != nil {
				fprintf(w, "Pending:     %s change %s reverts at %s unless confirmed (jailops host confirm)\n", p.Module, p.ID, p.Deadline.UTC().Format("15:04:05Z"))
			}
			for _, warn := range st.Warnings {
				fprintf(w, "Warning:     %s\n", warn)
			}
			if !st.Managed {
				fprintln(w, "\nJailOps does not touch /etc/pf.conf. To let it manage the firewall, add to")
				fprintln(w, "/usr/local/etc/jailops/jailopsd.yaml:")
				fprintln(w, "  host:\n    manage:\n      modules: [firewall]")
				fprintln(w, "and to /usr/local/etc/jailops/priv.conf:")
				fprintln(w, "  host-manage = firewall")
				fprintln(w, "then: service jailops_priv restart && service jailopsd restart")
			}
			return nil
		},
	}
}

func fwRuleRows(rules []api.HostFirewallRule) [][]string {
	var rows [][]string
	for _, r := range rules {
		what := r.Comment
		if r.Fixed {
			what += " (always)"
		}
		rows = append(rows, []string{r.Action, r.Direction, dash(r.Proto), dash(r.Ports), dash(r.From), dash(what)})
	}
	return rows
}

// fwApplyFlags are the flags every firewall change has.
type fwApplyFlags struct {
	within string
	iKnow  bool
}

func (f *fwApplyFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.within, "confirm-within", "", fmt.Sprintf("the change reverts unless confirmed within this time (seconds or 90s, 5m; default %ds, at most %ds)", api.DefaultConfirmWithin, api.MaxConfirmWithin))
	cmd.Flags().BoolVar(&f.iKnow, "confirm-lockout", false, "apply although the address of this request is unknown (the unix socket, a hub), so the lock-out check cannot run")
}

// applyFirewall sends a spec and prints the result.
func (a *app) applyFirewall(ctx context.Context, c *sdk.Client, spec api.HostFirewallSpec, f fwApplyFlags) error {
	within, err := confirmWithin(f.within)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	ch, err := c.HostSystem().Firewall().Apply(ctx, api.HostFirewallApply{Spec: spec, DryRun: a.dryRun, ConfirmWithin: within, ConfirmLockout: f.iKnow})
	if err != nil {
		return err
	}
	return a.printHostChange("host firewall", ch)
}

func (a *app) hostFirewallSetCmd() *cobra.Command {
	var template, icmp, logging string
	var sshPorts []int
	var sshFrom, consoleFrom []string
	var af fwApplyFlags
	cmd := &cobra.Command{
		Use:   "set [flags]",
		Short: "Change the host firewall from flags",
		Long: `Start from what was applied last (or the default) and change what the flags
name: --template, --ssh-port and --ssh-from, --console-from (sources are
addresses, prefixes or @set; "any" means anywhere), --icmp and --logging. The
rows of custom-rules and the address sets have commands of their own: 'host
firewall allow' and 'host firewall address-set'. --dry-run shows the diff of
/etc/pf.conf and the rules.
The change reverts itself unless 'jailops host confirm' follows within
--confirm-within. It needs the admin role.`,
		Example: `jailops host firewall set --ssh-from 192.0.2.0/24 --ssh-from 2001:db8:a::/48 --dry-run
jailops host firewall set --template custom-rules --confirm-within 5m
jailops host firewall set --ssh-from @admins --console-from @admins`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fl := cmd.Flags()
			for _, x := range []struct{ name, v string }{{"icmp", icmp}, {"logging", logging}} {
				if x.v != "" && x.v != "enable" && x.v != "disable" {
					return usagef("--%s is enable or disable, not %q", x.name, x.v)
				}
			}
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			cur, err := c.HostSystem().Firewall().Get(ctx)
			if err != nil {
				return err
			}
			spec := cur.Spec
			if fl.Changed("template") {
				spec.Template = template
			}
			if spec.SSH == nil {
				spec.SSH = &api.HostFirewallSSH{}
			}
			if spec.Console == nil {
				spec.Console = &api.HostFirewallConsole{}
			}
			spec.Console.Port = 0 // the daemon's own
			if fl.Changed("ssh-port") {
				spec.SSH.Ports = sshPorts
			}
			if fl.Changed("ssh-from") {
				spec.SSH.AllowFrom = sources(sshFrom)
			}
			if fl.Changed("console-from") {
				spec.Console.AllowFrom = sources(consoleFrom)
			}
			if icmp != "" {
				spec.ICMP = icmp == "enable"
			}
			if logging != "" {
				spec.Logging = logging == "enable"
			}
			return a.applyFirewall(ctx, c, spec, af)
		},
	}
	f := cmd.Flags()
	f.StringVar(&template, "template", "", "default, open or custom-rules")
	enumFlag(cmd, "template", api.HostFirewallTemplates...)
	f.IntSliceVar(&sshPorts, "ssh-port", nil, "a port sshd listens on (repeatable, at most 4; replaces the list)")
	f.StringArrayVar(&sshFrom, "ssh-from", nil, "who may use ssh: an address, a prefix, @set or any (repeatable; replaces the list)")
	f.StringArrayVar(&consoleFrom, "console-from", nil, "who may reach the console and the API (repeatable; replaces the list)")
	f.StringVar(&icmp, "icmp", "", "enable or disable ping (neighbour discovery and path MTU discovery stay on)")
	enumFlag(cmd, "icmp", "enable", "disable")
	f.StringVar(&logging, "logging", "", "enable or disable logging what the final block rule drops")
	enumFlag(cmd, "logging", "enable", "disable")
	af.add(cmd)
	return cmd
}

func (a *app) hostFirewallApplyCmd() *cobra.Command {
	var file string
	var af fwApplyFlags
	cmd := &cobra.Command{
		Use:   "apply -f FILE",
		Short: "Apply a host firewall from a YAML or JSON file",
		Long: `Apply the HostFirewallSpec in FILE (a spec, or a document with a spec key such as
'jailops host firewall show -o yaml' prints). The whole spec is applied: a part
left out takes its default. The change reverts itself unless 'jailops host
confirm' follows within --confirm-within. It needs the admin role.`,
		Example: "jailops host firewall show -o yaml > fw.yaml\njailops host firewall apply -f fw.yaml --dry-run\njailops host firewall apply -f fw.yaml --confirm-within 300",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return usagef("-f FILE is required")
			}
			spec, err := a.readFirewallSpec(file)
			if err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			return a.applyFirewall(cmd.Context(), c, spec, af)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML or JSON file with the spec, or - for standard input")
	af.add(cmd)
	return cmd
}

// readFirewallSpec reads a spec, or a HostFirewall document, from a file.
func (a *app) readFirewallSpec(file string) (api.HostFirewallSpec, error) {
	b, err := a.readInput(file)
	if err != nil {
		return api.HostFirewallSpec{}, err
	}
	docs, err := readDocs(b)
	if err != nil {
		return api.HostFirewallSpec{}, err
	}
	if len(docs) != 1 {
		return api.HostFirewallSpec{}, usagef("the file holds %d documents, not one firewall spec", len(docs))
	}
	doc := docs[0]
	if s, ok := doc["spec"]; ok {
		if k, ok := doc["kind"]; ok && k != string(api.KindHostFirewall) {
			return api.HostFirewallSpec{}, usagef("the document is a %v, not a HostFirewall", k)
		}
		doc, _ = s.(map[string]any)
	}
	var spec api.HostFirewallSpec
	if err := decodeStrict(doc, &spec); err != nil {
		return spec, err
	}
	if spec.Console != nil {
		spec.Console.Port = 0 // the daemon's own
	}
	return spec, nil
}

func (a *app) hostFirewallDiffCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "diff [-f FILE]",
		Short: "Show how /etc/pf.conf differs from what JailOps would write",
		Long: `Without -f: render what was applied last again and show how /etc/pf.conf differs
from it (a hand edit shows as drift). With -f: the same for the spec in FILE.
Nothing changes; it is the dry run of an apply.`,
		Example: "jailops host firewall diff\njailops host firewall diff -f fw.yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			var spec api.HostFirewallSpec
			if file != "" {
				if spec, err = a.readFirewallSpec(file); err != nil {
					return err
				}
			} else {
				cur, err := c.HostSystem().Firewall().Get(ctx)
				if err != nil {
					return err
				}
				spec = cur.Spec
				if spec.Console != nil {
					spec.Console.Port = 0
				}
			}
			ch, err := c.HostSystem().Firewall().Apply(ctx, api.HostFirewallApply{Spec: spec, DryRun: true, ConfirmLockout: true})
			if err != nil {
				return err
			}
			if a.format != fmtTable {
				return a.emit(ch, nil, nil, nil)
			}
			if !ch.Changed {
				a.say("host firewall: /etc/pf.conf is what JailOps would write\n")
				return nil
			}
			fprintf(a.env.Stdout, "%s", ch.Diff)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML or JSON file with the spec, or - for standard input")
	return cmd
}

func (a *app) printPending(p api.HostPending) error {
	if a.format != fmtTable {
		return a.emit(p, nil, nil, func() []string {
			if p.Pending != nil {
				return []string{p.Pending.ID}
			}
			return nil
		})
	}
	w := a.env.Stdout
	if c := p.Pending; c != nil {
		fprintf(w, "Pending:     %s change %s (snapshot %s)\n", c.Module, c.ID, c.Snapshot)
		fprintf(w, "Reverts at:  %s, in %d s, unless confirmed: jailops host confirm --id %s\n", c.Deadline.UTC().Format("2006-01-02 15:04:05Z"), c.SecondsLeft, c.ID)
	} else {
		fprintln(w, "Pending:     nothing waits for a confirmation")
	}
	if o := p.Last; o != nil {
		fprintf(w, "Last:        %s change %s was %s at %s", o.Module, o.ID, strings.ReplaceAll(o.Outcome, "_", " "), o.Time.UTC().Format("2006-01-02 15:04:05Z"))
		if o.Detail != "" {
			fprintf(w, " (%s)", o.Detail)
		}
		fprintln(w)
	}
	return nil
}

func (a *app) completePendingID() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, _ []string) ([]string, error) {
		p, err := c.HostSystem().Pending(ctx)
		if err != nil || p.Pending == nil {
			return nil, err
		}
		return []string{p.Pending.ID}, nil
	})
}

func (a *app) hostPendingCmds() []*cobra.Command {
	pending := &cobra.Command{
		Use:   "pending",
		Short: "Show the host change that waits for its confirmation",
		Long: `Show the host change (module, id, snapshot, deadline) that reverts itself unless
it is confirmed, and how the last one ended. The deadline is kept by the
privileged helper: neither a restart of the daemon nor a lost connection stops
the revert.`,
		Example: "jailops host pending\njailops host pending -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			p, err := c.HostSystem().Pending(cmd.Context())
			if err != nil {
				return err
			}
			return a.printPending(p)
		},
	}
	act := func(use, short, long, verb string, confirm bool) *cobra.Command {
		var id string
		cmd := &cobra.Command{
			Use: use, Short: short, Long: long,
			Example: "jailops host " + verb + "\njailops host " + verb + " --id 0123456789abcdef\njailops --dry-run host " + verb,
			Args:    cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if err := api.ValidHostPendingID(id); err != nil {
					return err
				}
				ctx := cmd.Context()
				c, err := a.connect(ctx)
				if err != nil {
					return err
				}
				if a.dryRun {
					p, err := c.HostSystem().Pending(ctx)
					if err != nil {
						return err
					}
					if p.Pending == nil {
						return api.Errorf(api.CodeNotFound, "no host change waits for a confirmation")
					}
					fprintf(a.env.Stdout, "dry-run: would %s the %s change %s\n", verb, p.Pending.Module, p.Pending.ID)
					return nil
				}
				var p api.HostPending
				if confirm {
					p, err = c.HostSystem().Confirm(ctx, id)
				} else {
					if err := a.confirm("Put the snapshot of the pending host change back now?"); err != nil {
						return err
					}
					p, err = c.HostSystem().Revert(ctx, id)
				}
				if err != nil {
					return err
				}
				return a.printPending(p)
			},
		}
		cmd.Flags().StringVar(&id, "id", "", "the id of the pending change (default: whichever waits)")
		_ = cmd.RegisterFlagCompletionFunc("id", a.completePendingID())
		return cmd
	}
	return []*cobra.Command{pending,
		act("confirm [--id ID]", "Keep the host change that waits for its confirmation",
			`Keep the pending change: the helper stops its timer and the change stays. Send it
through the new configuration (over the new firewall rules), which proves that
you can still reach the host. It needs the admin role.`, "confirm", true),
		act("revert [--id ID]", "Undo the host change that waits for its confirmation, now",
			`Put the snapshot of the pending change back now instead of at its deadline, and
make it take effect (pfctl -f). It needs the admin role.`, "revert", false),
	}
}

// changeHostFirewall starts from what was applied last (or the default), lets mutate change the spec and applies it
// with the confirmation window every host firewall change has.
func (a *app) changeHostFirewall(cmd *cobra.Command, af fwApplyFlags, mutate func(spec *api.HostFirewallSpec) error) error {
	ctx := cmd.Context()
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	cur, err := c.HostSystem().Firewall().Get(ctx)
	if err != nil {
		return err
	}
	spec := cur.Spec
	if spec.SSH == nil {
		spec.SSH = &api.HostFirewallSSH{}
	}
	if spec.Console == nil {
		spec.Console = &api.HostFirewallConsole{}
	}
	spec.Console.Port = 0 // the daemon's own
	if err := mutate(&spec); err != nil {
		return err
	}
	return a.applyFirewall(ctx, c, spec, af)
}

// hostFirewallAllowCmd is the group of the rows of the custom-rules template: more ports to pass to the host.
func (a *app) hostFirewallAllowCmd() *cobra.Command {
	ac := group("allow", "Manage the rows of the custom-rules template (ports passed to the host)",
		`A row passes a protocol and ports to the host, from anyone or from the sources it names, with a
comment that says what it is for. Rows count from 1 in the order of 'host firewall allow list' and apply with the
custom-rules template. Every change reverts itself unless 'jailops host confirm' follows in time.`,
		"jailops host firewall allow add --proto tcp --port 80,443 --comment \"the web\"\njailops host firewall allow list\njailops host firewall allow remove 1")
	ac.AddCommand(a.hostFirewallAllowAdd(), a.hostFirewallAllowList(), a.hostFirewallAllowRemove())
	return ac
}

func (a *app) hostFirewallAllowAdd() *cobra.Command {
	var proto, comment string
	var ports, from []string
	var af fwApplyFlags
	cmd := &cobra.Command{
		Use:   "add --proto PROTO --port PORT --comment TEXT [--from SOURCE]",
		Short: "Add a row: ports passed to the host",
		Long: `Add a row at the end. --port takes ports and ranges (repeat the flag or separate them with commas),
--from the sources that may use them (an address, a prefix, @set; none or "any" means anyone). The comment says what
the row is for. The template has to be custom-rules ('jailops host firewall set --template custom-rules').`,
		Example: `jailops host firewall allow add --proto tcp --port 80,443 --comment "the web"
jailops host firewall allow add --proto udp --port 51820 --from 192.0.2.0/24 --comment "WireGuard from the office"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if proto == "" || len(ports) == 0 {
				return usagef("--proto and --port are required")
			}
			if strings.TrimSpace(comment) == "" {
				return usagef("--comment is required: say what the row is for")
			}
			row := api.HostFirewallAllow{Proto: proto, Comment: comment, From: sources(from)}
			for _, p := range ports {
				for _, x := range strings.Split(p, ",") {
					if x = strings.TrimSpace(x); x != "" {
						row.Ports = append(row.Ports, x)
					}
				}
			}
			return a.changeHostFirewall(cmd, af, func(spec *api.HostFirewallSpec) error {
				spec.Allow = append(spec.Allow, row)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&proto, "proto", "", "tcp or udp")
	enumFlag(cmd, "proto", "tcp", "udp")
	f.StringArrayVar(&ports, "port", nil, "a port or a range such as 8000-8100 (repeatable)")
	f.StringArrayVar(&from, "from", nil, "who may use it: an address, a prefix, @set or any (repeatable; none means anyone)")
	f.StringVar(&comment, "comment", "", "what the row is for")
	_ = cmd.RegisterFlagCompletionFunc("from", a.completeHostFirewall(func(spec api.HostFirewallSpec, _ []string) []string {
		out := []string{"any"}
		for _, st := range spec.Sets {
			out = append(out, "@"+st.Name+"\t"+strings.Join(st.Members, ","))
		}
		return out
	}))
	af.add(cmd)
	return cmd
}

// completeHostFirewall completes from the spec the host firewall has now.
func (a *app) completeHostFirewall(from func(spec api.HostFirewallSpec, args []string) []string) completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		fw, err := c.HostSystem().Firewall().Get(ctx)
		if err != nil {
			return nil, err
		}
		return from(fw.Spec, args), nil
	})
}

func (a *app) hostFirewallAllowList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the rows of the custom-rules template",
		Long:    `List the rows with their numbers: protocol, ports, sources and comment.`,
		Example: "jailops host firewall allow list\njailops host firewall allow list -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			fw, err := c.HostSystem().Firewall().Get(cmd.Context())
			if err != nil {
				return err
			}
			rows := fw.Spec.Allow
			return a.emit(rows, nil, func() ([]string, [][]string) {
				var out [][]string
				for i, r := range rows {
					out = append(out, []string{fmt.Sprint(i + 1), r.Proto, strings.Join(r.Ports, ","), dash(strings.Join(r.From, ",")), dash(r.Comment)})
				}
				return []string{"#", "PROTO", "PORTS", "FROM", "COMMENT"}, out
			}, nil)
		},
	}
}

func (a *app) hostFirewallAllowRemove() *cobra.Command {
	var af fwApplyFlags
	cmd := &cobra.Command{
		Use:     "remove NUMBER",
		Short:   "Remove a row",
		Long:    `Remove the row with that number of 'host firewall allow list'. The rows after it move up.`,
		Example: "jailops host firewall allow remove 2",
		Args:    cobra.ExactArgs(1),
		ValidArgsFunction: a.completeHostFirewall(func(spec api.HostFirewallSpec, args []string) []string {
			if len(args) > 0 {
				return nil
			}
			var out []string
			for i, r := range spec.Allow {
				out = append(out, fmt.Sprintf("%d\t%s %s %s", i+1, r.Proto, strings.Join(r.Ports, ","), r.Comment))
			}
			return out
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[0])
			if err != nil || n < 1 {
				return usagef("the number of a row is 1 or more, not %q", args[0])
			}
			return a.changeHostFirewall(cmd, af, func(spec *api.HostFirewallSpec) error {
				if n > len(spec.Allow) {
					return api.Errorf(api.CodeNotFound, "there is no row %d: the firewall has %d", n, len(spec.Allow)).WithHint("jailops host firewall allow list")
				}
				spec.Allow = slices.Delete(slices.Clone(spec.Allow), n-1, n)
				return nil
			})
		},
	}
	af.add(cmd)
	return cmd
}

// hostFirewallSetsCmd is the group of the address sets of the host firewall: named lists a source can name as @NAME.
func (a *app) hostFirewallSetsCmd() *cobra.Command {
	sc := group("address-set", "Manage the address sets of the host firewall",
		`An address set is a named list of addresses and prefixes that ssh, console and allow sources name as @NAME.
Every change reverts itself unless 'jailops host confirm' follows in time.`,
		"jailops host firewall address-set create admins --member 192.0.2.0/24 --member 2001:db8:a::/48\njailops host firewall set --ssh-from @admins")
	sc.AddCommand(a.hostFirewallSetWrite(true), a.hostFirewallSetWrite(false), a.hostFirewallSetList(), a.hostFirewallSetDelete())
	return sc
}

func (a *app) hostFirewallSetWrite(create bool) *cobra.Command {
	var members []string
	var af fwApplyFlags
	verb, short := "set", "Replace the members of an address set"
	if create {
		verb, short = "create", "Create an address set"
	}
	cmd := &cobra.Command{
		Use:               verb + " NAME --member MEMBER",
		Short:             short,
		Long:              short + `. --member is an address or a prefix and is repeated for each one.`,
		Example:           "jailops host firewall address-set " + verb + " admins --member 192.0.2.0/24 --member 2001:db8:a::/48",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeHostSetNames(!create),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			var list []string
			for _, m := range members {
				for _, x := range strings.Split(m, ",") {
					if x = strings.TrimSpace(x); x != "" {
						list = append(list, x)
					}
				}
			}
			if len(list) == 0 {
				return usagef("--member is required: an address or a prefix, repeated for each one")
			}
			return a.changeHostFirewall(cmd, af, func(spec *api.HostFirewallSpec) error {
				i := slices.IndexFunc(spec.Sets, func(s api.HostFirewallSet) bool { return s.Name == name })
				switch {
				case create && i >= 0:
					return api.Errorf(api.CodeAlreadyExists, "address set %q already exists", name).WithHint("replace its members with 'jailops host firewall address-set set'")
				case !create && i < 0:
					return api.Errorf(api.CodeNotFound, "address set %q not found", name).WithHint("jailops host firewall address-set list")
				case i >= 0:
					spec.Sets = slices.Clone(spec.Sets)
					spec.Sets[i].Members = list
				default:
					spec.Sets = append(spec.Sets, api.HostFirewallSet{Name: name, Members: list})
				}
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&members, "member", nil, "an address or a prefix (repeatable)")
	af.add(cmd)
	return cmd
}

func (a *app) hostFirewallSetList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the address sets of the host firewall",
		Long:    `List the sets with their members.`,
		Example: "jailops host firewall address-set list",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			fw, err := c.HostSystem().Firewall().Get(cmd.Context())
			if err != nil {
				return err
			}
			sets := fw.Spec.Sets
			return a.emit(sets, nil, func() ([]string, [][]string) {
				var out [][]string
				for _, st := range sets {
					out = append(out, []string{st.Name, strings.Join(st.Members, ",")})
				}
				return []string{"NAME", "MEMBERS"}, out
			}, nil)
		},
	}
}

func (a *app) hostFirewallSetDelete() *cobra.Command {
	var af fwApplyFlags
	cmd := &cobra.Command{
		Use:               "delete NAME",
		Short:             "Delete an address set",
		Long:              `Delete the set. A source that still names it as @NAME makes the spec invalid, and nothing is applied.`,
		Example:           "jailops host firewall address-set delete admins",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeHostSetNames(true),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			return a.changeHostFirewall(cmd, af, func(spec *api.HostFirewallSpec) error {
				i := slices.IndexFunc(spec.Sets, func(s api.HostFirewallSet) bool { return s.Name == name })
				if i < 0 {
					return api.Errorf(api.CodeNotFound, "address set %q not found", name).WithHint("jailops host firewall address-set list")
				}
				spec.Sets = slices.Delete(slices.Clone(spec.Sets), i, i+1)
				return nil
			})
		},
	}
	af.add(cmd)
	return cmd
}

// completeHostSetNames completes the names of the address sets of the host firewall for the first argument; a new
// name (create) completes nothing and never the files of the directory.
func (a *app) completeHostSetNames(existing bool) completer {
	if !existing {
		return completeNone
	}
	return a.completeHostFirewall(func(spec api.HostFirewallSpec, args []string) []string {
		if len(args) > 0 {
			return nil
		}
		var out []string
		for _, st := range spec.Sets {
			out = append(out, st.Name+"\t"+strings.Join(st.Members, ","))
		}
		return out
	})
}
