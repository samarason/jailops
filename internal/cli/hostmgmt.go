package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// Host management (appliance mode, docs/appliance.md): this host's name, resolvers and NTP, and the copies of host
// files kept before each change. The commands sit next to the hub's host commands: 'host show' without a name is
// this host.

const hostMgmtLong = `
Without a NAME, 'host show' shows this host: its name, resolvers and NTP, and
whether JailOps manages them. JailOps changes the host itself only for the
modules enabled in both jailopsd.yaml (host.manage.modules) and the helper's
priv.conf (host-manage); otherwise 'host identity set' answers not_managed and
nothing changes. Every change keeps a copy of the files it touches first
('host snapshots', 'host restore').`

// addHostManagement adds the host management commands to the host group.
func (a *app) addHostManagement(hc *cobra.Command) {
	hc.Short = "Manage this host, and the hosts a hub controls"
	hc.Long += "\n" + hostMgmtLong
	hc.Example = "jailops host show\njailops host identity set --hostname web1.example.org --dry-run\njailops host certificate show\n" + hc.Example
	for _, c := range hc.Commands() {
		if c.Name() != "show" {
			continue
		}
		hubShow := c.RunE
		c.Use = "show [NAME]"
		c.Short = "Show this host, or one host of the hub"
		c.Long = "Without NAME: this host's name, resolvers, NTP and how JailOps manages them (also with -o json or yaml).\nWith NAME: one host the hub controls, with its specification and observed status."
		c.Example = "jailops host show\njailops host show -o json\njailops host show host-b"
		c.Args = cobra.MaximumNArgs(1)
		c.RunE = func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return hubShow(cmd, args)
			}
			return a.hostShow(cmd.Context())
		}
	}
	hc.AddCommand(a.hostIdentityCmd(), a.hostSnapshotsCmd(), a.hostRestoreCmd(), a.hostFirewallCmd(), a.hostCertificateCmd())
	hc.AddCommand(a.hostPendingCmds()...)
}

func (a *app) hostShow(ctx context.Context) error {
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	id, err := c.HostSystem().Identity().Get(ctx)
	if err != nil {
		return err
	}
	if a.format != fmtTable {
		return a.emit(id, nil, func() ([]string, [][]string) { return hostIdentityRows(id) }, func() []string { return []string{id.Spec.Hostname} })
	}
	w := a.env.Stdout
	st := id.Status
	managed := "no"
	switch {
	case st.Managed:
		managed = "yes (module identity)"
	case st.ConfigEnabled:
		managed = "no: jailopsd.yaml enables identity, priv.conf does not (host-manage = identity)"
	case st.HelperEnabled:
		managed = "no: priv.conf enables identity, jailopsd.yaml does not (host.manage.modules)"
	}
	h, rows := hostIdentityRows(id)
	a.printTable(w, h, rows, nil)
	fprintln(w)
	fprintf(w, "Managed:     %s\n", managed)
	if st.RCHostname != "" && !strings.EqualFold(st.RCHostname, id.Spec.Hostname) {
		fprintf(w, "At boot:     %s (hostname in /etc/rc.conf)\n", st.RCHostname)
	}
	if st.AppliedAt != nil {
		fprintf(w, "Applied:     %s\n", st.AppliedAt.UTC().Format("2006-01-02 15:04:05Z"))
	}
	if len(st.Drift) > 0 {
		fprintf(w, "Drift:       %s (changed outside JailOps since it was applied)\n", strings.Join(st.Drift, ", "))
	} else if st.Applied != nil {
		fprintf(w, "Drift:       none\n")
	}
	if !st.Managed {
		fprintln(w, "\nJailOps does not change this host. To let it manage the identity, add to")
		fprintln(w, "/usr/local/etc/jailops/jailopsd.yaml:")
		fprintln(w, "  host:\n    manage:\n      modules: [identity]")
		fprintln(w, "and to /usr/local/etc/jailops/priv.conf:")
		fprintln(w, "  host-manage = identity")
		fprintln(w, "then: service jailops_priv restart && service jailopsd restart")
	}
	return nil
}

func hostIdentityRows(id api.HostIdentity) ([]string, [][]string) {
	sp, st := id.Spec, id.Status
	var rows [][]string
	rows = append(rows, []string{"hostname", dash(sp.Hostname)})
	if r := sp.Resolvers; r != nil {
		src := "/etc/resolv.conf"
		if st.ResolvConfManaged {
			src += " (managed by jailops)"
		}
		rows = append(rows, []string{"nameservers", dash(strings.Join(r.Nameservers, " ")) + "  " + src}, []string{"search", dash(strings.Join(r.Search, " "))})
	}
	if n := sp.NTP; n != nil {
		rows = append(rows, []string{"ntp servers", dash(strings.Join(n.Servers, " ")) + "  (the jailops block of /etc/ntp.conf)"}, []string{"ntpd", map[bool]string{true: "enabled", false: "disabled"}[n.Enable]})
	}
	sync := "unknown (ntpq did not answer)"
	if s := st.NTPSync; s != nil {
		sync = "not synchronised"
		if s.Synchronised {
			sync = "synchronised to " + s.Peer
		} else if s.Detail != "" {
			sync += ": " + s.Detail
		}
	}
	rows = append(rows, []string{"time", sync})
	return []string{"SETTING", "VALUE"}, rows
}

// printHostChange prints the result of an apply or a restore.
func (a *app) printHostChange(what string, ch api.HostChange) error {
	if a.format != fmtTable {
		return a.emit(ch, nil, nil, func() []string { return []string{ch.Snapshot} })
	}
	w := a.env.Stdout
	if !ch.Changed {
		a.say("%s: the host already has it, nothing to do\n", what)
		return nil
	}
	if ch.Diff != "" {
		fprintf(w, "%s", ch.Diff)
	}
	if ch.DryRun {
		fprintln(w, "dry-run: would")
	}
	for _, s := range ch.Actions {
		fprintf(w, "  %s\n", s)
	}
	for _, s := range ch.Warnings {
		a.say("warning: %s\n", s)
	}
	switch {
	case ch.DryRun:
	case ch.Pending != nil:
		a.say("%s: applied; it REVERTS at %s (in %d s) unless you confirm it: jailops host confirm --id %s\n",
			what, ch.Pending.Deadline.UTC().Format("15:04:05Z"), ch.Pending.SecondsLeft, ch.Pending.ID)
	default:
		a.say("%s: done; undo with: jailops host restore %s\n", what, ch.Snapshot)
	}
	return nil
}

func (a *app) hostIdentityCmd() *cobra.Command {
	ic := group("identity", "Set this host's name, resolvers and NTP servers",
		`The identity module: the host name (hostname(1) and hostname in /etc/rc.conf),
/etc/resolv.conf (written whole, marked "# managed by jailops") and the NTP servers
between "# jailops begin" and "# jailops end" in /etc/ntp.conf, with ntpd_enable.
Nothing else in those files changes. A change made by hand later is reported as
drift ('host show', 'doctor'), never overwritten silently.`,
		"jailops host identity set --hostname web1.example.org --dry-run\njailops host identity set --nameserver 192.0.2.53 --nameserver 2001:db8::53 --search example.org")
	var hostname, ntp string
	var ns, search, ntpServers []string
	set := &cobra.Command{
		Use:   "set [--hostname H] [--nameserver IP]... [--search DOMAIN]... [--ntp-server S]... [--ntp enable|disable]",
		Short: "Change the host name, the resolvers or NTP",
		Long: `Change the parts named by the flags; the others stay as they are. --nameserver
and --search replace the resolvers (the search list is kept when only nameservers
are given); --ntp-server replaces the NTP servers JailOps manages, --ntp turns
ntpd on or off. With --dry-run the server shows the diff and the steps and
changes nothing. A change keeps a copy of every file it touches first; the
command prints the snapshot to restore. Needs the admin role and the module
enabled (see 'jailops host show').`,
		Example: `jailops host identity set --hostname web1.example.org --dry-run
jailops host identity set --nameserver 192.0.2.53 --nameserver 2001:db8::53 --search example.org
jailops host identity set --ntp-server 0.pool.example.org --ntp enable`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fl := cmd.Flags()
			spec := api.HostIdentitySpec{Hostname: hostname}
			if ntp != "" && ntp != "enable" && ntp != "disable" {
				return usagef("--ntp is enable or disable, not %q", ntp)
			}
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			needCur := (fl.Changed("search") && !fl.Changed("nameserver")) || (fl.Changed("nameserver") && !fl.Changed("search")) ||
				(fl.Changed("ntp-server") != fl.Changed("ntp"))
			var cur api.HostIdentity
			if needCur {
				if cur, err = c.HostSystem().Identity().Get(ctx); err != nil {
					return err
				}
			}
			if fl.Changed("nameserver") || fl.Changed("search") {
				r := api.HostResolvers{Nameservers: ns, Search: search}
				if !fl.Changed("nameserver") && cur.Spec.Resolvers != nil {
					r.Nameservers = cur.Spec.Resolvers.Nameservers
				}
				if !fl.Changed("search") && cur.Spec.Resolvers != nil {
					r.Search = cur.Spec.Resolvers.Search
				}
				spec.Resolvers = &r
			}
			if fl.Changed("ntp-server") || fl.Changed("ntp") {
				n := api.HostNTP{Servers: ntpServers, Enable: ntp == "enable"}
				if !fl.Changed("ntp-server") && cur.Spec.NTP != nil {
					n.Servers = cur.Spec.NTP.Servers
				}
				if !fl.Changed("ntp") && cur.Spec.NTP != nil {
					n.Enable = cur.Spec.NTP.Enable
				}
				if n.Servers == nil {
					n.Servers = []string{}
				}
				spec.NTP = &n
			}
			if err := spec.Validate(); err != nil {
				return err
			}
			ch, err := c.HostSystem().Identity().Apply(ctx, spec, a.dryRun)
			if err != nil {
				return err
			}
			return a.printHostChange("host identity", ch)
		},
	}
	f := set.Flags()
	f.StringVar(&hostname, "hostname", "", "host name: one label or a fully qualified name")
	f.StringArrayVar(&ns, "nameserver", nil, "resolver address, IPv4 or IPv6 (repeatable, at most 3; replaces the list)")
	f.StringArrayVar(&search, "search", nil, "search domain (repeatable, at most 6; replaces the list)")
	f.StringArrayVar(&ntpServers, "ntp-server", nil, "NTP server, a host name or an address (repeatable, at most 4; replaces the list)")
	f.StringVar(&ntp, "ntp", "", "enable or disable ntpd")
	enumFlag(set, "ntp", "enable", "disable")
	ic.AddCommand(set)
	return ic
}

func (a *app) completeHostSnapshots() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) > 0 {
			return nil, nil
		}
		snaps, err := c.HostSystem().Snapshots(ctx)
		names := []string{api.HostSnapshotLatest}
		for _, s := range snaps {
			names = append(names, s.Name)
		}
		return names, err
	})
}

func (a *app) hostSnapshotsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "snapshots",
		Short: "List the copies of host files kept before each change",
		Long: `List the snapshots, newest first: the copies of the host files a change touched,
taken just before it (reason apply), or before a restore (reason restore). The
last 20 are kept, in a directory of the privileged helper the daemon cannot write.`,
		Example: "jailops host snapshots\njailops host snapshots -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			snaps, err := c.HostSystem().Snapshots(cmd.Context())
			if err != nil {
				return err
			}
			return a.emit(nonNil(snaps), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, s := range snaps {
					rows = append(rows, []string{s.Name, s.Module, dash(s.Reason), strings.Join(s.Files, " "), age(a.env.Now(), s.Time)})
				}
				return []string{"NAME", "MODULE", "REASON", "FILES", "AGE"}, rows
			}, func() []string {
				var n []string
				for _, s := range snaps {
					n = append(n, s.Name)
				}
				return n
			})
		},
	}
}

func (a *app) hostRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore [SNAPSHOT]",
		Short: "Put the host files of a snapshot back",
		Long: `Put the files of a snapshot back as they were, byte for byte (default: the
latest), set the host name it recorded and restart or stop ntpd to match. Any
other change made to those files since is undone too; --dry-run shows the diff
first. The restore keeps a copy of what it replaces, so it can be undone with
another restore. It needs the admin role.`,
		Example:           "jailops host restore --dry-run\njailops host restore 20261030T101500Z\njailops host restore latest -y",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: a.completeHostSnapshots(),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := api.HostSnapshotLatest
			if len(args) == 1 {
				name = args[0]
			}
			if err := api.ValidHostSnapshotName(name); err != nil {
				return err
			}
			if !a.dryRun {
				if err := a.confirm(fmt.Sprintf("Put the host files of snapshot %s back?", name)); err != nil {
					return err
				}
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			ch, err := c.HostSystem().Restore(cmd.Context(), name, a.dryRun)
			if err != nil {
				return err
			}
			return a.printHostChange("host restore", ch)
		},
	}
}
