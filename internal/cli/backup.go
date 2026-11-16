package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func targetDesc() *kindDesc[api.BackupTarget] {
	d := newDesc("backup target", "backup targets", api.KindBackupTarget,
		func(p *api.BackupTarget) *api.ObjectMeta { return &p.Metadata },
		func(p *api.BackupTarget) *api.BackupTargetSpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.BackupTarget] { return c.Backups().Targets() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.BackupTarget] { return c.Backups().Targets() })
	d.renameLong = renameLong("backup target", `the targets lists of the backup policies that name it. The backups that were made keep the name in their records`)
	d.head = []string{"NAME", "KIND", "ADDRESS", "PATH", "PINNED"}
	d.row = func(_ time.Time, t api.BackupTarget) []string {
		pinned := "no"
		if t.Spec.Fingerprint != "" {
			pinned = "yes"
		}
		return []string{t.Metadata.Name, t.Spec.Kind, dash(t.Spec.Address), dash(t.Spec.Path), pinned}
	}
	return &d
}

func backupPolicyDesc() *kindDesc[api.BackupPolicy] {
	d := newDesc("backup policy", "backup policies", api.KindBackupPolicy,
		func(p *api.BackupPolicy) *api.ObjectMeta { return &p.Metadata },
		func(p *api.BackupPolicy) *api.BackupPolicySpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.BackupPolicy] { return c.Backups().Policies() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.BackupPolicy] { return c.Backups().Policies() })
	d.renameLong = renameLong("backup policy", `nothing else names it. Its schedule starts again under the new name, and the backups that were made keep the old name in their records`)
	d.head = []string{"NAME", "SELECTOR", "TARGETS", "SCHEDULE", "KEEP"}
	d.row = func(_ time.Time, p api.BackupPolicy) []string {
		var sel []string
		for _, k := range sortedKeys(p.Spec.Selector) {
			sel = append(sel, k+"="+p.Spec.Selector[k])
		}
		r := p.Spec.Retention
		var keep []string
		for _, kv := range []struct {
			n string
			v int
		}{{"last", r.Last}, {"hourly", r.Hourly}, {"daily", r.Daily}, {"weekly", r.Weekly}, {"monthly", r.Monthly}, {"yearly", r.Yearly}} {
			if kv.v > 0 {
				keep = append(keep, fmt.Sprintf("%s=%d", kv.n, kv.v))
			}
		}
		return []string{p.Metadata.Name, joinOrDash(sel), joinOrDash(p.Spec.Targets), p.Spec.Schedule, joinOrDash(keep)}
	}
	return &d
}

func (a *app) backupCmd() *cobra.Command {
	bc := group("backup", "Manage backup targets, policies and backups",
		`Backups are encrypted on the host before they leave it. A target is where they
go, a policy says which jails, when and how long to keep them, and a backup is
one committed snapshot in a repository.

Restoring always starts with a preflight that lists what is missing and what
would change; nothing is touched until you confirm.`,
		`jailops backup target create nightly-node --kind node --url https://backup.example.net:39110 --fingerprint ab12...
jailops backup policy create nightly --selector env=prod --target nightly-node --schedule "0 2 * * *" --keep-daily 14
jailops backup list --jail web
jailops backup restore 20260101020000-ab12cd34 --as web-restored`, "backups")
	td := targetDesc()
	tc := group("target", "Manage backup targets", "A target is a backup node or a directory that receives encrypted backups.",
		"jailops backup target list\njailops backup target show nightly-node")
	crudCommands(a, tc, td, "Create a backup target: a backup node reached over HTTPS (pinned by fingerprint) or a local directory.",
		`jailops backup target create nightly-node --kind node --url https://backup.example.net:39110 --fingerprint ab12...
jailops backup target create usb --kind directory --path /mnt/backup`,
		func(cmd *cobra.Command) func(string) (api.BackupTarget, error) {
			var kind, addr, fp, path, comment string
			f := cmd.Flags()
			f.StringVar(&comment, "comment", "", "what the target is for")
			f.StringVar(&kind, "kind", "node", "target kind: node or directory")
			f.StringVar(&addr, "url", "", "node address, https://host:port")
			f.StringVar(&fp, "fingerprint", "", "SHA-256 fingerprint pinning the node's certificate")
			f.StringVar(&path, "path", "", "directory path (kind directory)")
			enumFlag(cmd, "kind", "node", "directory")
			return func(name string) (api.BackupTarget, error) {
				return api.BackupTarget{Metadata: api.ObjectMeta{Name: name}, Spec: api.BackupTargetSpec{Comment: comment, Kind: kind, Address: addr, Fingerprint: fp, Path: path}}, nil
			}
		})
	pd := backupPolicyDesc()
	pc := group("policy", "Manage backup policies", "A policy selects jails by label and says when to back them up and how long to keep the backups. It also backs up the volumes those jails attach, and the volumes whose own labels match, each volume once however many jails attach it; --no-volumes leaves them out.",
		"jailops backup policy list\njailops backup policy show nightly", "policies")
	crudCommands(a, pc, pd, "Create a backup policy. The selector matches jails by label; an empty selector matches none.",
		`jailops backup policy create nightly --selector env=prod --target nightly-node --schedule "0 2 * * *" --keep-daily 14 --keep-weekly 8`,
		func(cmd *cobra.Command) func(string) (api.BackupPolicy, error) {
			var selector, targets []string
			var schedule, vsched, vmode string
			var last, hourly, daily, weekly, monthly, yearly, fullEvery int
			var includeState, excludeVolumes bool
			var comment string
			f := cmd.Flags()
			f.StringVar(&comment, "comment", "", "what the policy is for")
			f.StringArrayVarP(&selector, "selector", "l", nil, "label selector KEY=VALUE (repeatable)")
			f.StringArrayVar(&targets, "target", nil, "backup target name (repeatable)")
			f.StringVar(&schedule, "schedule", "", "five-field cron expression (required without -f)")
			f.IntVar(&last, "keep-last", 0, "keep the last N backups")
			f.IntVar(&hourly, "keep-hourly", 0, "keep N hourly backups")
			f.IntVar(&daily, "keep-daily", 0, "keep N daily backups")
			f.IntVar(&weekly, "keep-weekly", 0, "keep N weekly backups")
			f.IntVar(&monthly, "keep-monthly", 0, "keep N monthly backups")
			f.IntVar(&yearly, "keep-yearly", 0, "keep N yearly backups")
			f.BoolVar(&includeState, "include-state", false, "also back up the host's state dataset")
			f.BoolVar(&excludeVolumes, "no-volumes", false, "leave the volumes out (by default the volumes of the selected jails are backed up too, once each)")
			f.IntVar(&fullEvery, "full-every", 0, "force a full read every N days")
			f.StringVar(&vsched, "verify-schedule", "", "cron expression for restore tests")
			f.StringVar(&vmode, "verify-mode", "", "verification depth: deep, extract or full")
			enumFlag(cmd, "verify-mode", "deep", "extract", "full")
			a.completeFlag(cmd, "target", listNames(func(ctx context.Context, c *sdk.Client) iterNames {
				return namesOf(c.Backups().Targets().List(ctx), func(t api.BackupTarget) string { return t.Metadata.Name })
			}))
			return func(name string) (api.BackupPolicy, error) {
				if (schedule == "" || len(targets) == 0) && !a.partial {
					return api.BackupPolicy{}, usagef("--schedule and at least one --target are required (or use -f FILE)")
				}
				sel := map[string]string{}
				for _, s := range selector {
					k, v, ok := strings.Cut(s, "=")
					if !ok || k == "" {
						return api.BackupPolicy{}, usagef("selector %q must be KEY=VALUE", s)
					}
					sel[k] = v
				}
				return api.BackupPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.BackupPolicySpec{
					Comment:  comment,
					Selector: sel, Targets: targets, Schedule: schedule,
					Retention:    api.RetentionPolicy{Last: last, Hourly: hourly, Daily: daily, Weekly: weekly, Monthly: monthly, Yearly: yearly},
					IncludeState: includeState, ExcludeVolumes: excludeVolumes, FullEvery: fullEvery, VerifySchedule: vsched, VerifyMode: vmode,
				}}, nil
			}
		})
	bc.AddCommand(a.backupKeyCmd(), tc, pc, a.backupList(), a.backupShow(), a.backupRun(), a.backupRestore(), a.backupVerify(), a.backupDelete())
	return bc
}

func (a *app) completeBackups() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		items, err := collect(c.Backups().List(ctx))
		var n []string
		for _, b := range items {
			n = append(n, b.Metadata.Name)
		}
		return n, err
	})
}

// backupKind is "volume" for a volume backup and "jail" for a jail backup.
func backupKind(b api.Backup) string {
	if b.Spec.Kind == "volume" {
		return "volume"
	}
	return "jail"
}

func verifiedText(b api.Backup) string {
	switch {
	case b.Status.Failed:
		return "failed"
	case b.Status.Verified:
		return "yes"
	}
	return "no"
}

func (a *app) backupList() *cobra.Command {
	var jail, volume, target string
	var labels []string
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List backups",
		Long:    "List the backups the server knows, newest last, optionally of one jail, one volume or one target. A volume is a backup of its own, so the KIND column tells a jail backup from a volume backup.",
		Example: "jailops backup list\njailops backup list --jail web -o json\njailops backup list --volume mail",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			opts, err := labelOpts(labels)
			if err != nil {
				return err
			}
			all, err := collect(c.Backups().List(cmd.Context(), opts...))
			if err != nil {
				return err
			}
			items := all[:0]
			for _, b := range all {
				if (jail == "" || (b.Spec.Kind != "volume" && b.Spec.Jail == jail)) && (volume == "" || (b.Spec.Kind == "volume" && b.Spec.Jail == volume)) &&
					(target == "" || b.Spec.Target == target) {
					items = append(items, b)
				}
			}
			return a.emit(nonNil(items), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, b := range items {
					rows = append(rows, []string{b.Metadata.Name, backupKind(b), b.Spec.Jail, dash(b.Spec.Target), humanBytes(b.Status.Bytes),
						humanBytes(b.Status.NewBytes), verifiedText(b), age(a.env.Now(), b.Metadata.CreatedAt)})
				}
				return []string{"BACKUP", "KIND", "NAME", "TARGET", "SIZE", "NEW", "VERIFIED", "AGE"}, rows
			}, func() []string {
				var n []string
				for _, b := range items {
					n = append(n, b.Metadata.Name)
				}
				return n
			})
		},
	}
	cmd.Flags().StringVar(&jail, "jail", "", "only backups of this jail")
	cmd.Flags().StringVar(&volume, "volume", "", "only backups of this volume")
	cmd.Flags().StringVar(&target, "target", "", "only backups stored on this target")
	a.completeFlag(cmd, "target", listNames(func(ctx context.Context, c *sdk.Client) iterNames {
		return namesOf(c.Backups().Targets().List(ctx), func(t api.BackupTarget) string { return t.Metadata.Name })
	}))
	cmd.Flags().StringArrayVarP(&labels, "label", "l", nil, "only objects with this label, key=value (repeatable)")
	return cmd
}

func (a *app) backupShow() *cobra.Command {
	return &cobra.Command{
		Use:               "show BACKUP",
		Short:             "Show one backup",
		Long:              "Show one backup: what it holds, which key domain protects it, its size and its verification state. The restore bundle lists the closure a restore needs.",
		Example:           "jailops backup show 20260101020000-ab12cd34",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeBackups(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			b, err := c.Backups().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.emit(b, nil, nil, func() []string { return []string{b.Metadata.Name} })
		},
	}
}

func (a *app) emitRuns(runs []api.BackupRun) error {
	if err := a.emit(nonNil(runs), func(col int, v string) string {
		switch v {
		case "ok":
			return "32"
		case "FAILED":
			return "31"
		}
		return ""
	}, func() ([]string, [][]string) {
		var rows [][]string
		for _, r := range runs {
			res := "ok"
			if !r.OK {
				res = "FAILED"
			}
			detail := dash(r.Error)
			if len(r.Problems) > 0 {
				detail = strings.Join(r.Problems, "; ")
			}
			rows = append(rows, []string{r.Jail, dash(r.Target), dash(r.Kind), res, dash(r.Snapshot), humanBytes(r.Bytes), humanBytes(r.NewBytes), detail})
		}
		return []string{"JAIL", "TARGET", "KIND", "RESULT", "SNAPSHOT", "SIZE", "NEW", "DETAIL"}, rows
	}, func() []string {
		var n []string
		for _, r := range runs {
			n = append(n, r.ID)
		}
		return n
	}); err != nil {
		return err
	}
	bad := 0
	for _, r := range runs {
		if !r.OK {
			bad++
		}
	}
	if bad > 0 {
		return &hintError{err: fmt.Errorf("%d of %d runs failed", bad, len(runs)), hint: "'jailops explain CODE' explains the error codes; the detail column says what went wrong"}
	}
	return nil
}

func (a *app) backupRun() *cobra.Command {
	var noVolumes bool
	cmd := &cobra.Command{
		Use:   "run POLICY",
		Short: "Run a backup policy now",
		Long: `Run a backup policy immediately, outside its schedule, for every jail it
selects and for the volumes those jails attach (each volume once, however many
jails attach it), and wait for it to finish. --no-volumes leaves the volumes out
of this run. The result has one line per jail, volume and target; the exit status
is 1 when a run failed. Needs the admin role and a server with a backup backend
(extension backup_run).`,
		Example: "jailops backup run nightly\njailops backup run nightly --no-volumes\njailops backup run nightly --no-wait",
		Args:    cobra.ExactArgs(1),
		ValidArgsFunction: a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
			items, err := collect(c.Backups().Policies().List(ctx))
			var n []string
			for _, p := range items {
				n = append(n, p.Metadata.Name)
			}
			return n, err
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("run backup policy "+args[0], nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Backups().RunWith(cmd.Context(), api.BackupRunRequest{Policy: args[0], NoVolumes: noVolumes}))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "policy", args[0], "started", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			runs, _ := v.([]api.BackupRun)
			return a.emitRuns(runs)
		},
	}
	cmd.Flags().BoolVar(&noVolumes, "no-volumes", false, "leave the volumes out of this run")
	return cmd
}

func (a *app) backupVerify() *cobra.Command {
	var depth string
	cmd := &cobra.Command{
		Use:   "verify BACKUP",
		Short: "Verify a backup by reading it back",
		Long: `Check that a backup can be read back and is intact. --depth chooses how far:
deep (default) reads and checks every chunk, extract restores into a scratch
directory, full restores and starts the jail isolated. It needs the key on the
host that runs the check. The exit status is 1 when the check found problems.`,
		Example:           "jailops backup verify 20260101020000-ab12cd34\njailops backup verify 20260101020000-ab12cd34 --depth extract",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeBackups(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("verify backup "+args[0], map[string]string{"depth": depth}); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Backups().VerifyDepth(cmd.Context(), args[0], depth))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "backup", args[0], "verifying", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			run, _ := v.(api.BackupRun)
			return a.emitRuns([]api.BackupRun{run})
		},
	}
	cmd.Flags().StringVar(&depth, "depth", "", "deep (default), extract or full")
	enumFlag(cmd, "depth", "deep", "extract", "full")
	return cmd
}

func (a *app) backupKeyCmd() *cobra.Command {
	kc := group("key", "Create, inspect and escrow the backup key",
		`Backups are encrypted on the host with a backup key that never leaves it
unprotected. The recovery key printed when the key is created is the only way
to restore on another machine if the host is lost; it is shown once, JailOps
keeps it nowhere, and nothing can show it again. Escrow wraps the key to
one or more age recipients and uploads it to the backup node, so that a
holder of a matching identity can recover it. Raw backups are refused while
the key is not escrowed (key_not_escrowed).`,
		"jailops backup key status\njailops backup key create --recipient age1qq...\njailops backup key escrow --recipient age1qq...")
	status := &cobra.Command{
		Use:     "status",
		Short:   "Show whether this host has a backup key and whether it is escrowed",
		Long:    "Show the state of the backup key: none, present (not escrowed) or escrowed, with its non-secret key domain id.",
		Example: "jailops backup key status\njailops backup key status -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			st, err := c.Backups().KeyStatus(cmd.Context())
			if err != nil {
				return err
			}
			return a.emit(st, nil, func() ([]string, [][]string) {
				return []string{"STATUS", "DOMAIN", "PATH"}, [][]string{{st.Status, dash(st.Domain), dash(st.Path)}}
			}, func() []string { return []string{st.Status} })
		},
	}
	var recips []string
	create := &cobra.Command{
		Use:   "create [--recipient age1...]",
		Short: "Create the backup key of this host",
		Long: `Create the backup key. The recovery key is printed ONCE on standard output,
alone, and a warning on standard error; it is not stored anywhere by JailOps or
by this command. Write it down or put it in a password manager now.
With --recipient (repeatable) the key is escrowed to those age public keys at
once; without it the daemon's configured recipients are used.`,
		Example: "jailops backup key create --recipient age1qq... --recipient age1zz...\nKEY=$(jailops backup key create 2>/dev/null)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkRecipients(recips); err != nil {
				return err
			}
			if ok, err := a.dry("create the backup key", map[string]any{"recipients": recips}); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			out, err := c.Backups().CreateKey(cmd.Context(), recips...)
			if err != nil {
				return err
			}
			fprintln(a.env.Stderr, "warning: the recovery key is shown only once and is stored nowhere; write it down now.")
			if !out.Escrowed {
				fprintf(a.env.Stderr, "warning: the key was created but not escrowed (%s); retry with 'jailops backup key escrow'\n", dash(out.EscrowError))
			}
			if a.format == fmtTable {
				fprintln(a.env.Stdout, out.RecoveryKey)
				return nil
			}
			return a.emit(out, nil, nil, func() []string { return []string{out.Domain} })
		},
	}
	create.Flags().StringArrayVar(&recips, "recipient", nil, "age public key to escrow to (repeatable)")
	var erecips []string
	escrow := &cobra.Command{
		Use:   "escrow --recipient age1...",
		Short: "Wrap the backup key to recovery recipients and upload it",
		Long: `Wrap the backup key to age recipients and upload it to the backup node, so a
holder of a matching identity can recover it. Use it to escrow a key that was
created without recipients, to add recipients, or to retry a failed escrow.`,
		Example: "jailops backup key escrow --recipient age1qq... --recipient age1zz...",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkRecipients(erecips); err != nil {
				return err
			}
			if ok, err := a.dry("escrow the backup key", map[string]any{"recipients": erecips}); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			st, err := c.Backups().EscrowKey(cmd.Context(), erecips...)
			if err != nil {
				return err
			}
			return a.emit(st, nil, func() ([]string, [][]string) {
				return []string{"STATUS", "DOMAIN", "PATH"}, [][]string{{st.Status, dash(st.Domain), dash(st.Path)}}
			}, func() []string { return []string{st.Status} })
		},
	}
	escrow.Flags().StringArrayVar(&erecips, "recipient", nil, "age public key to escrow to (repeatable)")
	kc.AddCommand(status, create, escrow)
	return kc
}

func checkRecipients(r []string) error {
	for _, k := range r {
		if !strings.HasPrefix(k, "age1") || len(k) < 20 {
			return usagef("recipient %q is not an age public key (it starts with age1)", k)
		}
	}
	return nil
}

func (a *app) backupDelete() *cobra.Command {
	return &cobra.Command{
		Use:     "delete BACKUP...",
		Aliases: []string{"rm"},
		Short:   "Request deletion of backups",
		Long: `Request deletion of backups. Deleting needs the backup-admin role, and the backup
node may delay it on purpose. The command asks for confirmation unless -y is given.`,
		Example:           "jailops backup delete 20260101020000-ab12cd34",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: a.completeBackups(),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, id := range args {
				if ok, err := a.dry("delete backup "+id, nil); ok || err != nil {
					if err != nil {
						return err
					}
					continue
				}
				if err := a.confirm(fmt.Sprintf("Delete backup %q?", id)); err != nil {
					return err
				}
				c, err := a.connect(cmd.Context())
				if err != nil {
					return err
				}
				h, err := handle(c.Backups().Delete(cmd.Context(), id))
				if err != nil {
					return err
				}
				if err := a.finishOp(cmd.Context(), h, "backup", id, "deleted", nil); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (a *app) backupRestore() *cobra.Command {
	var as, toHost string
	var replace, keepIP, confirmLoss, noVolumes bool
	var maps []string
	cmd := &cobra.Command{
		Use:   "restore BACKUP",
		Short: "Restore a backup as a jail or a volume",
		Long: `Restore a backup as a jail, or, for a volume backup, as a new volume of the
project (a volume is never replaced: give another name with --as). The command
first asks the server for a preflight:
what is missing (image generations, networks, policies), what would be created
or changed, and what conflicts. The report is always shown. A restore whose
preflight fails is not started.

With --dry-run the command stops after the preflight. Otherwise you must
confirm; -y answers yes. Restoring over an existing jail (--replace) destroys
it, so you must type its name or pass --confirm-data-loss.

With --project the jail is restored into that project (the caller needs access
to it; its grants and quotas apply); otherwise into the project of the backup.
On a hub, --to-host names the host to restore on (its name or UUID); without it
the restore goes to the host the request is scoped to (--host), else this host.

By default the restored jail gets a new UUID and fresh addresses; --keep-ip
keeps the fixed addresses of the backup, and --map moves its networks.

The volumes the jail attaches that the project lacks are restored first, each
from its newest backup, so the jail finds its data. --no-volumes restores the
jail with no volume attachments at all (every one is left out; attach the volumes
afterwards). An encrypted volume is restored on its own, before the jail, because
it needs its passphrase (--passphrase-file reads it from a file; otherwise it is
asked for twice).`,
		Example: `jailops backup restore 20260101020000-ab12cd34 --dry-run
jailops backup restore 20260101020000-ab12cd34 --as web-restored
jailops backup restore 20260101020000-ab12cd34 --map lan=dmz --keep-ip
jailops backup restore 20260101020000-ab12cd34 --replace
jailops backup restore 20260101020000-ef56ab12 --as mail-restored
jailops --remote hub backup restore 20260101020000-ab12cd34 --to-host host-b`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeBackups(),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			req := api.RestoreRequest{Backup: args[0], As: as, Replace: replace, KeepIP: keepIP, NoVolumes: noVolumes, Project: a.project}
			if toHost != "" {
				if req.Host, err = a.hostUUID(ctx, c, toHost); err != nil {
					return err
				}
			}
			if len(maps) > 0 {
				req.NetworkMap = map[string]string{}
				for _, m := range maps {
					from, to, ok := strings.Cut(m, "=")
					if !ok || from == "" || to == "" {
						return usagef("--map %q must be OLD=NEW", m)
					}
					req.NetworkMap[from] = to
				}
			}
			bk, err := c.Backups().Get(ctx, args[0])
			if err != nil {
				return err
			}
			name := as
			if name == "" {
				name = bk.Spec.Jail
			}
			isVolume := bk.Spec.Kind == "volume"
			if isVolume && bk.Spec.Volume != nil && bk.Spec.Volume.Encrypted && !a.dryRun {
				// the passphrase makes the volume again; it is used once and never stored
				if req.Passphrase, err = a.newPassphrase(a.passFile, "Passphrase for the restored volume: "); err != nil {
					return err
				}
			}
			pf, err := c.Backups().Preflight(ctx, withPreflightPassphrase(req, isVolume, bk))
			if err != nil {
				return err
			}
			if err := a.showPreflight(bk, name, pf); err != nil {
				return err
			}
			if !pf.OK {
				e := api.Errorf(api.CodeInvalid, "the restore preflight failed; nothing was changed").
					WithHint("fix the missing items or conflicts listed above, then run the restore again")
				return e
			}
			if a.dryRun {
				return nil
			}
			if isVolume {
				if err := a.confirm(fmt.Sprintf("Restore backup %s as volume %q?", args[0], name)); err != nil {
					return err
				}
				h, err := handle(c.Backups().RestoreVolume(ctx, req))
				if err != nil {
					return err
				}
				return a.finishOp(ctx, h, "volume", name, "restored", nil)
			}
			if replace {
				warn := fmt.Sprintf("--replace destroys the existing jail %q and everything in it.", name)
				if err := a.confirmTyped(warn, name, confirmLoss, "--confirm-data-loss"); err != nil {
					return err
				}
			} else if err := a.confirm(fmt.Sprintf("Restore backup %s as jail %q?", args[0], name)); err != nil {
				return err
			}
			h, err := handle(c.Backups().Restore(ctx, req))
			if err != nil {
				return err
			}
			return a.finishOp(ctx, h, "jail", name, "restored", nil)
		},
	}
	f := cmd.Flags()
	f.StringVar(&as, "as", "", "restore under this jail name")
	f.StringVar(&toHost, "to-host", "", "host to restore on, by name or UUID (default: the host of the request)")
	_ = cmd.RegisterFlagCompletionFunc("to-host", a.completeHosts())
	f.BoolVar(&replace, "replace", false, "replace an existing jail of that name")
	f.BoolVar(&keepIP, "keep-ip", false, "keep the fixed addresses of the backup")
	f.StringArrayVar(&maps, "map", nil, "map a network of the backup to a local one, OLD=NEW (repeatable)")
	f.BoolVar(&confirmLoss, "confirm-data-loss", false, "confirm that --replace may destroy the existing jail")
	f.BoolVar(&noVolumes, "no-volumes", false, "restore the jail with no volume attachments (attach them afterwards)")
	f.StringVar(&a.passFile, "passphrase-file", "", "read the passphrase of a restored encrypted volume from this file (its first line) instead of asking")
	return cmd
}

// withPreflightPassphrase gives a preflight of an encrypted volume a stand-in passphrase when none was asked for (a
// dry run): the preflight only checks that one is given, and the server never stores it.
func withPreflightPassphrase(req api.RestoreRequest, isVolume bool, b api.Backup) api.RestoreRequest {
	if isVolume && b.Spec.Volume != nil && b.Spec.Volume.Encrypted && req.Passphrase == "" {
		req.Passphrase = "dry-run"
	}
	return req
}

func (a *app) showPreflight(b api.Backup, name string, pf api.RestorePreflight) error {
	if a.format == fmtJSON || a.format == fmtYAML {
		if a.dryRun {
			return a.emit(pf, nil, nil, nil)
		}
		return nil
	}
	w := a.env.Stdout
	fprintf(w, "Preflight: restore backup %s (%s %s) as %s\n", b.Metadata.Name, backupKind(b), b.Spec.Jail, name)
	show := func(title, mark string, items []string) {
		if len(items) == 0 {
			return
		}
		fprintf(w, "%s\n", title)
		for _, i := range items {
			fprintf(w, "  %s %s\n", mark, i)
		}
	}
	show("Changes:", "+", pf.Changes)
	show("Missing:", "!", pf.Missing)
	show("Errors:", "x", pf.Errors)
	if pf.OK {
		fprintln(w, "Result: ok")
	} else {
		fprintln(w, "Result: failed")
	}
	return nil
}
