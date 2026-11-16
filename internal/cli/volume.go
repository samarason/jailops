package cli

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func volumeDesc() *kindDesc[api.Volume] {
	d := newDesc("volume", "volumes", api.KindVolume,
		func(v *api.Volume) *api.ObjectMeta { return &v.Metadata },
		func(v *api.Volume) *api.VolumeSpec { return &v.Spec })
	d.list = func(ctx context.Context, c *sdk.Client, o ...sdk.ListOption) iter.Seq2[api.Volume, error] {
		return c.Volumes().List(ctx, o...)
	}
	d.get = func(ctx context.Context, c *sdk.Client, n string) (api.Volume, string, error) {
		return c.Volumes().GetETag(ctx, n)
	}
	d.update = func(ctx context.Context, c *sdk.Client, n string, v api.Volume, etag string) (api.Volume, error) {
		return c.Volumes().Update(ctx, n, v, etag)
	}
	d.del = func(ctx context.Context, c *sdk.Client, n string) (opHandle, error) {
		return handle(c.Volumes().Delete(ctx, n))
	}
	d.rename = func(ctx context.Context, c *sdk.Client, n string, req api.Rename, etag string) (*sdk.Operation[api.RenameResult], error) {
		return c.Volumes().Rename(ctx, n, req, etag)
	}
	d.renameLong = renameLong("volume", `its dataset and mount point, the attachments of the jails (they must be stopped) and the disk keys of the profiles of the project that name it`)
	d.head = []string{"NAME", "STORAGE", "USED", "SIZE", "OWNER", "MODE", "ATTACHED TO", "COMMENT"}
	d.row = func(_ time.Time, v api.Volume) []string {
		if v.Spec.IsHostDir() {
			// a directory of the host: its path stands where the storage does, and nothing of a dataset applies
			return []string{v.Metadata.Name, v.Spec.Path, "-", "-", "-", "-", dash(usesCell(v.Status.AttachedTo) + lockedCell(v)), dash(v.Spec.Comment)}
		}
		return []string{v.Metadata.Name, v.Spec.Storage, humanBytes(v.Status.Used), unlimitedOr(v.Spec.Size), fmt.Sprintf("%d:%d", v.Spec.UID, v.Spec.GID),
			v.Spec.Mode, dash(usesCell(v.Status.AttachedTo) + lockedCell(v)), dash(v.Spec.Comment)}
	}
	d.brief = &listView[api.Volume]{
		head: []string{"NAME", "USED", "OWNER", "MODE", "ATTACHED TO"},
		drop: []int{4, 3},
		row: func(_ time.Time, v api.Volume) []string {
			if v.Spec.IsHostDir() {
				return []string{v.Metadata.Name, "-", "-", "-", dash(usesCell(v.Status.AttachedTo) + lockedCell(v))}
			}
			return []string{v.Metadata.Name, humanBytes(v.Status.Used), fmt.Sprintf("%d:%d", v.Spec.UID, v.Spec.GID), v.Spec.Mode,
				dash(usesCell(v.Status.AttachedTo) + lockedCell(v))}
		},
	}
	d.show = func(a *app, v api.Volume) error {
		var extra []string
		for _, u := range v.Status.AttachedTo {
			mode := "read-write"
			if u.ReadOnly {
				mode = "read-only"
			}
			extra = append(extra, fmt.Sprintf("Attached:    %s at %s (%s)", u.Jail, u.Mount, mode))
		}
		if v.Spec.IsHostDir() {
			state := v.Status.State
			if v.Status.Detail != "" {
				state += " (" + v.Status.Detail + ")"
			}
			extra = append([]string{"Directory:   " + v.Spec.Path, "State:       " + state}, extra...)
		}
		for _, w := range v.Status.Warnings {
			extra = append(extra, "Warning:     "+w)
		}
		return a.showObject(v.Metadata, extra, v.Spec, v.Status)
	}
	d.warnings = func(v api.Volume) []string { return v.Status.Warnings }
	d.loss = volumeLoss
	d.emptyHint = "jailops volume create NAME --uid UID --gid GID"
	return &d
}

// usesCell lists the jails a volume is attached to, with ":ro" on the read-only ones.
func usesCell(uses []api.VolumeUse) string {
	var out []string
	for _, u := range uses {
		s := u.Jail
		if u.ReadOnly {
			s += ":ro"
		}
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

func lockedCell(v api.Volume) string {
	switch {
	case v.Status.Locked:
		return " (locked)"
	case v.Status.State == api.VolumeStateLost:
		return " (lost)"
	}
	return ""
}

// volumeLoss says what deleting a volume destroys: its files and its snapshots, as the server reports them now. A
// volume a jail attaches is refused here, before any question.
func volumeLoss(cmd *cobra.Command, ctx context.Context, c *sdk.Client, name string) (string, error) {
	v, err := c.Volumes().Get(ctx, name)
	if err != nil {
		return "", err
	}
	if len(v.Status.AttachedTo) > 0 && !cmdBool(cmd, "dry-run") {
		j := v.Status.AttachedTo[0].Jail
		return "", api.Errorf(api.CodeConflict, "volume %q is attached to jail %q", name, j).
			WithHint("detach it first: jailops volume detach " + j + " " + name)
	}
	if v.Spec.IsHostDir() {
		return fmt.Sprintf("%s: the directory %s is left as it is; only the volume is forgotten", name, v.Spec.Path), nil
	}
	parts := []string{humanBytes(v.Status.Used) + " of files"}
	if snaps, err := collect(c.Volumes().Snapshots(name).List(ctx)); err != nil {
		parts = append(parts, "snapshots unknown")
	} else {
		parts = append(parts, count(len(snaps), "snapshot", "snapshots"))
	}
	line := fmt.Sprintf("%s: %s", name, strings.Join(parts, ", "))
	if len(v.Status.AttachedTo) > 0 {
		line += "; attached to " + usesCell(v.Status.AttachedTo) + ", the delete needs it detached"
	}
	return line, nil
}

func cmdBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

// completeVolumes completes the name of a volume of the project.
func (a *app) completeVolumes() completer {
	return completeKind(a, volumeDesc())
}

// completeVolumeSnapshots completes a snapshot name of the volume named first.
func (a *app) completeVolumeSnapshots() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		items, err := collect(c.Volumes().Snapshots(args[0]).List(ctx))
		var n []string
		for _, s := range items {
			n = append(n, s.Metadata.Name)
		}
		return n, err
	})
}

// completeJailsThenVolumes completes a jail, then a volume of the project.
func (a *app) completeJailsThenVolumes() completer {
	return completeArgs(completeKind(a, a.jailDesc()), a.completeVolumes(), completeNone)
}

// completeAttached completes the volumes the jail named first attaches.
func (a *app) completeAttached() completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		vs, err := c.Jails().Volumes(ctx, args[0])
		var n []string
		for _, v := range vs {
			n = append(n, v.Name)
		}
		return n, err
	})
}

const volumeCreateLong = `Create a volume: a dataset of the project that jails attach by name. The volume
outlives the jails: deleting a jail never deletes a volume, and the same volume
can be attached to several jails. Attach it with 'jailops volume attach JAIL
VOLUME PATH'.

--uid, --gid and --mode are the owner and the mode of the root of the volume,
set once when it is made. FreeBSD has no uid mapping, so a user with the same
number in two jails (a mail server and a desktop, say) reads and writes the same
files. Without them the root is owned by root:wheel with mode 0755.

--size is a ZFS quota of the volume. --storage defaults to the only storage of the
project. An encrypted volume (--encrypted) is a ZFS encryption root with a
passphrase you type twice (scripts give --passphrase-file); it is attached to one
jail only, and that jail does not start while the volume is locked.

--path makes the volume a directory of the host instead of a dataset: a mount
such as a storage box, a share or a disk of its own, below a directory the host
operator allows with admin-host-mount in priv.conf. Only a global administrator
makes one and attaches it. The files are the host's: no snapshots, no size, no
encryption, no backup by JailOps. A jail does not start while the directory is not
on its mount (a lost mount leaves an empty directory that the jail would take for
its data). With --watch the daemon looks at the mount every few seconds, shows
the state (ok or lost), and sends an event when it changes; --probe write also
checks that a file can be made; --on-loss stop stops the running jails that attach
the volume when the mount is lost, and when the mount is back the jails that kept
running get their mount again.`

const volumeCreateExample = `jailops volume create maildir --uid 5000 --gid 5000 --mode 0770 --comment "the mail of every user"
jailops volume create db-data --size 50G --uid 770 --gid 770
jailops volume create vault --encrypted
jailops volume create backups --path /mnt/storagebox/backups --watch --probe write --on-loss stop
jailops volume create -f maildir.yaml`

func (a *app) volumeFlagBuild(cmd *cobra.Command) func(string) (api.Volume, error) {
	var storage, size, mode, comment, path, probe, onLoss string
	var uid, gid int
	var encrypted, watch bool
	var labels []string
	f := cmd.Flags()
	f.StringVar(&storage, "storage", "", "storage to place the volume on, one granted to the project (default: the project's only storage)")
	f.StringVar(&size, "size", "", "ZFS quota of the volume, for example 50G (default: none)")
	f.IntVar(&uid, "uid", 0, "owner of the root of the volume, a number (default 0)")
	f.IntVar(&gid, "gid", 0, "group of the root of the volume, a number (default 0)")
	f.StringVar(&mode, "mode", "", "mode of the root of the volume, octal up to 0777 (default 0755)")
	f.BoolVar(&encrypted, "encrypted", false, "encrypt the volume with ZFS (aes-256-gcm) under a passphrase you type twice")
	f.StringVar(&a.passFile, "passphrase-file", "", "read the passphrase of an encrypted volume from this file (its first line) instead of asking")
	f.StringVar(&path, "path", "", "make the volume a directory of the host, on a mount below an admin-host-mount directory (global administrator)")
	f.BoolVar(&watch, "watch", false, "with --path: check every few seconds that the directory is still on its mount, and say when it is not")
	f.StringVar(&probe, "probe", "", "with --watch: what to check, mounted (default) or write (also that a file can be made)")
	f.StringVar(&onLoss, "on-loss", "", "with --watch: what happens to the running jails when the mount is lost, none (default) or stop")
	enumFlag(cmd, "probe", api.VolumeProbeMounted, api.VolumeProbeWrite)
	enumFlag(cmd, "on-loss", api.VolumeOnLossNone, api.VolumeOnLossStop)
	f.StringVar(&comment, "comment", "", "what the volume is for")
	f.StringArrayVar(&labels, "label", nil, "label KEY=VALUE (repeatable)")
	a.completeFlag(cmd, "storage", listNames(func(ctx context.Context, c *sdk.Client) iterNames { return namesOf(c.Storage().List(ctx), storName) }))
	return func(name string) (api.Volume, error) {
		v := sdk.NewVolume(name, api.VolumeSpec{Storage: storage, Size: size, UID: uid, GID: gid, Mode: mode, Encrypted: encrypted, Comment: comment,
			Path: path, Watch: watch, Probe: probe, OnLoss: onLoss})
		if len(labels) > 0 {
			v.Metadata.Labels = map[string]string{}
			for _, l := range labels {
				k, val, ok := strings.Cut(l, "=")
				if !ok || k == "" {
					return v, usagef("label %q must be KEY=VALUE", l)
				}
				v.Metadata.Labels[k] = val
			}
		}
		return v, nil
	}
}

func (a *app) volumeCmd() *cobra.Command {
	d := volumeDesc()
	d.create = func(ctx context.Context, c *sdk.Client, v api.Volume) (opHandle, api.Volume, error) {
		pass := ""
		switch {
		case v.Spec.Encrypted:
			var err error
			if pass, err = a.newVolumePassphrase(); err != nil {
				return nil, api.Volume{}, err
			}
		case a.passFile != "":
			return nil, api.Volume{}, usagef("--passphrase-file is given but the volume is not encrypted (--encrypted)")
		}
		h, err := handle(c.Volumes().Create(ctx, v, pass))
		return h, api.Volume{}, err
	}
	vc := group("volume", "Create volumes and attach them to jails",
		`A volume is a dataset of a project that jails attach by name, at a path of their
own. It outlives the jails: a jail's deletion detaches its volumes and never deletes
one, a copy of a jail attaches none, and a jail snapshot or rollback leaves volumes
alone (a volume has snapshots of its own). The same volume can be attached to several
jails; one that is writable in more than one says so.

The root of a volume has the owner and the mode it was made with, so a user of the
same number in two jails reads and writes the same files.`,
		`jailops volume create maildir --uid 5000 --gid 5000 --mode 0770
jailops volume attach mail maildir /var/mail/vhosts
jailops volume attach desktop maildir /home/ann/Mail
jailops volume list`, "volumes", "vol")
	crudCommands(a, vc, d, volumeCreateLong, volumeCreateExample, a.volumeFlagBuild)
	vc.AddCommand(a.volumeAttach(), a.volumeDetach(), a.volumeSnapshotCmd(d), a.volumeUnlock(d), a.volumeLock(d), a.volumePassphrase(d))
	return vc
}

func (a *app) volumeAttach() *cobra.Command {
	var ro, copyExisting bool
	cmd := &cobra.Command{
		Use:   "attach JAIL VOLUME PATH",
		Short: "Attach a volume to a stopped jail",
		Long: `Attach a volume of the project to a stopped jail: the jail sees it at PATH, through
a nullfs mount from the volume's place on the host, from its next start on. A jail
that runs is refused; the attachment is part of the jail's specification
(volumes), so it is the same as editing the jail.

With --ro the jail may read the volume and not write it. The same volume can be
attached to several jails; a volume that is writable in more than one jail is
reported, because the jails then share its files and their locking. An encrypted
volume is attached to one jail only.

What the jail has at PATH is hidden while the volume is mounted over it. With
--copy-existing the files of PATH are copied into the volume first (the volume
should be new); nothing is removed from the jail's own root.`,
		Example:           "jailops volume attach mail maildir /var/mail/vhosts\njailops volume attach desktop maildir /home/ann/Mail --ro",
		Args:              cobra.ExactArgs(3),
		ValidArgsFunction: a.completeJailsThenVolumes(),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, jail, vol, path := cmd.Context(), args[0], args[1], args[2]
			req := api.VolumeAttachRequest{Volume: vol, Mount: path, ReadOnly: ro, CopyExisting: copyExisting}
			if ok, err := a.dry("attach volume "+vol+" to jail "+jail, req); ok || err != nil {
				return err
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := handle(c.Jails().AttachVolume(ctx, jail, req))
			if err != nil {
				return err
			}
			if err := a.finishOp(ctx, h, "volume", vol, "attached to jail "+jail, nil); err != nil {
				return err
			}
			if v, err := c.Volumes().Get(ctx, vol); err == nil {
				for _, w := range v.Status.Warnings {
					fprintf(a.env.Stderr, "warning: %s\n", w)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&ro, "ro", false, "the jail may read the volume and not write it")
	cmd.Flags().BoolVar(&copyExisting, "copy-existing", false, "copy the files the jail has at PATH into the volume first")
	return cmd
}

func (a *app) volumeDetach() *cobra.Command {
	return &cobra.Command{
		Use:   "detach JAIL VOLUME",
		Short: "Detach a volume from a stopped jail",
		Long: `Detach a volume from a stopped jail. The volume and its files stay; the jail no
longer sees them. A jail that runs is refused.`,
		Example:           "jailops volume detach mail maildir",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeArgs(completeKind(a, a.jailDesc()), a.completeAttached(), completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, jail, vol := cmd.Context(), args[0], args[1]
			if ok, err := a.dry("detach volume "+vol+" from jail "+jail, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := handle(c.Jails().DetachVolume(ctx, jail, vol))
			if err != nil {
				return err
			}
			return a.finishOp(ctx, h, "volume", vol, "detached from jail "+jail, nil)
		},
	}
}

func (a *app) volumeSnapshotCmd(d *kindDesc[api.Volume]) *cobra.Command {
	sc := group("snapshot", "Create, list, delete and roll back volume snapshots",
		`A snapshot is a ZFS snapshot of one volume. It costs almost nothing until data
changes; the written column shows how much has changed since each one. A rollback
returns the volume to a snapshot and discards everything written since.`,
		`jailops volume snapshot create maildir before-migration -m "before the move"
jailops volume snapshot list maildir
jailops volume snapshot rollback maildir before-migration
jailops volume snapshot delete maildir before-migration`, "snap", "snapshots")
	volThenSnap := completeArgs(a.completeVolumes(), a.completeVolumeSnapshots())
	var comment string
	create := &cobra.Command{
		Use:               "create VOLUME [SNAPSHOT]",
		Short:             "Take a snapshot of a volume",
		Long:              "Take a snapshot of a volume. Without SNAPSHOT the server chooses a name.\nA snapshot name has at most 64 lower case letters, digits, '.', '_' and '-'; names starting with jo- are reserved.",
		Example:           "jailops volume snapshot create maildir\njailops volume snapshot create maildir before-migration -m \"before the move\"",
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeArgs(a.completeVolumes(), completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := ""
			if len(args) == 2 {
				name = args[1]
			}
			if ok, err := a.dry("snapshot volume "+args[0], map[string]string{"name": name, "comment": comment}); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Volumes().Snapshots(args[0]).Create(cmd.Context(), name, comment))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "snapshot", name, "created", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			sn, _ := v.(api.VolumeSnapshot)
			return a.emitOne(sn, "snapshot", sn.Metadata.Name, "created")
		},
	}
	create.Flags().StringVarP(&comment, "message", "m", "", "comment stored with the snapshot")
	list := &cobra.Command{
		Use:               "list VOLUME",
		Aliases:           []string{"ls"},
		Short:             "List the snapshots of a volume",
		Long:              "List the snapshots of a volume, oldest first, with the bytes written to the volume since each one.",
		Example:           "jailops volume snapshot list maildir\njailops volume snapshot list maildir -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeVolumes(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			items, err := collect(c.Volumes().Snapshots(args[0]).List(cmd.Context()))
			if err != nil {
				return err
			}
			return a.emit(nonNil(items), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, s := range items {
					rows = append(rows, []string{s.Metadata.Name, humanBytes(s.Status.Written), age(a.env.Now(), s.Metadata.CreatedAt), dash(s.Spec.Comment)})
				}
				return []string{"NAME", "WRITTEN", "AGE", "COMMENT"}, rows
			}, func() []string {
				var n []string
				for _, s := range items {
					n = append(n, s.Metadata.Name)
				}
				return n
			})
		},
	}
	del := &cobra.Command{
		Use:               "delete VOLUME SNAPSHOT...",
		Aliases:           []string{"rm"},
		Short:             "Delete snapshots of a volume",
		Long:              "Delete snapshots of a volume after confirmation (-y skips it). A rollback to a deleted snapshot is no longer possible.",
		Example:           "jailops volume snapshot delete maildir before-migration\njailops volume snapshot delete -y maildir old1 old2",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: volThenSnap,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, sn := range args[1:] {
				if ok, err := a.dry("delete snapshot "+sn+" of volume "+args[0], nil); ok || err != nil {
					if err != nil {
						return err
					}
					continue
				}
				if err := a.confirm(fmt.Sprintf("Delete snapshot %q of volume %q?", sn, args[0])); err != nil {
					return err
				}
				c, err := a.connect(cmd.Context())
				if err != nil {
					return err
				}
				h, err := handle(c.Volumes().Snapshots(args[0]).Delete(cmd.Context(), sn))
				if err != nil {
					return err
				}
				if err := a.finishOp(cmd.Context(), h, "snapshot", sn, "deleted", nil); err != nil {
					return err
				}
			}
			return nil
		},
	}
	var confirmLoss bool
	rollback := &cobra.Command{
		Use:   "rollback VOLUME SNAPSHOT",
		Short: "Return a volume to a snapshot",
		Long: `Return a volume to a snapshot. Everything written to the volume since is discarded for
good, and so are the snapshots after it. No jail that attaches the volume may run.

The command shows how many bytes were written since the snapshot, which is what
would be lost, and asks you to type the volume name. In a script, pass
--confirm-data-loss once you have decided; -y does not apply to data loss.`,
		Example:           "jailops volume snapshot rollback maildir before-migration\njailops volume snapshot rollback maildir before-migration --confirm-data-loss",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: volThenSnap,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name, snap := cmd.Context(), args[0], args[1]
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			var written int64
			items, err := collect(c.Volumes().Snapshots(name).List(ctx))
			if err != nil {
				return err
			}
			found := false
			for _, s := range items {
				if s.Metadata.Name == snap {
					found, written = true, s.Status.Written
				}
			}
			if !found {
				return api.Errorf(api.CodeNotFound, "volume %q has no snapshot %q", name, snap)
			}
			rb := api.VolumeRollback{Snapshot: snap, ConfirmDataLoss: true}
			fprintf(a.env.Stdout, "Rolling volume %s back to snapshot %s.\n%s written since then would be discarded.\n", name, snap, humanBytes(written))
			if ok, err := a.dry("roll back volume "+name, rb); ok || err != nil {
				return err
			}
			warn := fmt.Sprintf("This destroys %s of data written to volume %q since snapshot %q. It cannot be undone.", humanBytes(written), name, snap)
			if err := a.confirmTyped(warn, name, confirmLoss, "--confirm-data-loss"); err != nil {
				return err
			}
			h, err := handle(c.Volumes().Rollback(ctx, name, rb))
			if err != nil {
				return err
			}
			return a.finishOp(ctx, h, "volume", name, "rolled back", nil)
		},
	}
	rollback.Flags().BoolVar(&confirmLoss, "confirm-data-loss", false, "confirm that data written since the snapshot may be destroyed")
	sc.AddCommand(create, list, del, rollback)
	return sc
}

// unlimitedOr is the size of a volume: without one only the project's storage quota bounds it, and the list says so.
func unlimitedOr(size string) string {
	if size == "" {
		return "unlimited"
	}
	return size
}
