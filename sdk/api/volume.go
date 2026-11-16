package api

import (
	"fmt"
	"strings"
)

// Volume is a named dataset of a project that is attached to jails. It outlives them: a jail's deletion detaches
// its volumes and never deletes one. The root of the volume has the owner and the mode it was created with, so a
// user of the same numeric id in two jails (a mail server and a desktop, say) reads and writes the same files.
type Volume struct {
	Metadata ObjectMeta   `json:"metadata"`
	Spec     VolumeSpec   `json:"spec"`
	Status   VolumeStatus `json:"status,omitempty"`
}

// VolumeSpec is what a volume is made with. Everything but Comment, Watch, Probe and OnLoss is fixed at creation.
//
// A volume with a Path is a host directory: no dataset of JailOps, but a directory of the host that is a mount (a
// storage box, an NFS or CIFS share, a disk of its own) and that jails attach like any volume. Storage, Size, UID, GID,
// Mode and Encrypted do not apply to it.
type VolumeSpec struct {
	// Storage is the storage the volume's dataset lives on; empty means the project's only storage grant.
	Storage string `json:"storage,omitempty"`
	// Size is the ZFS quota of the volume (4G, 500M); empty means none.
	Size string `json:"size,omitempty"`
	// UID, GID and Mode are the owner and the mode of the root of the volume, set once when it is made.
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Mode string `json:"mode,omitempty"` // octal, default 0755
	// Encrypted makes the volume a ZFS encryption root (aes-256-gcm) with a passphrase a person types; it can be
	// attached to one jail only, and that jail does not start while the volume is locked.
	Encrypted bool `json:"encrypted,omitempty"`
	// Path makes the volume a host directory: the directory of the host the jails see. It lies on a mount below a
	// directory the host operator allows with admin-host-mount in priv.conf. Only a global administrator makes such a
	// volume or attaches one.
	Path string `json:"path,omitempty"`
	// Watch has the daemon check, every few seconds, that the directory of a host-directory volume is still on its mount
	// (and writable with Probe "write"). The state shows in the volume and in events; OnLoss says what happens to the
	// jails when it is lost; when the mount is back the jails that kept running get their mount again.
	Watch bool `json:"watch,omitempty"`
	// Probe is what a watch checks: "mounted" (the default) that the directory is on a mount, "write" also that a file
	// can be created in it.
	Probe string `json:"probe,omitempty"`
	// OnLoss is what happens to the running jails that attach the volume when its mount is lost: "none" (the default)
	// leaves them running, "stop" stops them. A jail does not start while the mount is lost, with either.
	OnLoss string `json:"on_loss,omitempty"`
	// Comment says what the volume is for.
	Comment string `json:"comment,omitempty"`
}

// The probes of a watched host-directory volume and what happens when its mount is lost.
const (
	VolumeProbeMounted = "mounted"
	VolumeProbeWrite   = "write"
	VolumeOnLossNone   = "none"
	VolumeOnLossStop   = "stop"
)

// The states of a host-directory volume.
const (
	VolumeStateOK   = "ok"
	VolumeStateLost = "lost"
)

// IsHostDir reports whether the volume is a directory of the host and not a dataset.
func (s VolumeSpec) IsHostDir() bool { return s.Path != "" }

// VolumeStatus is what the dataset and the jails say about a volume now.
type VolumeStatus struct {
	// Dataset is the ZFS dataset of the volume and Mountpoint where the host mounts it.
	Dataset    string `json:"dataset,omitempty"`
	Mountpoint string `json:"mountpoint,omitempty"`
	// Used is the space the volume (and its snapshots) take, in bytes.
	Used int64 `json:"used"`
	// Locked is true for an encrypted volume whose key is not loaded.
	Locked bool `json:"locked,omitempty"`
	// State is "ok" or "lost" for a host-directory volume: whether its directory is on a mount now. Detail says why it
	// is lost ("the directory is not on a mount", "no file can be created in it").
	State  string `json:"state,omitempty"`
	Detail string `json:"detail,omitempty"`
	// AttachedTo lists the jails the volume is attached to.
	AttachedTo []VolumeUse `json:"attached_to,omitempty"`
	// Warnings are lines a reviewer should read, such as a volume that is writable in more than one jail.
	Warnings []string `json:"warnings,omitempty"`
}

// VolumeUse is one attachment of a volume, seen from the volume.
type VolumeUse struct {
	Jail     string `json:"jail"`
	Mount    string `json:"mount"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// VolumeSnapshot is a snapshot of a volume.
type VolumeSnapshot struct {
	Metadata ObjectMeta           `json:"metadata"`
	Spec     VolumeSnapshotSpec   `json:"spec"`
	Status   VolumeSnapshotStatus `json:"status"`
}

// VolumeSnapshotSpec names the volume and says what the snapshot is for.
type VolumeSnapshotSpec struct {
	Volume  string `json:"volume"`
	Comment string `json:"comment,omitempty"`
}

// VolumeSnapshotStatus is what the snapshot holds now.
type VolumeSnapshotStatus struct {
	// Written is the number of bytes written to the volume since the snapshot, which is what a rollback to it would
	// discard.
	Written int64 `json:"written,omitempty"`
}

// VolumeRollback is the body of POST /api/v1/volumes/{name}/rollback.
type VolumeRollback struct {
	Snapshot string `json:"snapshot"`
	// ConfirmDataLoss must be true: everything written to the volume since the snapshot is discarded, and so are the
	// snapshots after it.
	ConfirmDataLoss bool `json:"confirm_data_loss,omitempty"`
}

// VolumeCreate is the body of POST /api/v1/volumes: a Volume and, when it is encrypted, its passphrase. The passphrase
// is used once, to create the volume; it is never stored, logged or returned.
type VolumeCreate struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     VolumeSpec `json:"spec"`
	// Passphrase is between MinPassphrase and MaxPassphrase bytes, without line breaks.
	Passphrase string `json:"passphrase,omitempty"`
}

// VolumeUnlock is the body of POST /api/v1/volumes/{name}/unlock.
type VolumeUnlock struct {
	Passphrase string `json:"passphrase"`
	// Start starts the jail the volume is attached to once the volume is unlocked.
	Start bool `json:"start,omitempty"`
}

// VolumePassphraseChange is the body of POST /api/v1/volumes/{name}/passphrase: the passphrase of an unlocked
// encrypted volume changes from Old to New.
type VolumePassphraseChange struct {
	Old string `json:"old_passphrase"`
	New string `json:"new_passphrase"`
}

// VolumeAttachRequest is the body of POST /api/v1/jails/{name}/volumes: attach a volume of the jail's project at a
// path in the jail.
type VolumeAttachRequest struct {
	Volume   string `json:"volume"`
	Mount    string `json:"mount"`
	ReadOnly bool   `json:"read_only,omitempty"`
	// CopyExisting copies the files the jail has at Mount into the volume first, so that the mount does not hide
	// them. The volume should be new; nothing is removed from the jail's own root.
	CopyExisting bool `json:"copy_existing,omitempty"`
}

// CheckHostDirVolume checks the spec of a volume that is a directory of the host and returns it in its canonical form:
// the defaults of a watch filled in, and nothing set that a dataset has. The helper looks at the directory itself (it
// is on a mount below a directory the host operator allows); this is the check of the spec.
func CheckHostDirVolume(spec VolumeSpec) (VolumeSpec, error) {
	fail := func(field, format string, args ...any) *Error {
		return Errorf(CodeInvalid, format, args...).WithDetail("field", field)
	}
	if !spec.IsHostDir() {
		return spec, fail("path", "only a volume of a host directory is watched").WithHint("give the directory with --path, or leave --watch, --probe and --on-loss out")
	}
	if err := checkHostPath(spec.Path); err != nil {
		return spec, fail("path", "%v", err)
	}
	for _, f := range []struct {
		what string
		set  bool
	}{
		{"storage", spec.Storage != ""}, {"size", spec.Size != ""}, {"uid", spec.UID != 0}, {"gid", spec.GID != 0},
		{"mode", spec.Mode != ""}, {"encrypted", spec.Encrypted},
	} {
		if f.set {
			return spec, fail(f.what, "a volume of a host directory has no %s: the files are the host's", f.what).WithHint("leave it out, or make a volume without --path")
		}
	}
	switch spec.Probe {
	case "", VolumeProbeMounted, VolumeProbeWrite:
	default:
		return spec, fail("probe", "probe %q is not %s or %s", spec.Probe, VolumeProbeMounted, VolumeProbeWrite)
	}
	switch spec.OnLoss {
	case "", VolumeOnLossNone, VolumeOnLossStop:
	default:
		return spec, fail("on_loss", "on-loss %q is not %s or %s", spec.OnLoss, VolumeOnLossNone, VolumeOnLossStop)
	}
	if !spec.Watch {
		if spec.Probe != "" || spec.OnLoss != "" {
			return spec, fail("watch", "--probe and --on-loss say what a watch does").WithHint("add --watch")
		}
		return spec, nil
	}
	if spec.Probe == "" {
		spec.Probe = VolumeProbeMounted
	}
	if spec.OnLoss == "" {
		spec.OnLoss = VolumeOnLossNone
	}
	return spec, nil
}

// checkHostPath requires a clean absolute path of the characters a jail's fstab line takes, below /.
func checkHostPath(p string) error {
	if len(p) < 2 || len(p) > 1024 || p[0] != '/' {
		return fmt.Errorf("%q is not an absolute path below /", p)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/._+@:=,-", c) >= 0) {
			return fmt.Errorf("%q contains the unsupported character %q", p, string(c))
		}
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%q is not a clean path: no empty, '.' or '..' segments", p)
		}
	}
	return nil
}
