package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"jailops.net/jailops/internal/hostdir"
	"jailops.net/jailops/internal/mounts"
	"jailops.net/jailops/internal/priv"
	"jailops.net/jailops/sdk/api"
)

// privFiles implements service.FS through jailops-priv's file operations, which
// refuse anything outside the allow-listed roots.
type privFiles struct {
	h priv.Host
	// own is the directory the daemon owns (its state directory): there it reads and writes itself. The helper
	// never writes in a directory the daemon can modify (a path component swapped for a symlink would turn the
	// helper's root write into a write anywhere).
	own string
}

func (f privFiles) mine(path string) bool {
	return f.own != "" && (path == f.own || strings.HasPrefix(path, f.own+"/"))
}

func (f privFiles) WriteAtomic(ctx context.Context, path string, data []byte) error {
	if f.mine(path) {
		return osFiles{}.WriteAtomic(ctx, path, data)
	}
	return f.h.WriteFile(ctx, priv.WriteFileReq{Path: path, Data: data, Mode: 0o644, Parents: true})
}
func (f privFiles) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if f.mine(path) {
		return osFiles{}.ReadFile(ctx, path)
	}
	return f.h.ReadFile(ctx, path)
}
func (f privFiles) Exists(ctx context.Context, path string) (bool, error) {
	if f.mine(path) {
		return osFiles{}.Exists(ctx, path)
	}
	_, err := f.h.ReadFile(ctx, path)
	if err == nil {
		return true, nil
	}
	if api.IsCode(err, api.CodeNotFound) {
		return false, nil
	}
	return true, nil // present but not a readable file (a directory)
}
func (f privFiles) MkdirAll(ctx context.Context, path string) error {
	if f.mine(path) {
		return osFiles{}.MkdirAll(ctx, path)
	}
	return f.h.MkdirAll(ctx, priv.MkdirReq{Path: path, Mode: 0o755})
}
func (f privFiles) SetOwner(ctx context.Context, path string, uid, gid int, mode uint32) error {
	return f.h.SetVolumeOwner(ctx, priv.VolumeOwnerReq{Path: path, UID: uint32(uid), GID: uint32(gid), Mode: mode})
}
func (f privFiles) ProbeSource(ctx context.Context, path string, write bool) (hostdir.Probe, error) {
	r, err := f.h.ProbeSource(ctx, priv.SourceProbeReq{Path: path, Write: write})
	return hostdir.Probe{Mounted: r.Mounted, Writable: r.Writable, Detail: r.Detail}, err
}
func (f privFiles) StaleMounts(ctx context.Context) ([]mounts.Stale, error) {
	ms, err := f.h.StaleMounts(ctx)
	out := make([]mounts.Stale, 0, len(ms))
	for _, m := range ms {
		out = append(out, mounts.Stale{Jail: m.Jail, Path: m.Path, Type: m.Type})
	}
	return out, err
}
func (f privFiles) HealJail(ctx context.Context, jail string) (mounts.Healed, error) {
	r, err := f.h.HealJail(ctx, jail)
	return mounts.Healed{Unmounted: r.Unmounted, Left: r.Left, Errors: r.Errors}, err
}
func (f privFiles) HealNetwork(ctx context.Context) (mounts.NetHealed, error) {
	r, err := f.h.HealNetwork(ctx)
	return mounts.NetHealed{Destroyed: r.Destroyed, Skipped: r.Skipped}, err
}
func (f privFiles) DNSUnbound(ctx context.Context, apply bool) (mounts.UnboundState, error) {
	r, err := f.h.DNSUnbound(ctx, apply)
	return mounts.UnboundState{Enabled: r.Enabled, Base: r.Base, Reason: r.Reason, Current: r.Current, Changed: r.Changed, Reloaded: r.Reloaded, Path: r.Path,
		Control: r.Control, Sample: r.Sample, Names: r.Names, Gateways: r.Gateways,
		Suffix: r.Suffix, Jails: r.Jails, Projects: r.Projects, Forward: r.Forward, Recurse: r.Recurse}, err
}
func (f privFiles) RemoveAll(ctx context.Context, path string) error {
	if f.mine(path) {
		return osFiles{}.RemoveAll(ctx, path)
	}
	err := f.h.RemoveAll(ctx, path)
	if api.IsCode(err, api.CodeNotFound) {
		return nil
	}
	return err
}

// SeedKeys copies the host signing keys into an image root through the helper.
func (f privFiles) SeedKeys(ctx context.Context, root string) error {
	_, err := f.h.SeedKeys(ctx, root)
	return err
}

// CopyTree seeds a persistent dataset from the image through the helper.
func (f privFiles) CopyTree(ctx context.Context, src, dst string) error {
	_, err := f.h.CopyTree(ctx, src, dst, priv.CopyOpts{})
	return err
}
func (f privFiles) SHA256(ctx context.Context, path string) (string, error) {
	b, err := f.h.ReadFile(ctx, path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// osFiles is the real filesystem, for --dev as root. UNVERIFIED on FreeBSD:
// file flags, ACLs and extended attributes are not copied.
type osFiles struct{}

func (osFiles) WriteAtomic(_ context.Context, path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".previous", old, 0o600)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
func (osFiles) ReadFile(_ context.Context, path string) ([]byte, error) { return os.ReadFile(path) }
func (osFiles) Exists(_ context.Context, path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
func (osFiles) MkdirAll(_ context.Context, path string) error { return os.MkdirAll(path, 0o755) }
func (osFiles) SetOwner(_ context.Context, path string, uid, gid int, mode uint32) error {
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

// StaleMounts, HealJail and HealNetwork of a daemon without the helper: there is no table of mounts to read and nothing to take off.
func (osFiles) StaleMounts(context.Context) ([]mounts.Stale, error)     { return nil, nil }
func (osFiles) HealJail(context.Context, string) (mounts.Healed, error) { return mounts.Healed{}, nil }
func (osFiles) HealNetwork(context.Context) (mounts.NetHealed, error)   { return mounts.NetHealed{}, nil }
func (osFiles) DNSUnbound(context.Context, bool) (mounts.UnboundState, error) {
	return mounts.UnboundState{}, nil
}

// ProbeSource of a daemon without the helper: the directory is on a mount when its device is not its parent's.
func (osFiles) ProbeSource(_ context.Context, path string, write bool) (hostdir.Probe, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return hostdir.Probe{Detail: "the directory does not exist"}, nil
	}
	up, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return hostdir.Probe{}, err
	}
	a, ok1 := fi.Sys().(*syscall.Stat_t)
	b, ok2 := up.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || uint64(a.Dev) == uint64(b.Dev) { //nolint:unconvert // the width of Dev differs by system
		return hostdir.Probe{Detail: "the directory is not on a mount"}, nil
	}
	out := hostdir.Probe{Mounted: true}
	if write {
		f, err := os.CreateTemp(path, ".jailops-probe-")
		if err != nil {
			out.Detail = "no file can be created in the directory"
			return out, nil
		}
		f.Close()
		os.Remove(f.Name())
		out.Writable = true
	}
	return out, nil
}
func (osFiles) RemoveAll(_ context.Context, path string) error { return os.RemoveAll(path) }
func (osFiles) SHA256(_ context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CopyTree copies a directory tree preserving modes, owners and symlinks.
func (osFiles) CopyTree(_ context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
		case d.Type()&fs.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(l, target); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			in, err := os.Open(p)
			if err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
			if err != nil {
				in.Close()
				return err
			}
			_, cerr := io.Copy(out, in)
			in.Close()
			if err := out.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		default:
			return nil // devices, sockets and fifos are not part of an image tree
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		}
		return nil
	})
}

// SeedKeys copies /usr/share/keys into <root>/usr/share/keys.
func (o osFiles) SeedKeys(ctx context.Context, root string) error {
	return o.CopyTree(ctx, "/usr/share/keys", filepath.Join(root, "usr/share/keys"))
}
