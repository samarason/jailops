package lifecycle

import (
	"context"
	"path"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Encrypted volumes: a volume declared encrypted is created as its own ZFS encryption root with the passphrase a
// person typed (aes-256-gcm, keyformat=passphrase, keylocation=prompt). After a host boot the key is not loaded: the
// jail that attaches it is locked and does not start, and an unlock of the volume loads the key. Lock unmounts the
// volume and unloads the key.

// volumeName is the name of a volume dataset (its last component).
func volumeName(ds string) string { return path.Base(ds) }

func encryptedVolumes(st *jailState) []dsInfo {
	var out []dsInfo
	for _, v := range st.Volumes {
		if v.Encrypted {
			out = append(out, v)
		}
	}
	return out
}

// lockedVolumes returns the encrypted volumes whose key is not loaded.
func (s *Service) lockedVolumes(ctx context.Context, st *jailState) ([]dsInfo, error) {
	var out []dsInfo
	for _, v := range encryptedVolumes(st) {
		if s.Keys == nil {
			out = append(out, v)
			continue
		}
		ks, err := s.Keys.KeyStatus(ctx, v.DS)
		if err != nil {
			return nil, err
		}
		if ks != "available" {
			out = append(out, v)
		}
	}
	return out, nil
}

func names(l []dsInfo) []string {
	out := make([]string, len(l))
	for i, v := range l {
		out[i] = volumeName(v.DS)
	}
	return out
}

// LockedError is the error of starting a jail whose encrypted volumes wait for a passphrase.
func LockedError(key string, volumes []string) error {
	_, plain := splitKey(key)
	return api.Errorf(api.CodeLocked, "jail %q is locked: the encrypted volume(s) %s wait for a passphrase", plain, strings.Join(volumes, ", ")).
		WithHint("jailops volume unlock "+volumes[0]).WithDetail("volumes", strings.Join(volumes, ","))
}

func (s *Service) refuseLocked(ctx context.Context, st *jailState) error {
	l, err := s.lockedVolumes(ctx, st)
	if err != nil {
		return err
	}
	if len(l) > 0 {
		return LockedError(st.Name, names(l))
	}
	return nil
}

// Locked returns the names of the encrypted volumes of a jail whose key is not loaded (nil when none).
func (s *Service) Locked(ctx context.Context, name string) ([]string, error) {
	st, err := s.observe(ctx, name)
	if err != nil {
		return nil, err
	}
	l, err := s.lockedVolumes(ctx, st)
	if err != nil || len(l) == 0 {
		return nil, err
	}
	return names(l), nil
}

// EncryptedVolumes returns the names of the encrypted volumes of a jail.
func (s *Service) EncryptedVolumes(ctx context.Context, name string) ([]string, error) {
	st, err := s.observe(ctx, name)
	if err != nil {
		return nil, err
	}
	return names(encryptedVolumes(st)), nil
}

func (s *Service) needKeys() error {
	if s.Keys == nil {
		return api.Errorf(api.CodeUnsupported, "this host has no key operations for encrypted volumes")
	}
	return nil
}

// UnlockVolume loads the key of an encrypted volume. Nothing is mounted: the volume is mounted on the host by the
// start of the jail that attaches it. A wrong passphrase answers bad_passphrase.
func (s *Service) UnlockVolume(ctx context.Context, st Storage, project, name string, passphrase []byte) error {
	if err := s.needKeys(); err != nil {
		return err
	}
	ds := VolumeDS(st, project, name)
	if ks, err := s.Keys.KeyStatus(ctx, ds); err != nil {
		return err
	} else if ks == "available" {
		return nil
	}
	return s.Keys.LoadKey(ctx, ds, passphrase)
}

// LockVolume unmounts an encrypted volume and unloads its key. The caller has stopped the jail that attaches it.
func (s *Service) LockVolume(ctx context.Context, st Storage, project, name string) error {
	if err := s.needKeys(); err != nil {
		return err
	}
	ds := VolumeDS(st, project, name)
	if err := s.ZFS.Unmount(ctx, ds); err != nil {
		return err
	}
	return s.Keys.UnloadKey(ctx, ds)
}

// ChangeVolumePassphrase changes the passphrase of an unlocked encrypted volume.
func (s *Service) ChangeVolumePassphrase(ctx context.Context, st Storage, project, name string, oldPass, newPass []byte) error {
	if err := s.needKeys(); err != nil {
		return err
	}
	ds := VolumeDS(st, project, name)
	if ks, err := s.Keys.KeyStatus(ctx, ds); err != nil {
		return err
	} else if ks != "available" {
		return VolumeLockedError(name)
	}
	return s.Keys.ChangeKey(ctx, ds, oldPass, newPass)
}

// VolumeLockedError is the error of an operation that needs an unlocked volume.
func VolumeLockedError(volume string) error {
	return api.Errorf(api.CodeLocked, "volume %q is locked: it waits for a passphrase", volume).WithHint("jailops volume unlock " + volume)
}
