package priv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// Encrypted volumes (design 4.6, docs/storage.md). A volume of a jail can be a ZFS encryption root with a passphrase
// a person types. The passphrase travels on the request stream of the operation, never in its arguments, so it is in
// no argv, no audit line and no error. The helper feeds it to zfs on standard input: zfs reads a passphrase from a
// stdin that is not a terminal as one line.
//
// The operations accept only what JailOps creates: a dataset named <storage root>/projects/<project>/volumes/<volume>,
// managed (jailops:managed=on set locally), of kind volume, below a parent of kind volumes, and, except at creation,
// its own encryption root with keyformat=passphrase.
//
// UNVERIFIED: the zfs commands below were not run on FreeBSD by this change (scripts/ci-freebsd-e2e.sh has the
// block): that create, load-key and change-key read one line from a stdin that is not a terminal, that
// "load-key -n" checks a passphrase while the key is loaded, and the error texts mapped here.
const (
	OpZFSCreateEncrypted = "zfs.create_encrypted"
	OpZFSLoadKey         = "zfs.load_key"
	OpZFSUnloadKey       = "zfs.unload_key"
	OpZFSChangeKey       = "zfs.change_key"
	// zfs.feature_state reads the state of one feature of a pool that holds a storage root (doctor).
	OpZFSFeatureState = "zfs.feature_state"
)

type featureArgs struct {
	Name    string `json:"name"`
	Feature string `json:"feature"`
}

// The encryption every encrypted volume gets; the caller cannot choose another.
var volumeEncryption = map[string]string{"encryption": "aes-256-gcm", "keyformat": "passphrase", "keylocation": "prompt"}

// keyProps are the properties only the helper sets on an encrypted volume.
var keyProps = []string{"encryption", "keyformat", "keylocation", "pbkdf2iters", "pbkdf2salt"}

const keyTimeout = 2 * time.Minute // PBKDF2 makes a key load slow on purpose

func init() {
	register(OpZFSCreateEncrypted, false, func(ctx context.Context, h Host, a zfs.CreateOpts, c *callIO) (any, error) {
		p, err := readSecrets(c.In, 1)
		if err != nil {
			return nil, err
		}
		defer wipe(p...)
		return empty{}, h.CreateEncrypted(ctx, a, p[0])
	})
	register(OpZFSLoadKey, false, func(ctx context.Context, h Host, a nameArgs, c *callIO) (any, error) {
		p, err := readSecrets(c.In, 1)
		if err != nil {
			return nil, err
		}
		defer wipe(p...)
		return empty{}, h.LoadKey(ctx, a.Name, p[0])
	})
	register(OpZFSFeatureState, false, func(ctx context.Context, h Host, a featureArgs, _ *callIO) (any, error) {
		fs, ok := h.ZFS().(zfs.FeatureStater)
		if !ok {
			return nil, api.Errorf(api.CodeUnsupported, "this host cannot read pool features")
		}
		v, err := fs.FeatureState(ctx, a.Name, a.Feature)
		return strRes{v}, err
	})
	register(OpZFSUnloadKey, false, func(ctx context.Context, h Host, a nameArgs, _ *callIO) (any, error) {
		return empty{}, h.UnloadKey(ctx, a.Name)
	})
	register(OpZFSChangeKey, false, func(ctx context.Context, h Host, a nameArgs, c *callIO) (any, error) {
		p, err := readSecrets(c.In, 2)
		if err != nil {
			return nil, err
		}
		defer wipe(p...)
		return empty{}, h.ChangeKey(ctx, a.Name, p[0], p[1])
	})
}

// readSecrets reads n passphrases from the request stream: one, or two separated by a single line feed. Each is 1 to
// api.MaxPassphrase bytes without a line break or NUL; more input than that is refused, not cut.
func readSecrets(r io.Reader, n int) ([][]byte, error) {
	limit := n*api.MaxPassphrase + (n - 1)
	b, err := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if err != nil {
		return nil, invalid("reading the passphrase: %v", err)
	}
	if len(b) > limit {
		wipe(b)
		return nil, invalid("a passphrase is at most %d bytes", api.MaxPassphrase)
	}
	parts := [][]byte{b}
	if n == 2 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			wipe(b)
			return nil, invalid("expected two passphrases")
		}
		parts = [][]byte{b[:i], b[i+1:]}
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > api.MaxPassphrase || bytes.ContainsAny(p, "\n\r\x00") {
			wipe(b)
			return nil, invalid("a passphrase is 1 to %d bytes without a line break or a NUL byte", api.MaxPassphrase)
		}
	}
	return parts, nil
}

// wipe overwrites secrets that are no longer needed (best effort: Go may have copied them).
func wipe(bs ...[]byte) {
	for _, b := range bs {
		for i := range b {
			b[i] = 0
		}
	}
}

func checkNewPassphrase(p []byte) error {
	if len(p) < api.MinPassphrase || len(p) > api.MaxPassphrase || bytes.ContainsAny(p, "\n\r\x00") {
		return invalid("a new passphrase is %d to %d bytes without a line break or a NUL byte", api.MinPassphrase, api.MaxPassphrase)
	}
	return nil
}

// localProp returns a property's value when it is set on the dataset itself.
func (l *Local) localProp(m map[string]zfs.Prop, k string) string {
	if p, ok := m[k]; ok && p.Source == "local" {
		return p.Value
	}
	return ""
}

// volumeParent checks that parent is the managed volumes dataset of a project: <storage root>/projects/<project>/volumes.
func (l *Local) volumeParent(ctx context.Context, parent string) error {
	if err := (zfsGuard{l}).managed(ctx, parent); err != nil {
		return err
	}
	m, err := l.d.ZFS.Get(ctx, parent, "jailops:kind")
	if err != nil {
		return err
	}
	if l.localProp(m, "jailops:kind") != "volumes" || !l.cfg.isVolumesDataset(parent) {
		return forbidden("%s is not the volumes dataset of a project", parent)
	}
	return nil
}

// isVolumesDataset reports whether ds is <storage root>/projects/<project>/volumes.
func (c Config) isVolumesDataset(ds string) bool {
	e, ok := c.rootOf(ds)
	if !ok {
		return false
	}
	rest, ok := strings.CutPrefix(ds, e.Dataset+"/projects/")
	if !ok {
		return false
	}
	p, last, ok := strings.Cut(rest, "/")
	return ok && p != "" && last == "volumes"
}

// encryptedVolume checks that ds is an encrypted volume of a project and returns its key status.
func (l *Local) encryptedVolume(ctx context.Context, ds string) (string, error) {
	if err := l.cfg.zfsDataset(ds); err != nil {
		return "", err
	}
	if err := (zfsGuard{l}).managed(ctx, ds); err != nil {
		return "", err
	}
	i := strings.LastIndexByte(ds, '/')
	if i < 0 {
		return "", forbidden("%s is not a volume of a project", ds)
	}
	if err := l.volumeParent(ctx, ds[:i]); err != nil {
		return "", err
	}
	m, err := l.d.ZFS.Get(ctx, ds, "jailops:kind", "encryptionroot", "keyformat", "keystatus")
	if err != nil {
		return "", err
	}
	if l.localProp(m, "jailops:kind") != "volume" {
		return "", forbidden("%s is not a volume of a project", ds)
	}
	if m["encryptionroot"].Value != ds || m["keyformat"].Value != "passphrase" {
		return "", forbidden("%s is not an encrypted volume with a passphrase", ds)
	}
	return m["keystatus"].Value, nil
}

// zfsKey runs one zfs key command with the secret on standard input.
func (l *Local) zfsKey(ctx context.Context, args []string, secret []byte) (run.Result, error) {
	c := run.Cmd{Name: "zfs", Args: args, Timeout: keyTimeout}
	if secret != nil {
		in := make([]byte, 0, len(secret)+1)
		in = append(append(in, secret...), '\n')
		defer wipe(in)
		c.Stdin = bytes.NewReader(in)
	}
	return l.d.Runner.Run(ctx, c)
}

// keyError turns a failed zfs key command into an API error. Nothing of the input is repeated.
func keyError(verb string, err error) error {
	ee, ok := run.IsExit(err)
	if !ok {
		return err
	}
	msg := strings.TrimSpace(ee.Stderr)
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "incorrect key") || strings.Contains(low, "wrong key") || strings.Contains(low, "invalid key"):
		return api.Errorf(api.CodeBadPassphrase, "the passphrase is not correct")
	case strings.Contains(low, "busy"):
		return api.Errorf(api.CodeBusy, "zfs %s: %s", verb, clip(msg, 300))
	case strings.Contains(low, "does not exist"):
		return api.Errorf(api.CodeNotFound, "zfs %s: %s", verb, clip(msg, 300))
	}
	return api.Errorf(api.CodeInternal, "zfs %s: %s", verb, clip(msg, 300))
}

// CreateEncrypted creates a volume of a jail as an encryption root (aes-256-gcm, keyformat=passphrase,
// keylocation=prompt). Its key stays loaded: the new jail can start without an unlock.
func (l *Local) CreateEncrypted(ctx context.Context, o zfs.CreateOpts, passphrase []byte) error {
	c := l.cfg
	if err := c.zfsDataset(o.Name); err != nil {
		return err
	}
	if o.VolumeSize != "" || o.Parents {
		return invalid("an encrypted volume is a file system created below an existing parent")
	}
	for _, k := range keyProps {
		if _, set := o.Props[k]; set {
			return forbidden("property %s of an encrypted volume is set by the helper", k)
		}
	}
	if err := c.zfsProps(ctx, o.Props); err != nil {
		return err
	}
	if o.Props["jailops:managed"] != "on" || o.Props["jailops:kind"] != "volume" {
		return forbidden("an encrypted volume carries jailops:managed=on and jailops:kind=volume")
	}
	i := strings.LastIndexByte(o.Name, '/')
	if err := l.volumeParent(ctx, o.Name[:i]); err != nil {
		return err
	}
	if err := checkNewPassphrase(passphrase); err != nil {
		return err
	}
	props := map[string]string{}
	for k, v := range o.Props {
		props[k] = v
	}
	for k, v := range volumeEncryption {
		props[k] = v
	}
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := []string{"create"}
	for _, k := range keys {
		args = append(args, "-o", k+"="+props[k])
	}
	args = append(args, o.Name)
	if _, err := l.zfsKey(ctx, args, passphrase); err != nil {
		return keyError("create", err)
	}
	// a volume created incomplete is being restored: file agents may write it until it is marked complete or destroyed
	if o.Props[propComplete] == "off" {
		l.grants.beginRestore(o.Name)
	}
	return nil
}

// Wrong passphrases are limited in the helper itself, not only in the daemon, which a compromised daemon would skip:
// after keyFreeTries wrong ones for a volume (keyGlobalFree for all volumes together) every further try waits,
// keyBaseWait at first and twice as long after each further wrong one, at most keyMaxWait. A right passphrase forgets
// the failures. The counters live in memory: a restart of the helper forgets them, which needs root.
const (
	keyFreeTries  = 5
	keyGlobalFree = 20
	keyBaseWait   = 30 * time.Second
	keyMaxWait    = time.Hour
)

type keyFails struct {
	n     int
	until time.Time
}

// keyLimiter counts wrong passphrases per dataset and for all of them.
type keyLimiter struct {
	mu  sync.Mutex
	per map[string]*keyFails
	all keyFails
}

func keyWait(n, free int) time.Duration {
	if n < free {
		return 0
	}
	d := keyBaseWait
	for i := free; i < n && d < keyMaxWait; i++ {
		d *= 2
	}
	return min(d, keyMaxWait)
}

// check refuses while the dataset, or every dataset, waits after wrong passphrases.
func (k *keyLimiter) check(ds string, now time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	until := k.all.until
	if f := k.per[ds]; f != nil && f.until.After(until) {
		until = f.until
	}
	if !now.Before(until) {
		return nil
	}
	wait := max(until.Sub(now).Round(time.Second), time.Second)
	return api.Errorf(api.CodeRateLimited, "too many wrong passphrases for %s", ds).WithHint(fmt.Sprintf("wait %s and try again", wait))
}

// result counts a wrong passphrase, or forgets the failures of the dataset (and the global count) after a right one.
func (k *keyLimiter) result(ds string, err error, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch {
	case err == nil:
		delete(k.per, ds)
		k.all = keyFails{}
	case api.IsCode(err, api.CodeBadPassphrase):
		if k.per == nil {
			k.per = map[string]*keyFails{}
		}
		f := k.per[ds]
		if f == nil {
			f = &keyFails{}
			k.per[ds] = f
		}
		for _, c := range []struct {
			f    *keyFails
			free int
		}{{f, keyFreeTries}, {&k.all, keyGlobalFree}} {
			c.f.n++
			if w := keyWait(c.f.n, c.free); w > 0 {
				c.f.until = now.Add(w)
			}
		}
	}
}

// LoadKey loads the key of an encrypted volume. A key that is loaded already is success.
func (l *Local) LoadKey(ctx context.Context, dataset string, passphrase []byte) error {
	st, err := l.encryptedVolume(ctx, dataset)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 || len(passphrase) > api.MaxPassphrase || bytes.ContainsAny(passphrase, "\n\r\x00") {
		return invalid("a passphrase is 1 to %d bytes without a line break or a NUL byte", api.MaxPassphrase)
	}
	if st == "available" {
		return nil
	}
	if err := l.keyLim.check(dataset, l.now()); err != nil {
		return err
	}
	_, err = l.zfsKey(ctx, []string{"load-key", dataset}, passphrase)
	if ee, ok := run.IsExit(err); ok && strings.Contains(strings.ToLower(ee.Stderr), "already loaded") {
		err = nil
	} else if err != nil {
		err = keyError("load-key", err)
	}
	l.keyLim.result(dataset, err, l.now())
	return err
}

// UnloadKey unloads the key of an encrypted volume; the volume must be unmounted. An unloaded key is success.
func (l *Local) UnloadKey(ctx context.Context, dataset string) error {
	st, err := l.encryptedVolume(ctx, dataset)
	if err != nil {
		return err
	}
	if st == "unavailable" {
		return nil
	}
	if _, err := l.zfsKey(ctx, []string{"unload-key", dataset}, nil); err != nil {
		if ee, ok := run.IsExit(err); ok && strings.Contains(strings.ToLower(ee.Stderr), "already unloaded") {
			return nil
		}
		return keyError("unload-key", err)
	}
	return nil
}

// ChangeKey changes the passphrase of an encrypted volume whose key is loaded. The old passphrase is checked first
// (zfs load-key -n), so a running daemon alone cannot change a passphrase it was never told.
func (l *Local) ChangeKey(ctx context.Context, dataset string, oldPass, newPass []byte) error {
	st, err := l.encryptedVolume(ctx, dataset)
	if err != nil {
		return err
	}
	if st != "available" {
		return api.Errorf(api.CodeLocked, "%s is locked", dataset).WithHint("unlock the jail first")
	}
	if err := checkNewPassphrase(newPass); err != nil {
		return err
	}
	if err := l.keyLim.check(dataset, l.now()); err != nil {
		return err
	}
	if _, err := l.zfsKey(ctx, []string{"load-key", "-n", dataset}, oldPass); err != nil {
		err = keyError("load-key", err)
		l.keyLim.result(dataset, err, l.now())
		return err
	}
	l.keyLim.result(dataset, nil, l.now())
	if _, err := l.zfsKey(ctx, []string{"change-key", "-o", "keyformat=passphrase", "-o", "keylocation=prompt", dataset}, newPass); err != nil {
		return keyError("change-key", err)
	}
	return nil
}

// ReplicateRaw is Replicate with a raw send (zfs send -w): an encrypted volume is copied as it is stored, with its
// key and passphrase, and the copy stays encrypted (and locked) on the same pool.
func (l *Local) ReplicateRaw(ctx context.Context, snapshot, dst string, props map[string]string) error {
	return zfsGuard{l}.replicate(ctx, snapshot, dst, props, true)
}

// FeatureState reads one feature of a pool that holds a registered storage root.
func (g zfsGuard) FeatureState(ctx context.Context, pool, feature string) (string, error) {
	if !slices.Contains(g.l.cfg.Pools(), pool) {
		return "", forbidden("pool %q holds no registered storage root", pool)
	}
	if err := zfs.ValidateFeature(feature); err != nil {
		return "", err
	}
	fs, ok := g.l.d.ZFS.(zfs.FeatureStater)
	if !ok {
		return "", api.Errorf(api.CodeUnsupported, "this host cannot read pool features")
	}
	return fs.FeatureState(ctx, pool, feature)
}

// ---- client side ----

// FeatureState implements zfs.FeatureStater over the helper.
func (z zfsClient) FeatureState(ctx context.Context, pool, feature string) (string, error) {
	r, err := callJSON[strRes](ctx, z.c, OpZFSFeatureState, featureArgs{pool, feature}, callOpts{})
	return r.V, err
}

// CreateEncrypted implements Host.
func (c *Client) CreateEncrypted(ctx context.Context, o zfs.CreateOpts, passphrase []byte) error {
	_, err := callJSON[empty](ctx, c, OpZFSCreateEncrypted, o, callOpts{in: bytes.NewReader(passphrase)})
	return err
}

// LoadKey implements Host.
func (c *Client) LoadKey(ctx context.Context, dataset string, passphrase []byte) error {
	_, err := callJSON[empty](ctx, c, OpZFSLoadKey, nameArgs{dataset}, callOpts{in: bytes.NewReader(passphrase)})
	return err
}

// UnloadKey implements Host.
func (c *Client) UnloadKey(ctx context.Context, dataset string) error {
	return callNone(ctx, c, OpZFSUnloadKey, nameArgs{dataset})
}

// ChangeKey implements Host: the two passphrases go on the stream, separated by a line feed.
func (c *Client) ChangeKey(ctx context.Context, dataset string, oldPass, newPass []byte) error {
	in := make([]byte, 0, len(oldPass)+1+len(newPass))
	in = append(append(append(in, oldPass...), '\n'), newPass...)
	_, err := callJSON[empty](ctx, c, OpZFSChangeKey, nameArgs{dataset}, callOpts{in: bytes.NewReader(in)})
	return err
}

// ReplicateRaw implements Host.
func (c *Client) ReplicateRaw(ctx context.Context, snapshot, dst string, props map[string]string) error {
	return callNone(ctx, c, OpZFSReplicate, zfsReplicateArgs{Snapshot: snapshot, Dst: dst, Props: props, Raw: true})
}
