package priv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/wgtool"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// WireGuard. The helper creates and configures the WireGuard interfaces of the daemon's WireGuard objects and keeps
// their secrets. Each object has a directory <wireguard-dir>/<name> (root, mode 0700) holding
//
//	private.key       the interface's private key (0600), made with `wg genkey` or taken from a join token
//	public.key        its public key
//	iface             the name of the interface the helper created for the object: the proof that it is JailOps's
//	psk/<id>.psk      the preshared key of one peer (0600); id is derived from the peer's public key
//
// Nothing else is written, and nothing outside the directory. The daemon never reads it: the private key leaves the
// helper only inside a configuration file the helper writes there for `wg syncconf` and removes again, and a peer's
// private key leaves it once, in the answer of wg.peer_keys, for the peer's join token. Every operation that
// changes something needs the admin assertion (an API admin, or the daemon's own reconcile loop).

// DefaultWireGuardDir is where the helper keeps the keys of WireGuard interfaces. It is the helper's own, outside
// the daemon's data directory, which the daemon could rearrange.
const DefaultWireGuardDir = "/var/db/jailops-priv/wireguard"

// Operation names of WireGuard.
const (
	OpWGKeys     = "wg.keys"
	OpWGPeerKeys = "wg.peer_keys"
	OpWGImport   = "wg.import"
	OpWGApply    = "wg.apply"
	OpWGRemove   = "wg.remove"
	OpWGRename   = "wg.rename"
	OpWGShow     = "wg.show"
	OpWGTools    = "wg.tools"
)

const (
	wgPrivFile  = "private.key"
	wgPubFile   = "public.key"
	wgIfaceFile = "iface"
	wgPSKDir    = "psk"
	wgConfFile  = ".syncconf"
)

func init() {
	register(OpWGKeys, false, func(ctx context.Context, h Host, a wireguard.KeysReq, _ *callIO) (any, error) {
		return h.WGKeys(ctx, a)
	})
	register(OpWGPeerKeys, false, func(ctx context.Context, h Host, a wireguard.PeerKeysReq, _ *callIO) (any, error) {
		return h.WGPeerKeys(ctx, a)
	})
	register(OpWGImport, false, func(ctx context.Context, h Host, a wireguard.ImportReq, _ *callIO) (any, error) {
		return h.WGImport(ctx, a)
	})
	register(OpWGApply, false, func(ctx context.Context, h Host, a wireguard.ApplyReq, _ *callIO) (any, error) {
		return h.WGApply(ctx, a)
	})
	register(OpWGRemove, false, func(ctx context.Context, h Host, a wireguard.RemoveReq, _ *callIO) (any, error) {
		return empty{}, h.WGRemove(ctx, a)
	})
	register(OpWGRename, false, func(ctx context.Context, h Host, a wireguard.RenameReq, _ *callIO) (any, error) {
		return empty{}, h.WGRename(ctx, a)
	})
	register(OpWGShow, false, func(ctx context.Context, h Host, a wireguard.ShowReq, _ *callIO) (any, error) {
		return h.WGShow(ctx, a)
	})
	register(OpWGTools, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.WGTools(ctx)
	})
}

// ---- client side ----

// WGKeys implements wireguard.Host.
func (c *Client) WGKeys(ctx context.Context, q wireguard.KeysReq) (wireguard.KeysRes, error) {
	return callJSON[wireguard.KeysRes](ctx, c, OpWGKeys, q, callOpts{})
}

// WGPeerKeys implements wireguard.Host.
func (c *Client) WGPeerKeys(ctx context.Context, q wireguard.PeerKeysReq) (wireguard.PeerKeysRes, error) {
	return callJSON[wireguard.PeerKeysRes](ctx, c, OpWGPeerKeys, q, callOpts{})
}

// WGImport implements wireguard.Host.
func (c *Client) WGImport(ctx context.Context, q wireguard.ImportReq) (wireguard.KeysRes, error) {
	return callJSON[wireguard.KeysRes](ctx, c, OpWGImport, q, callOpts{})
}

// WGApply implements wireguard.Host.
func (c *Client) WGApply(ctx context.Context, q wireguard.ApplyReq) (wireguard.ApplyRes, error) {
	return callJSON[wireguard.ApplyRes](ctx, c, OpWGApply, q, callOpts{})
}

// WGRemove implements wireguard.Host.
func (c *Client) WGRemove(ctx context.Context, q wireguard.RemoveReq) error {
	return callNone(ctx, c, OpWGRemove, q)
}

// WGRename implements wireguard.Host.
func (c *Client) WGRename(ctx context.Context, q wireguard.RenameReq) error {
	return callNone(ctx, c, OpWGRename, q)
}

// WGShow implements wireguard.Host.
func (c *Client) WGShow(ctx context.Context, q wireguard.ShowReq) (wireguard.ShowRes, error) {
	return callJSON[wireguard.ShowRes](ctx, c, OpWGShow, q, callOpts{})
}

// WGTools implements wireguard.Host.
func (c *Client) WGTools(ctx context.Context) (wireguard.ToolsRes, error) {
	return callJSON[wireguard.ToolsRes](ctx, c, OpWGTools, empty{}, callOpts{})
}

// ---- helper side ----

func (l *Local) wgTool() wgtool.Tool {
	path := ""
	if l.d.WGLocate != nil {
		path = l.d.WGLocate()
	} else {
		path = wgtool.Locate(os.Stat, fileUID)
	}
	return wgtool.Tool{R: l.d.Runner, Path: path}
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// wgDir opens the helper's WireGuard directory, creating it (mode 0700) when create is set. It must be a plain
// directory of root that nobody else may enter, below a parent nobody but root may write: the daemon must not be able
// to swap it for a link between a check and a write.
func (l *Local) wgDir(create bool) (*os.Root, error) {
	dir := l.cfg.WireGuardDir
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, api.Errorf(api.CodeInternal, "creating %s: %v", dir, err)
		}
	}
	if err := l.cfg.checkWGDir(dir); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, api.Errorf(api.CodeNotFound, "the helper has no WireGuard keys yet")
		}
		return nil, api.Errorf(api.CodeInternal, "opening %s: %v", dir, err)
	}
	// What was opened is what was checked: the opened directory itself must still be root's and closed to others.
	if fi, err := r.Stat("."); err != nil || !l.cfg.noOwnerCheck && !rootOnly(fi) {
		r.Close()
		return nil, forbidden("%s must belong to root with mode 0700", dir)
	}
	return r, nil
}

func rootOnly(fi os.FileInfo) bool {
	uid, ok := fileUID(fi)
	return ok && uid == 0 && fi.IsDir() && fi.Mode().Perm()&0o077 == 0
}

// checkWGDir checks the directory and its parent before they are used.
func (c Config) checkWGDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return api.Errorf(api.CodeNotFound, "the helper has no WireGuard keys yet")
		}
		return api.Errorf(api.CodeInternal, "%s: %v", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return forbidden("%s is not a plain directory", dir)
	}
	if c.noOwnerCheck {
		return nil
	}
	if !rootOnly(fi) {
		return forbidden("%s must belong to root with mode 0700", dir)
	}
	pi, err := os.Lstat(filepath.Dir(dir))
	if err != nil {
		return api.Errorf(api.CodeInternal, "%s: %v", filepath.Dir(dir), err)
	}
	if uid, ok := fileUID(pi); !ok || uid != 0 || pi.Mode()&os.ModeSymlink != 0 || pi.Mode().Perm()&0o022 != 0 {
		return forbidden("%s must belong to root and not be writable by anybody else", filepath.Dir(dir))
	}
	return nil
}

// wgObj opens the directory of one object.
func (l *Local) wgObj(name string, create bool) (*os.Root, error) {
	if err := wireguard.ValidName("name", name); err != nil {
		return nil, err
	}
	base, err := l.wgDir(create)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	if create {
		if err := base.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, api.Errorf(api.CodeInternal, "creating the key directory of %s: %v", name, err)
		}
	}
	r, err := base.OpenRoot(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, api.Errorf(api.CodeNotFound, "wireguard %q has no keys on this host", name)
		}
		return nil, api.Errorf(api.CodeInternal, "opening the key directory of %s: %v", name, err)
	}
	if fi, err := r.Stat("."); err != nil || !fi.IsDir() || !l.cfg.noOwnerCheck && !rootOnly(fi) {
		r.Close()
		return nil, forbidden("the key directory of %s must belong to root with mode 0700", name)
	}
	return r, nil
}

// wgWrite writes a file of the object atomically with mode 0600.
func wgWrite(r *os.Root, name string, data []byte) error {
	tmp := name + ".tmp"
	_ = r.Remove(tmp)
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return api.Errorf(api.CodeInternal, "writing %s: %v", name, err)
	}
	_, werr := f.Write(data)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = r.Rename(tmp, name)
	}
	if werr != nil {
		_ = r.Remove(tmp)
		return api.Errorf(api.CodeInternal, "writing %s: %v", name, werr)
	}
	return nil
}

// wgRead reads a small file of the object; a missing file is "".
func wgRead(r *os.Root, name string) (string, error) {
	b, err := r.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", api.Errorf(api.CodeInternal, "reading %s: %v", name, err)
	}
	if len(b) > 4096 {
		return "", api.Errorf(api.CodeInternal, "%s is too large", name)
	}
	return strings.TrimSpace(string(b)), nil
}

// pskFile names the preshared key of a peer: derived from its public key, so a peer that comes back with another
// key never gets the old preshared key.
func pskFile(pub string) string {
	s := sha256.Sum256([]byte(pub))
	return wgPSKDir + "/" + hex.EncodeToString(s[:16]) + ".psk"
}

func (l *Local) wgAdmin(what string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if !isAdmin(ctx) {
			return forbidden("%s needs the admin assertion", what)
		}
		return nil
	}
}

// WGKeys implements wireguard.Host.
func (l *Local) WGKeys(ctx context.Context, q wireguard.KeysReq) (wireguard.KeysRes, error) {
	if err := l.wgAdmin("making WireGuard keys")(ctx); err != nil {
		return wireguard.KeysRes{}, err
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, true)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	defer r.Close()
	t := l.wgTool()
	priv, err := wgRead(r, wgPrivFile)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	if priv != "" && !q.Rotate {
		if pub, err := wgRead(r, wgPubFile); err == nil && wireguard.ValidKey(pub) {
			return wireguard.KeysRes{PublicKey: pub}, nil
		}
		pub, err := t.PubKey(ctx, priv)
		if err != nil {
			return wireguard.KeysRes{}, err
		}
		return wireguard.KeysRes{PublicKey: pub}, wgWrite(r, wgPubFile, []byte(pub+"\n"))
	}
	priv, err = t.GenKey(ctx)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	pub, err := t.PubKey(ctx, priv)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wgWrite(r, wgPrivFile, []byte(priv+"\n")); err != nil {
		return wireguard.KeysRes{}, err
	}
	return wireguard.KeysRes{PublicKey: pub}, wgWrite(r, wgPubFile, []byte(pub+"\n"))
}

// WGPeerKeys implements wireguard.Host.
func (l *Local) WGPeerKeys(ctx context.Context, q wireguard.PeerKeysReq) (wireguard.PeerKeysRes, error) {
	if err := l.wgAdmin("enrolling a WireGuard peer")(ctx); err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, false)
	if err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	defer r.Close()
	if priv, err := wgRead(r, wgPrivFile); err != nil || priv == "" {
		return wireguard.PeerKeysRes{}, api.Errorf(api.CodeNotFound, "wireguard %q has no key on this host", q.Name)
	}
	t := l.wgTool()
	priv, err := t.GenKey(ctx)
	if err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	pub, err := t.PubKey(ctx, priv)
	if err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	psk, err := t.GenPSK(ctx)
	if err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	if err := r.MkdirAll(wgPSKDir, 0o700); err != nil {
		return wireguard.PeerKeysRes{}, api.Errorf(api.CodeInternal, "creating the preshared key directory: %v", err)
	}
	if err := wgWrite(r, pskFile(pub), []byte(psk+"\n")); err != nil {
		return wireguard.PeerKeysRes{}, err
	}
	return wireguard.PeerKeysRes{PublicKey: pub, PrivateKey: priv, PresharedKey: psk}, nil
}

// WGImport implements wireguard.Host.
func (l *Local) WGImport(ctx context.Context, q wireguard.ImportReq) (wireguard.KeysRes, error) {
	if err := l.wgAdmin("storing WireGuard keys")(ctx); err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wireguard.ValidName("name", q.Name); err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wireguard.CheckKey("private_key", q.PrivateKey); err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wireguard.CheckKey("peer_public_key", q.PeerPublicKey); err != nil {
		return wireguard.KeysRes{}, err
	}
	if q.PresharedKey != "" {
		if err := wireguard.CheckKey("preshared_key", q.PresharedKey); err != nil {
			return wireguard.KeysRes{}, err
		}
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, true)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	defer r.Close()
	if cur, err := wgRead(r, wgPrivFile); err != nil || cur != "" {
		if err == nil {
			err = api.Errorf(api.CodeAlreadyExists, "wireguard %q already has a key on this host", q.Name).
				WithHint("delete the object first, or join under another --name")
		}
		return wireguard.KeysRes{}, err
	}
	pub, err := l.wgTool().PubKey(ctx, q.PrivateKey)
	if err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wgWrite(r, wgPrivFile, []byte(q.PrivateKey+"\n")); err != nil {
		return wireguard.KeysRes{}, err
	}
	if err := wgWrite(r, wgPubFile, []byte(pub+"\n")); err != nil {
		return wireguard.KeysRes{}, err
	}
	if q.PresharedKey != "" {
		if err := r.MkdirAll(wgPSKDir, 0o700); err != nil {
			return wireguard.KeysRes{}, api.Errorf(api.CodeInternal, "creating the preshared key directory: %v", err)
		}
		if err := wgWrite(r, pskFile(q.PeerPublicKey), []byte(q.PresharedKey+"\n")); err != nil {
			return wireguard.KeysRes{}, err
		}
	}
	return wireguard.KeysRes{PublicKey: pub}, nil
}

// WGApply implements wireguard.Host.
func (l *Local) WGApply(ctx context.Context, q wireguard.ApplyReq) (wireguard.ApplyRes, error) {
	if err := l.wgAdmin("configuring a WireGuard interface")(ctx); err != nil {
		return wireguard.ApplyRes{}, err
	}
	if err := wireguard.CheckApply(q); err != nil {
		return wireguard.ApplyRes{}, err
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, false)
	if err != nil {
		return wireguard.ApplyRes{}, err
	}
	defer r.Close()
	priv, err := wgRead(r, wgPrivFile)
	if err != nil {
		return wireguard.ApplyRes{}, err
	}
	if !wireguard.ValidKey(priv) {
		return wireguard.ApplyRes{}, api.Errorf(api.CodeNotFound, "wireguard %q has no key on this host", q.Name)
	}
	pub, err := wgRead(r, wgPubFile)
	if err != nil {
		return wireguard.ApplyRes{}, err
	}
	t := l.wgTool()
	if t.Path == "" {
		return wireguard.ApplyRes{}, api.Errorf(api.CodeUnverified, "the wg program is not installed").WithHint("pkg install wireguard-tools")
	}
	record, err := wgRead(r, wgIfaceFile)
	if err != nil {
		return wireguard.ApplyRes{}, err
	}
	ifs, err := t.List(ctx)
	if err != nil {
		return wireguard.ApplyRes{}, err
	}
	find := func(n string) (ifconfig.Iface, bool) {
		for _, i := range ifs {
			if i.Name == n {
				return i, true
			}
		}
		return ifconfig.Iface{}, false
	}
	if err := l.checkWGRoutes(ctx, t, q, ifs); err != nil {
		return wireguard.ApplyRes{}, err
	}
	var res wireguard.ApplyRes
	// The object's interface was renamed in its spec: the one the helper made under the old name goes.
	if record != "" && record != q.Iface {
		if old, ok := find(record); ok && slices.Contains(old.Groups, "wg") {
			if err := t.Destroy(ctx, record); err != nil {
				return res, err
			}
			res.Changed = append(res.Changed, "destroyed "+record)
		}
		record = ""
	}
	cur, exists := find(q.Iface)
	if exists && record != q.Iface {
		return res, forbidden("interface %s exists and was not created by JailOps for wireguard %q; it is left untouched", q.Iface, q.Name)
	}
	created := false
	if !exists {
		// The record is written after the interface exists: a failed create must not leave a record that claims an
		// interface of that name which somebody else makes later. (A record that cannot be written takes the
		// interface down again.)
		if err := t.Create(ctx, q.Iface); err != nil {
			return res, err
		}
		if err := wgWrite(r, wgIfaceFile, []byte(q.Iface+"\n")); err != nil {
			_ = t.Destroy(ctx, q.Iface)
			return res, err
		}
		created = true
		res.Changed = append(res.Changed, "created "+q.Iface)
		cur = ifconfig.Iface{Name: q.Iface}
	}
	if want := render.WireGuardDesc(q.Name); cur.Description != want {
		if err := t.Describe(ctx, q.Iface, want); err != nil {
			return res, err
		}
		res.Changed = append(res.Changed, "description")
	}
	have := map[netip.Prefix]bool{}
	for _, list := range [][]netip.Prefix{cur.Inet, cur.Inet6} {
		for _, p := range list {
			if !p.Addr().IsLinkLocalUnicast() {
				have[p] = true
			}
		}
	}
	for _, p := range q.Addresses {
		if have[p] {
			delete(have, p)
			continue
		}
		if err := t.AddrAdd(ctx, q.Iface, p); err != nil && !api.IsCode(err, api.CodeAlreadyExists) {
			return res, err
		}
		res.Changed = append(res.Changed, "address "+p.String())
	}
	for p := range have {
		if err := t.AddrRemove(ctx, q.Iface, p); err != nil && !api.IsCode(err, api.CodeNotFound) {
			return res, err
		}
		res.Changed = append(res.Changed, "removed address "+p.String())
	}
	conf := wireguard.Conf{PrivateKey: priv, ListenPort: q.ListenPort}
	keep := map[string]bool{}
	for _, p := range q.Peers {
		psk, err := wgRead(r, pskFile(p.PublicKey))
		if err != nil {
			return res, err
		}
		if psk != "" && !wireguard.ValidKey(psk) {
			psk = ""
		}
		keep[pskFile(p.PublicKey)] = true
		conf.Peers = append(conf.Peers, wireguard.ConfPeer{PublicKey: p.PublicKey, PresharedKey: psk, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs, Keepalive: p.Keepalive})
	}
	dump, derr := t.Dump(ctx, q.Iface)
	if created || derr != nil || !conf.Matches(pub, dump) {
		if err := l.wgSync(ctx, r, t, q.Name, q.Iface, conf); err != nil {
			return res, err
		}
		res.Changed = append(res.Changed, "configuration")
	}
	// The preshared keys of peers that are gone go too.
	if ents, err := fs.ReadDir(r.FS(), wgPSKDir); err == nil {
		for _, e := range ents {
			if n := wgPSKDir + "/" + e.Name(); !keep[n] && strings.HasSuffix(n, ".psk") {
				_ = r.Remove(n)
			}
		}
	}
	if !slices.Contains(cur.Flags, "UP") {
		if err := t.Up(ctx, q.Iface); err != nil {
			return res, err
		}
		if !created {
			res.Changed = append(res.Changed, "up")
		}
	}
	if len(res.Changed) > 0 {
		for _, p := range q.Routes {
			if err := t.RouteAdd(ctx, q.Iface, p); err != nil {
				return res, err
			}
		}
	}
	res.PublicKey = pub
	return res, nil
}

// wgSpecial are the ranges no tunnel route may touch without admin-routes or wireguard-routes: loopback, this
// network, link-local and multicast.
var wgSpecial = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

// inside reports whether the prefix r lies within p.
func inside(r, p netip.Prefix) bool {
	return p.Addr().Is4() == r.Addr().Is4() && p.Bits() <= r.Bits() && p.Contains(r.Addr())
}

// checkWGRoutes keeps the routes of a tunnel to the networks behind it. Every route lies inside the allowed IPs of
// one of its peers. Without admin-routes (and the admin assertion), a route that is not inside a prefix of
// wireguard-routes must also be at least a /8 (IPv4) or /16 (IPv6) and stay clear of loopback, link-local and
// multicast, of the host's own addresses (the tunnel's excepted), of its default gateways and of its resolvers:
// otherwise a tunnel could take over the host's own traffic, which priv.conf did not allow.
func (l *Local) checkWGRoutes(ctx context.Context, t wgtool.Tool, q wireguard.ApplyReq, ifs []ifconfig.Iface) error {
	if len(q.Routes) == 0 {
		return nil
	}
	for _, r := range q.Routes {
		covered := false
		for _, p := range q.Peers {
			covered = covered || slices.ContainsFunc(p.AllowedIPs, func(a netip.Prefix) bool { return inside(r, a.Masked()) })
		}
		if !covered {
			return forbidden("route %s is not inside the allowed IPs of a peer of the tunnel", r)
		}
	}
	if isAdmin(ctx) && l.cfg.Admin.Routes {
		return nil
	}
	type held struct {
		addr netip.Addr
		what string
	}
	var host []held
	for _, i := range ifs {
		if i.Name == q.Iface {
			continue
		}
		for _, p := range slices.Concat(i.Inet, i.Inet6) {
			if !slices.Contains(q.Addresses, p) {
				host = append(host, held{p.Addr().WithZone(""), "an address of " + i.Name})
			}
		}
	}
	for _, g := range t.DefaultGateways(ctx) {
		host = append(host, held{g, "the default gateway"})
	}
	if b, err := os.ReadFile(l.etcPath("resolv.conf")); err == nil {
		ns, _, _ := parseResolv(string(b))
		for _, n := range ns {
			if a, err := netip.ParseAddr(n); err == nil {
				host = append(host, held{a.WithZone(""), "a resolver"})
			}
		}
	}
	for _, r := range q.Routes {
		if slices.ContainsFunc(l.cfg.WireGuardRoutes, func(p netip.Prefix) bool { return inside(r, p) }) {
			continue
		}
		hint := "; priv.conf allows it with wireguard-routes or admin-routes"
		if min := map[bool]int{true: 8, false: 16}[r.Addr().Is4()]; r.Bits() < min {
			return forbidden("route %s is wider than /%d%s", r, min, hint)
		}
		for _, s := range wgSpecial {
			if r.Overlaps(s) {
				return forbidden("route %s overlaps %s (loopback, link-local or multicast)%s", r, s, hint)
			}
		}
		for _, h := range host {
			if r.Contains(h.addr) {
				return forbidden("route %s covers %s, %s of the host%s", r, h.addr, h.what, hint)
			}
		}
	}
	return nil
}

// wgSync writes the configuration to a file of the object's directory (mode 0600), has `wg syncconf` read it, and
// removes it again. The private key is never on a command line.
func (l *Local) wgSync(ctx context.Context, r *os.Root, t wgtool.Tool, name, iface string, c wireguard.Conf) error {
	text, err := c.Render()
	if err != nil {
		return err
	}
	if err := wgWrite(r, wgConfFile, []byte(text)); err != nil {
		return err
	}
	defer func() { _ = r.Remove(wgConfFile) }()
	return t.SyncConf(ctx, iface, filepath.Join(l.cfg.WireGuardDir, name, wgConfFile))
}

// WGRename implements wireguard.Host: the key directory of an object moves to the new name inside the helper's own
// WireGuard directory, and nowhere else. A second call changes nothing.
func (l *Local) WGRename(ctx context.Context, q wireguard.RenameReq) error {
	if err := l.wgAdmin("renaming a WireGuard object")(ctx); err != nil {
		return err
	}
	for _, n := range []string{q.From, q.To} {
		if err := wireguard.ValidName("name", n); err != nil {
			return err
		}
	}
	if q.From == q.To {
		return api.Errorf(api.CodeInvalid, "the new name is the old name")
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	base, err := l.wgDir(false)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return nil // nothing was ever made on this host
		}
		return err
	}
	defer base.Close()
	_, fromErr := base.Lstat(q.From)
	_, toErr := base.Lstat(q.To)
	switch {
	case fromErr != nil && errors.Is(fromErr, fs.ErrNotExist):
		return nil // never made, or already renamed
	case fromErr != nil:
		return api.Errorf(api.CodeInternal, "reading the key directory of %s: %v", q.From, fromErr)
	case toErr == nil:
		return api.Errorf(api.CodeAlreadyExists, "wireguard %q already has keys on this host", q.To)
	}
	if err := base.Rename(q.From, q.To); err != nil {
		return api.Errorf(api.CodeInternal, "renaming the key directory of %s: %v", q.From, err)
	}
	return nil
}

// WGRemove implements wireguard.Host.
func (l *Local) WGRemove(ctx context.Context, q wireguard.RemoveReq) error {
	if err := l.wgAdmin("removing a WireGuard interface")(ctx); err != nil {
		return err
	}
	if err := wireguard.ValidName("name", q.Name); err != nil {
		return err
	}
	if q.Iface != "" {
		if err := wireguard.ValidIface(q.Iface); err != nil {
			return err
		}
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, false)
	if api.IsCode(err, api.CodeNotFound) {
		return nil // nothing was ever made for it
	}
	if err != nil {
		return err
	}
	record, err := wgRead(r, wgIfaceFile)
	r.Close()
	if err != nil {
		return err
	}
	if record != "" && (q.Iface == "" || q.Iface == record) {
		t := l.wgTool()
		ifs, err := t.List(ctx)
		if err != nil {
			return err
		}
		for _, i := range ifs {
			if i.Name == record && slices.Contains(i.Groups, "wg") {
				if err := t.Destroy(ctx, record); err != nil && !api.IsCode(err, api.CodeNotFound) {
					return err
				}
			}
		}
	}
	if !q.Purge {
		return nil
	}
	base, err := l.wgDir(false)
	if err != nil {
		return err
	}
	defer base.Close()
	if err := base.RemoveAll(q.Name); err != nil {
		return api.Errorf(api.CodeInternal, "removing the keys of %s: %v", q.Name, err)
	}
	return nil
}

// WGShow implements wireguard.Host.
func (l *Local) WGShow(ctx context.Context, q wireguard.ShowReq) (wireguard.ShowRes, error) {
	if err := wireguard.ValidName("name", q.Name); err != nil {
		return wireguard.ShowRes{}, err
	}
	if err := wireguard.ValidIface(q.Iface); err != nil {
		return wireguard.ShowRes{}, err
	}
	l.wgMu.Lock()
	defer l.wgMu.Unlock()
	r, err := l.wgObj(q.Name, false)
	if api.IsCode(err, api.CodeNotFound) {
		return wireguard.ShowRes{}, nil
	}
	if err != nil {
		return wireguard.ShowRes{}, err
	}
	record, err := wgRead(r, wgIfaceFile)
	r.Close()
	if err != nil || record != q.Iface {
		return wireguard.ShowRes{}, err
	}
	t := l.wgTool()
	ifs, err := t.List(ctx)
	if err != nil {
		return wireguard.ShowRes{}, err
	}
	var res wireguard.ShowRes
	for _, i := range ifs {
		if i.Name == q.Iface {
			res.Exists, res.Up, res.Description = true, i.Up(), i.Description
		}
	}
	if !res.Exists || t.Path == "" {
		return res, nil
	}
	d, err := t.Dump(ctx, q.Iface)
	if err != nil {
		return res, err
	}
	res.PublicKey, res.ListenPort, res.Peers = d.PublicKey, d.ListenPort, d.Peers
	return res, nil
}

// WGTools implements wireguard.Host.
func (l *Local) WGTools(ctx context.Context) (wireguard.ToolsRes, error) {
	t := l.wgTool()
	return wireguard.ToolsRes{Path: t.Path, Module: t.ModuleLoaded(ctx)}, nil
}
