package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"sync"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// Fake is an in-memory Host for tests. Keys are made from a counter, so runs are deterministic. Calls records the
// operations with the names they acted on, never a key.
type Fake struct {
	mu    sync.Mutex
	n     int
	objs  map[string]*fakeObj
	calls []string
	// Tools is what WGTools answers.
	Tools ToolsRes
	// Handshake, when set, is reported as the latest handshake of every peer.
	Handshake int64
}

type fakeObj struct {
	priv, pub string
	psk       map[string]string // peer public key -> preshared key
	iface     string
	exists    bool
	conf      ApplyReq
}

// NewFake returns an empty Fake whose host has the tools.
func NewFake() *Fake {
	return &Fake{objs: map[string]*fakeObj{}, Tools: ToolsRes{Path: Binaries[1], Module: true}}
}

var _ Host = (*Fake)(nil)

// FakeKey returns the n-th key the Fake hands out.
func FakeKey(n int) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("jailops-fake-wg-%d", n)))
	return base64.StdEncoding.EncodeToString(s[:])
}

// FakePublic is the public key the Fake derives from a private key.
func FakePublic(priv string) string {
	s := sha256.Sum256([]byte("public:" + priv))
	return base64.StdEncoding.EncodeToString(s[:])
}

func (f *Fake) key() string {
	f.n++
	return FakeKey(f.n)
}

func (f *Fake) note(format string, a ...any) { f.calls = append(f.calls, fmt.Sprintf(format, a...)) }

// SetTools changes what WGTools answers.
func (f *Fake) SetTools(t ToolsRes) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Tools = t
}

// Calls returns the recorded operations.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// Secrets returns every private and preshared key the Fake holds or handed out, for tests that prove none of them
// leaked.
func (f *Fake) Secrets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i := 1; i <= f.n; i++ {
		out = append(out, FakeKey(i))
	}
	for _, o := range f.objs {
		out = append(out, o.priv)
		for _, p := range o.psk {
			out = append(out, p)
		}
	}
	return out
}

// Iface reports whether the Fake holds the interface of an object and its configuration.
func (f *Fake) Iface(name string) (ApplyReq, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objs[name]
	if o == nil || !o.exists {
		return ApplyReq{}, false
	}
	return o.conf, true
}

// HasKeys reports whether the Fake holds keys for an object.
func (f *Fake) HasKeys(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objs[name]
	return o != nil && o.priv != ""
}

func (f *Fake) obj(name string) *fakeObj {
	o := f.objs[name]
	if o == nil {
		o = &fakeObj{psk: map[string]string{}}
		f.objs[name] = o
	}
	return o
}

// WGKeys implements Host.
func (f *Fake) WGKeys(_ context.Context, q KeysReq) (KeysRes, error) {
	if err := ValidName("name", q.Name); err != nil {
		return KeysRes{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("keys %s rotate=%v", q.Name, q.Rotate)
	o := f.obj(q.Name)
	if o.priv == "" || q.Rotate {
		o.priv = f.key()
		o.pub = FakePublic(o.priv)
	}
	return KeysRes{PublicKey: o.pub}, nil
}

// WGPeerKeys implements Host.
func (f *Fake) WGPeerKeys(_ context.Context, q PeerKeysReq) (PeerKeysRes, error) {
	if err := ValidName("name", q.Name); err != nil {
		return PeerKeysRes{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objs[q.Name]
	if o == nil || o.priv == "" {
		return PeerKeysRes{}, api.Errorf(api.CodeNotFound, "wireguard %q has no keys", q.Name)
	}
	f.note("peer-keys %s", q.Name)
	priv, psk := f.key(), f.key()
	pub := FakePublic(priv)
	o.psk[pub] = psk
	return PeerKeysRes{PublicKey: pub, PrivateKey: priv, PresharedKey: psk}, nil
}

// WGImport implements Host.
func (f *Fake) WGImport(_ context.Context, q ImportReq) (KeysRes, error) {
	if err := ValidName("name", q.Name); err != nil {
		return KeysRes{}, err
	}
	if err := CheckKey("private_key", q.PrivateKey); err != nil {
		return KeysRes{}, err
	}
	if err := CheckKey("peer_public_key", q.PeerPublicKey); err != nil {
		return KeysRes{}, err
	}
	if q.PresharedKey != "" {
		if err := CheckKey("preshared_key", q.PresharedKey); err != nil {
			return KeysRes{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.obj(q.Name)
	if o.priv != "" {
		return KeysRes{}, api.Errorf(api.CodeAlreadyExists, "wireguard %q already has keys", q.Name)
	}
	f.note("import %s", q.Name)
	o.priv, o.pub = q.PrivateKey, FakePublic(q.PrivateKey)
	if q.PresharedKey != "" {
		o.psk[q.PeerPublicKey] = q.PresharedKey
	}
	return KeysRes{PublicKey: o.pub}, nil
}

// WGApply implements Host.
func (f *Fake) WGApply(_ context.Context, q ApplyReq) (ApplyRes, error) {
	if err := CheckApply(q); err != nil {
		return ApplyRes{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objs[q.Name]
	if o == nil || o.priv == "" {
		return ApplyRes{}, api.Errorf(api.CodeNotFound, "wireguard %q has no keys", q.Name)
	}
	for n, x := range f.objs {
		if n != q.Name && x.exists && x.iface == q.Iface {
			return ApplyRes{}, api.Errorf(api.CodeForbidden, "interface %s exists and was not created for wireguard %q", q.Iface, q.Name)
		}
	}
	var res ApplyRes
	if !o.exists || o.iface != q.Iface {
		res.Changed = append(res.Changed, "created "+q.Iface)
	} else if !applyEqual(o.conf, q) {
		res.Changed = append(res.Changed, "configuration")
	}
	if len(res.Changed) > 0 {
		f.note("apply %s %s", q.Name, q.Iface)
	}
	o.exists, o.iface, o.conf = true, q.Iface, q
	for k := range o.psk {
		if !slices.ContainsFunc(q.Peers, func(p PeerConf) bool { return p.PublicKey == k }) {
			delete(o.psk, k)
		}
	}
	res.PublicKey = o.pub
	return res, nil
}

func applyEqual(a, b ApplyReq) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

// WGRename implements Host.
func (f *Fake) WGRename(_ context.Context, q RenameReq) error {
	for _, n := range []string{q.From, q.To} {
		if err := ValidName("name", n); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("rename %s %s", q.From, q.To)
	o := f.objs[q.From]
	if o == nil {
		return nil
	}
	if f.objs[q.To] != nil {
		return api.Errorf(api.CodeAlreadyExists, "wireguard %q already has keys on this host", q.To)
	}
	f.objs[q.To] = o
	delete(f.objs, q.From)
	return nil
}

// WGRemove implements Host.
func (f *Fake) WGRemove(_ context.Context, q RemoveReq) error {
	if err := ValidName("name", q.Name); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("remove %s %s purge=%v", q.Name, q.Iface, q.Purge)
	o := f.objs[q.Name]
	if o == nil {
		return nil
	}
	o.exists = false
	if q.Purge {
		delete(f.objs, q.Name)
	}
	return nil
}

// WGShow implements Host.
func (f *Fake) WGShow(_ context.Context, q ShowReq) (ShowRes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.objs[q.Name]
	if o == nil || !o.exists || o.iface != q.Iface {
		return ShowRes{}, nil
	}
	r := ShowRes{Exists: true, Up: true, Description: render.WireGuardDesc(q.Name), PublicKey: o.pub, ListenPort: o.conf.ListenPort}
	if r.ListenPort == 0 {
		r.ListenPort = 40000
	}
	for _, p := range o.conf.Peers {
		dp := DumpPeer{PublicKey: p.PublicKey, Endpoint: p.Endpoint, Keepalive: p.Keepalive, PresharedKey: o.psk[p.PublicKey] != ""}
		for _, a := range p.AllowedIPs {
			dp.AllowedIPs = append(dp.AllowedIPs, a.Masked().String())
		}
		if f.Handshake > 0 {
			dp.LatestHandshake, dp.RxBytes, dp.TxBytes = f.Handshake, 1024, 2048
		}
		r.Peers = append(r.Peers, dp)
	}
	return r, nil
}

// WGTools implements Host.
func (f *Fake) WGTools(context.Context) (ToolsRes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Tools, nil
}
