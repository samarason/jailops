package wireguard

import (
	"context"
	"net/netip"
	"strconv"
)

// Host is what the privileged helper offers for WireGuard. Every operation names the object; the helper keeps one
// directory per object below its own WireGuard directory (root only, mode 0700) with the interface's private key,
// the preshared keys of its peers and the name of the interface it created. The daemon never reads that directory.
type Host interface {
	// WGKeys makes sure the object has a private key (generated with `wg genkey` when there is none, or a new one
	// with Rotate) and returns the public key.
	WGKeys(ctx context.Context, q KeysReq) (KeysRes, error)
	// WGPeerKeys enrolls a peer of a server: a new key pair and preshared key. The preshared key is stored for the
	// peer's public key; the private key is returned for the peer's token and forgotten.
	WGPeerKeys(ctx context.Context, q PeerKeysReq) (PeerKeysRes, error)
	// WGImport stores the private key and the preshared key of a client made from a join token.
	WGImport(ctx context.Context, q ImportReq) (KeysRes, error)
	// WGApply creates the interface if needed (and records that the helper created it), sets its description,
	// addresses, routes and configuration, and brings it up. It changes only what differs.
	WGApply(ctx context.Context, q ApplyReq) (ApplyRes, error)
	// WGRemove destroys the interface the helper created for the object; Purge also removes its keys.
	WGRemove(ctx context.Context, q RemoveReq) error
	// WGRename gives the keys directory of an object the new name. The interface keeps its name; its description
	// follows with the next apply. Nothing is done for an object that never had keys, and a second call is a no-op.
	WGRename(ctx context.Context, q RenameReq) error
	// WGShow reports the interface and its peers, public parts only.
	WGShow(ctx context.Context, q ShowReq) (ShowRes, error)
	// WGTools says where the wg program is and whether the if_wg module is loaded.
	WGTools(ctx context.Context) (ToolsRes, error)
}

// RenameReq names the object before and after.
type RenameReq struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// KeysReq names an object; Rotate replaces its key.
type KeysReq struct {
	Name   string `json:"name"`
	Rotate bool   `json:"rotate,omitempty"`
}

// KeysRes carries a public key.
type KeysRes struct {
	PublicKey string `json:"public_key"`
}

// PeerKeysReq names the server a peer is enrolled at.
type PeerKeysReq struct {
	Name string `json:"name"`
}

// PeerKeysRes is a new peer's key pair and preshared key. PrivateKey and PresharedKey are secrets.
type PeerKeysRes struct {
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key"`
	PresharedKey string `json:"preshared_key"`
}

// ImportReq stores the keys of a joined client. PrivateKey and PresharedKey are secrets.
type ImportReq struct {
	Name          string `json:"name"`
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	PresharedKey  string `json:"preshared_key,omitempty"`
}

// ApplyReq is the public part of an interface's configuration. The helper adds the private key and the preshared
// keys from its files.
type ApplyReq struct {
	Name  string `json:"name"`
	Iface string `json:"iface"`
	// Addresses of the interface, with their prefix.
	Addresses  []netip.Prefix `json:"addresses"`
	ListenPort int            `json:"listen_port,omitempty"`
	// Routes are routed into the tunnel (a client's allowed IPs).
	Routes []netip.Prefix `json:"routes,omitempty"`
	Peers  []PeerConf     `json:"peers,omitempty"`
}

// PeerConf is one peer, public parts only.
type PeerConf struct {
	PublicKey  string         `json:"public_key"`
	AllowedIPs []netip.Prefix `json:"allowed_ips"`
	Endpoint   string         `json:"endpoint,omitempty"`
	Keepalive  int            `json:"keepalive,omitempty"`
}

// ApplyRes says what changed ("created wg-office", "configuration", "address 10.99.0.1/24").
type ApplyRes struct {
	Changed   []string `json:"changed,omitempty"`
	PublicKey string   `json:"public_key,omitempty"`
}

// RemoveReq names the interface of an object; Purge removes the keys too.
type RemoveReq struct {
	Name  string `json:"name"`
	Iface string `json:"iface"`
	Purge bool   `json:"purge,omitempty"`
}

// ShowReq names the interface of an object.
type ShowReq struct {
	Name  string `json:"name"`
	Iface string `json:"iface"`
}

// ShowRes is the state of an interface, public parts only.
type ShowRes struct {
	// Exists says the interface exists and is the one the helper created for the object.
	Exists      bool       `json:"exists"`
	Up          bool       `json:"up,omitempty"`
	Description string     `json:"description,omitempty"`
	PublicKey   string     `json:"public_key,omitempty"`
	ListenPort  int        `json:"listen_port,omitempty"`
	Peers       []DumpPeer `json:"peers,omitempty"`
}

// ToolsRes says what the host has: the wg program ("" when neither /usr/bin/wg nor /usr/local/bin/wg is there)
// and whether if_wg is loaded.
type ToolsRes struct {
	Path   string `json:"path,omitempty"`
	Module bool   `json:"module"`
}

// Binaries are the places the wg program is looked for, in order: the base system, then the package.
var Binaries = []string{"/usr/bin/wg", "/usr/local/bin/wg"}

// Module is the kernel module of WireGuard interfaces.
const Module = "if_wg"

// Anchor returns the pf anchor of a tunnel: jailops/wg.<name> (a dot, like the anchors of networks, so it never
// meets the anchor of a project).
func Anchor(name string) string { return "jailops/wg." + name }

// FirewallRule is the line the host's own pf.conf needs so that peers reach a server's listen port ($ext_if being
// the macro of the interface the peers come in on). JailOps never edits pf.conf.
func FirewallRule(port int) string {
	return "pass in on $ext_if proto udp to port " + strconv.Itoa(port)
}

// CheckApply validates an apply request (the helper does the same before it acts).
func CheckApply(q ApplyReq) error {
	if err := ValidName("name", q.Name); err != nil {
		return err
	}
	if err := ValidIface(q.Iface); err != nil {
		return err
	}
	if len(q.Addresses) == 0 || len(q.Addresses) > 2 {
		return invalid("addresses", "a tunnel has one or two addresses")
	}
	for _, a := range q.Addresses {
		if !a.IsValid() || a.Addr().Zone() != "" || a.Addr().IsLoopback() || a.Addr().IsMulticast() || a.Addr().IsUnspecified() || a.Addr().IsLinkLocalUnicast() {
			return invalid("addresses", "address %s cannot be used for a tunnel", a)
		}
	}
	if q.ListenPort < 0 || q.ListenPort > 65535 {
		return invalid("listen_port", "listen port must be 0 to 65535")
	}
	if len(q.Routes) > MaxPrefixes {
		return invalid("routes", "too many routes")
	}
	for _, r := range q.Routes {
		if !r.IsValid() || r.Bits() == 0 || r != r.Masked() || r.Addr().Zone() != "" {
			return invalid("routes", "route %s is not a network the tunnel may take (no default route)", r)
		}
	}
	c := Conf{PrivateKey: FakeKey(0), ListenPort: q.ListenPort}
	for _, p := range q.Peers {
		c.Peers = append(c.Peers, ConfPeer{PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs, Keepalive: p.Keepalive})
	}
	if err := c.Check(); err != nil {
		return err
	}
	for _, p := range q.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() == 0 {
				return invalid("allowed_ips", "a peer cannot take the default route (%s)", a)
			}
		}
	}
	return nil
}
