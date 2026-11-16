package api

import "time"

// WireGuardMode says which end of a tunnel an object is.
type WireGuardMode string

const (
	// WireGuardServer listens on a UDP port and enrolls peers (jailops wireguard peer add).
	WireGuardServer WireGuardMode = "server"
	// WireGuardClient connects to a server; it is made from a join token (jailops wireguard join).
	WireGuardClient WireGuardMode = "client"
)

// DefaultWireGuardPort is the listen port of a server when none is given.
const DefaultWireGuardPort = 51820

// DefaultWireGuardKeepalive is the persistent keepalive, in seconds, of a client and of the tokens a server issues.
const DefaultWireGuardKeepalive = 25

// WireGuard is a WireGuard interface the host owns: a server that peers join, or a client of a server. Private
// keys and preshared keys never appear here: they live in files of the privileged helper (mode 0600).
type WireGuard struct {
	Metadata ObjectMeta      `json:"metadata"`
	Spec     WireGuardSpec   `json:"spec"`
	Status   WireGuardStatus `json:"status"`
}

// WireGuardSpec is the desired state of a tunnel.
type WireGuardSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment string        `json:"comment,omitempty"`
	Mode    WireGuardMode `json:"mode"`
	// Interface is the interface name, default "wg-<name>" (at most 15 characters, starting with "wg").
	Interface string `json:"interface,omitempty"`
	// Address lists the addresses of the interface with their prefix (10.99.0.1/24, fd99::1/64); IPv4 and IPv6.
	Address []string `json:"address"`
	// ListenPort is the UDP port of a server (default 51820). A client leaves it empty and uses a random port.
	ListenPort int `json:"listen_port,omitempty"`
	// Endpoint is host:port. On a server it is what peers dial, written into join tokens (default the host name
	// and the listen port); on a client it is the server.
	Endpoint string `json:"endpoint,omitempty"`
	// PeerPublicKey is the server's public key (client only).
	PeerPublicKey string `json:"peer_public_key,omitempty"`
	// AllowedIPs: on a client, the prefixes routed into the tunnel; on a server, the pool peer addresses are
	// assigned from (default the subnets of Address).
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// DNS servers handed to peers in their tokens (server) or kept for reference (client); JailOps does not change
	// the host's resolver.
	DNS []string `json:"dns,omitempty"`
	// Keepalive is the persistent keepalive in seconds (a client gets 25 when it is 0).
	Keepalive int `json:"keepalive,omitempty"`
	// Peers are the enrolled peers of a server, public parts only.
	Peers []WireGuardPeer `json:"peers,omitempty"`
	// Networks are JailOps networks the peers of a server may reach: the managed pf anchor jailops/wg.<name> passes
	// traffic from the tunnel to them and nothing else. Forwarding stays the administrator's switch.
	Networks []string `json:"networks,omitempty"`
	// Down keeps the object and its keys but removes the interface.
	Down bool `json:"down,omitempty"`
}

// WireGuardPeer is one enrolled peer of a server.
type WireGuardPeer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	// AllowedIPs are the peer's tunnel addresses (one /32 and/or /128 from the pool).
	AllowedIPs []string `json:"allowed_ips"`
	// Keepalive, when set, is the persistent keepalive the server sends to this peer.
	Keepalive int       `json:"keepalive,omitempty"`
	Created   time.Time `json:"created,omitzero"`
}

// WireGuardStatus is the observed state of a tunnel.
type WireGuardStatus struct {
	// PublicKey is the interface's public key.
	PublicKey string `json:"public_key,omitempty"`
	Interface string `json:"interface,omitempty"`
	// Up says the interface exists and is up.
	Up         bool                  `json:"up,omitempty"`
	ListenPort int                   `json:"listen_port,omitempty"`
	Peers      []WireGuardPeerStatus `json:"peers,omitempty"`
	// FirewallRule is the rule the host's own pf.conf needs for a server's listen port; JailOps never edits pf.conf.
	FirewallRule string      `json:"firewall_rule,omitempty"`
	Conditions   []Condition `json:"conditions,omitempty"`
	Warnings     []string    `json:"warnings,omitempty"`
}

// WireGuardPeerStatus is what the kernel reports about one peer (wg show <if> dump).
type WireGuardPeerStatus struct {
	// Name is the peer's name in the spec ("" for a client's server).
	Name       string   `json:"name,omitempty"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// LatestHandshake is zero when no handshake happened.
	LatestHandshake time.Time `json:"latest_handshake,omitzero"`
	RxBytes         int64     `json:"rx_bytes"`
	TxBytes         int64     `json:"tx_bytes"`
	// PresharedKey says that a preshared key is set (its value is never shown).
	PresharedKey bool `json:"preshared_key,omitempty"`
}

// WireGuardPeerAdd is the body of POST /api/v1/wireguard/{name}/peers.
type WireGuardPeerAdd struct {
	Name string `json:"name"`
	// Address assigns the peer's tunnel addresses; empty takes the next free address of each family of the pool.
	Address []string `json:"address,omitempty"`
	// Keepalive goes into the peer's token (default 25).
	Keepalive int `json:"keepalive,omitempty"`
}

// WireGuardPeerCreated is the answer of a peer enrollment. Token and Config hold the peer's private key: they are
// shown once and never stored; the server keeps only the peer's public key and the preshared key.
type WireGuardPeerCreated struct {
	Peer WireGuardPeer `json:"peer"`
	// Token is "jwg1.<base64url(JSON)>", for `jailops wireguard join` on another host.
	Token string `json:"token"`
	// Config is the same in the configuration file format of the WireGuard tools (phones, laptops).
	Config  string `json:"config"`
	Warning string `json:"warning"`
}

// WireGuardJoin is the body of POST /api/v1/wireguard/join: a client object made from a token. The overrides
// replace what the token says (a different endpoint behind NAT, a test on one host).
type WireGuardJoin struct {
	Token      string   `json:"token"`
	Name       string   `json:"name,omitempty"`
	Interface  string   `json:"interface,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
	Address    []string `json:"address,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// WireGuardKeys is the answer of POST /api/v1/wireguard/{name}/rotate-keys.
type WireGuardKeys struct {
	PublicKey string `json:"public_key"`
	Warning   string `json:"warning,omitempty"`
}
