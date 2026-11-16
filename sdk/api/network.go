package api

// Network is an address range with an uplink policy and deterministic address allocation. It has no kernel object:
// every jail attachment is its own routed link (an epair whose host end carries the gateway address), and the host
// is the router. jailops creates the epair interfaces, configures addresses and routes inside the jail, and installs
// the host-side addresses and routes. There is no DHCP, no router advertisement and no SLAAC.
type Network struct {
	Metadata ObjectMeta    `json:"metadata"`
	Spec     NetworkSpec   `json:"spec"`
	Status   NetworkStatus `json:"status"`
}

// NetworkSpec is the desired state of a network.
type NetworkSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment string `json:"comment,omitempty"`
	// Uplink is the physical interface used for NAT or routing. In IPv6 proxy mode it must be a plain interface (not a
	// member of a bridge).
	Uplink string   `json:"uplink,omitempty"`
	IPv4   *IPv4Net `json:"ipv4,omitempty"`
	IPv6   *IPv6Net `json:"ipv6,omitempty"`
	DNS    []string `json:"dns,omitempty"`
	// MTU of the epair ends of the network's jails; zero keeps the default.
	MTU int `json:"mtu,omitempty"`
}

// IPv4Net configures IPv4 on a network.
type IPv4Net struct {
	Subnet string `json:"subnet"` // 10.20.0.0/24
	// Gateway is an address of the host inside the subnet. It is configured as a /32 on the host end of every jail's
	// epair, so each jail finds it on its own link; it is also the address jails ask for DNS when the host resolves
	// only through loopback.
	Gateway string `json:"gateway"`
	// Range is the inclusive span jailops may allocate from, "a-b".
	Range string `json:"range"`
	// Exclude removes spans or single addresses from the range.
	Exclude []string `json:"exclude,omitempty"`
	// NAT masquerades traffic leaving through the uplink.
	NAT bool `json:"nat,omitempty"`
}

// IPv6Mode selects how jail addresses reach the upstream network.
type IPv6Mode string

const (
	// IPv6Routed: the upstream routes a prefix to the host. Unallocated addresses of the prefix are rejected, and no
	// NDP proxy is involved.
	IPv6Routed IPv6Mode = "routed"
	// IPv6Proxy: the upstream treats the jail addresses as on-link. jailops
	// answers neighbor solicitations for allocated addresses on the uplink
	// and routes each address to its jail with a /128 host route.
	IPv6Proxy IPv6Mode = "proxy"
	IPv6None  IPv6Mode = "none"
)

// IPv6Net configures IPv6 on a network.
type IPv6Net struct {
	Mode    IPv6Mode `json:"mode"`
	Subnet  string   `json:"subnet"`
	Range   string   `json:"range"`
	Exclude []string `json:"exclude,omitempty"`
}

// NetworkStatus is the observed state of a network on one host.
type NetworkStatus struct {
	// Links are the host ends of the epairs of the jails that run on the network.
	Links     []string `json:"links,omitempty"`
	Allocated int      `json:"allocated,omitempty"`
	Free      int      `json:"free,omitempty"`
	// Orphans are epair interfaces without a jail.
	Orphans    []string    `json:"orphans,omitempty"`
	Conditions []Condition `json:"conditions,omitempty"`
	// Warnings are set in the answer of a create or an update only: what the host lacks for
	// this network (a sysctl the administrator has to set, a resolver that has to listen on the gateway). They are
	// never stored; jailops doctor reports the same things.
	Warnings []string `json:"warnings,omitempty"`
	// DNS is what the jails of the network get in their resolv.conf, worked out when the network is read.
	DNS *NetworkDNS `json:"dns,omitempty"`
}

// DNSSource says where the nameservers of a jail's resolv.conf come from.
type DNSSource string

const (
	// DNSFromNetwork: the network's dns.
	DNSFromNetwork DNSSource = "network"
	// DNSFromHost: the host's own nameservers in /etc/resolv.conf (those a jail can reach: not loopback, not link-local).
	DNSFromHost DNSSource = "host"
	// DNSFromGateway: the host resolves only through loopback (a local cache), so jails ask the network's gateway
	// address; that answers only when the administrator lets the cache listen there.
	DNSFromGateway DNSSource = "gateway"
	// DNSNone: no nameserver could be worked out (the host's resolv.conf cannot be read, or the network has no
	// gateway address a jail could use).
	DNSNone DNSSource = "none"
)

// NetworkDNS is the resolver configuration the jails of a network get.
type NetworkDNS struct {
	Source      DNSSource `json:"source"`
	Nameservers []string  `json:"nameservers,omitempty"`
	// Advice is what the administrator has to do on the host so that the gateway answers (source gateway only).
	Advice string `json:"advice,omitempty"`
	// Suffix is the zone under which the jails have names (NAME.PROJECT.<suffix>) when the host's resolver gives
	// them; Forward is where that resolver sends every other name, and Recurse says it resolves them itself.
	Suffix  string   `json:"suffix,omitempty"`
	Forward []string `json:"forward,omitempty"`
	Recurse bool     `json:"recurse,omitempty"`
	// Updated names the running jails whose resolv.conf an update rewrote at once (in the answer of an update only);
	// NotUpdated the running jails it could not rewrite, with the reason. Stopped jails get it when they start.
	Updated    []string `json:"updated,omitempty"`
	NotUpdated []string `json:"not_updated,omitempty"`
}

// Lease is one allocated address. Leases are derived from jail specs and are
// reported for inspection; the jail spec is the source of truth.
type Lease struct {
	Address string `json:"address"`
	Jail    string `json:"jail"`
	Network string `json:"network"`
}
