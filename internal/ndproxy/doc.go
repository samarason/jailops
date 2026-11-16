// Package ndproxy is the IPv6 neighbor discovery proxy for the
// JailOps "proxy" IPv6 mode. Routed IPv6 never depends on it.
//
// # Problem
//
// The upstream network treats jail addresses as on-link (a switched /64).
// The upstream router therefore sends neighbor solicitations for a jail
// address onto the uplink, where nobody owns it. The host, which routes to
// each jail through its own /128 host route, must answer them with its own
// MAC so that traffic for the jail arrives at the host.
//
// JailOps allocates every jail address itself, so the proxy knows which
// addresses to answer for and never has to learn them. By default it answers
// at once (ModeImmediate). ModeProbe first solicits toward the jail and
// answers only when the jail replies.
//
// # Design (RFC 4861, RFC 4443, RFC 8200)
//
//   - Parse and Build handle untagged Ethernet II + IPv6 + ICMPv6 NS/NA only.
//     802.1Q tagged frames are ignored; a VLAN uplink must be a vlan(4)
//     interface. Parse enforces hop limit 255, code 0, the pseudo-header
//     checksum, option sanity and the solicitation destination rules.
//   - Advertisements carry S (the request had a real source) and O (we
//     override), optionally R, and a target link-layer option with the
//     host's MAC. They go to the requester's link-layer address.
//   - A solicitation from the unspecified address is Duplicate Address
//     Detection. It is never answered, so a jail can run DAD.
//   - Table is a pure, clock-injected state machine (incomplete, valid,
//     stale, invalid) with bounded queues. Proxy wires it to the Capture,
//     Injector, Routes, Joiner, Prober and Clock interfaces.
//   - The BPF filter passes only ICMPv6 NS/NA with hop limit 255.
//
// # Acceptance
//
// In production the daemon does not open the capture itself: the root helper hands it a read-only, locked BPF
// descriptor and sends the advertisements (internal/priv/ndp.go, ndp_freebsd.go); the BPF code in bpf_freebsd.go is the
// in-process path of a daemon started with --dev. Results on FreeBSD 15.1 amd64, a shared switched /64 with the
// jails in a /80 (design sections 18.10 and 18.11):
//
// E1, MAC choice: met. The host's uplink MAC is advertised; packets arrive at the host and are routed by it.
//
// E2, unicast NUD without promiscuous mode: met. A 50 minute ping from another machine to a jail lost only the packets of
// the first minute, while the upstream neighbor entry went stale and was refreshed many times.
//
// E3, MLD joining: met. Solicited-node groups are joined per proxied address and multicast solicitations reach the
// capture without promiscuous mode. Not tested: MLD-snooping switches, the per-socket membership limit, rejoin after a link flap.
//
// E4, routing selection: met. /128 routes through the gateway interface carry the traffic and are removed (with the
// host's cached neighbor entry) when the jail stops. Not measured: that the host never emits a solicitation for a jail
// address on the uplink.
//
// E5, host connectivity: met for the host's own address and its SSH sessions, which were unchanged throughout; the
// proxy never answers for an address of the host. Not tested: removing and recreating the uplink while the proxy runs.
//
// Not verified: providers that filter by MAC address or limit neighbor discovery, hundreds of proxied addresses on one
// uplink.
//
// No code is copied from any existing NDP proxy.
package ndproxy
