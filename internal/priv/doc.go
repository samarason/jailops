// Package priv implements the privileged helper of JailOps: a protocol, a
// server (jailops-priv), a client (used by jailopsd) and an in-process
// implementation (Local) that all share one set of validation rules.
//
// jailopsd runs unprivileged. Everything that needs root is a typed operation
// from a fixed list (see ops.go). There is no operation that runs a command
// the caller names, and no shell. Every argument is validated again inside
// the helper, because the helper must not trust its client.
//
// Layers:
//
//	Local   validating, in-process implementation of the sys interfaces
//	Server  length-prefixed JSON protocol over a unix socket, peer checked
//	Client  the same interfaces, implemented as calls to a Server
//
// The client adapters return values that implement internal/sys/zfs.Client,
// jailos.Jails, pfctl.Client, ifconfig.Client and run.Runner, so code written
// against those interfaces is unchanged whether it runs as root in development
// (Local) or through the helper in production (Client).
//
// Storage. The helper serves a set of storage roots (datasets). A root must
// exist on an imported pool and carry jailops:managed=on locally; every ZFS
// name, mount path and file path is checked against that set and a name must
// live under exactly one root. Roots are fixed in priv.conf (storage-root) or
// registered at run time (storage.register, admin assertion) and persisted
// atomically in a root-owned 0600 file that is reread at start and on SIGHUP.
// The layout below a root is projects/<project>/jails/<name> and
// images/<image>/g<N>; a jail is known to the host by <project>--<name>.
//
// IPv6 neighbor discovery. The built-in proxy needs two privileged things, and the helper offers them as two typed
// operations (ndp.go): ndp.open hands the daemon a read-only, locked BPF capture of an approved uplink that delivers
// neighbor discovery frames only, and ndp.answer sends one Neighbor Advertisement that the helper builds itself.
// Both work only for the uplinks and subnets of the networks in IPv6 proxy mode that JailOps has stored; the daemon
// cannot widen that. The /128 host routes go through the ordinary network steps of the reconcile loop. Joining the
// solicited-node multicast group of an address needs no helper operation: it is an ordinary IPV6_JOIN_GROUP on a
// UDP socket the daemon opens itself (unprivileged on FreeBSD; checked on FreeBSD 15.1).
//
// Host management (host.go, docs/appliance.md). The identity module's four operations read the host name, resolvers
// and NTP settings, and, for an admin and only when priv.conf lists the module (host-manage), render and write them
// from validated fields, keeping copies of the files they change in host-dir, a directory of root's own.
//
// Verified on FreeBSD 15.1 (design section 18): peer checks, descriptor passing of the neighbor discovery capture,
// and the commands the Local implementation runs; what is not yet verified is listed in section 16.
package priv
