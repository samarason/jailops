// Package reconcile is the loop of design section 7: observe the system,
// render the desired artifacts (pure functions in internal/render), compute a
// plan, apply it under per-resource locks and verify. Failures become status
// conditions; the loop never edits a spec.
//
// Everything is driven by an injected clock and by the interfaces of
// internal/sys, so the whole loop runs against fakes.
package reconcile

import (
	"context"
	"time"

	"jailops.net/jailops/internal/ndproxy"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// Desired is the rendered desired state of the host. It holds no observed
// data. The service builds it from the spec objects.
type Desired struct {
	Networks []NetworkDesired
	Jails    []JailDesired
	// WireGuard are the tunnels; the loop recreates their interfaces (after a reboot) and keeps them configured.
	WireGuard []WireGuardDesired
	// Host is the kernel state JailOps manages: modules, then sysctls.
	Host HostDesired
	// Pipes are the dummynet pipes of the bandwidth limits that jails have: the loop configures them before it loads
	// the anchors that send traffic into them, and deletes the pipes of JailOps's range that nobody wants.
	Pipes []PipeDesired
}

// PipeDesired is one dummynet pipe: its number (in JailOps's range, render.PipeBase) and its bandwidth in bits per
// second, 0 for unlimited.
type PipeDesired struct {
	Number int
	Rate   uint64
}

// HostDesired is the kernel state the loop asserts before it touches
// networks. Modules are loaded first (a sysctl of a module that is not
// loaded does not exist); Sysctls are then set at runtime through the helper
// and never written to /etc/sysctl.conf.
type HostDesired struct {
	// Modules to load, in order (kldstat -m, then kldload).
	Modules []string
	// Sysctls maps a name to the value to assert.
	Sysctls map[string]string
	// Release maps a sysctl JailOps set earlier to the value it returns to
	// once nothing needs it (kern.elf64.fallback_brand goes back to -1 when
	// the last Linux jail is gone).
	Release map[string]string
}

// NetworkDesired is one managed network.
type NetworkDesired struct {
	Name string
	ID   string
	Spec api.NetworkSpec
	// Steps is render.NetworkPlan for the network.
	Steps []render.Step
	// Anchors maps an anchor name used by Steps (OpLoadAnchor) to its ruleset.
	Anchors map[string]string
	// Allocated and Free come from IPAM.
	Allocated, Free int
	// Problem is set when the network could not be rendered; the loop reports
	// it as a condition and does nothing else for the network.
	Problem string
}

// JailDesired is one jail as far as reconcile cares.
type JailDesired struct {
	// Name is the project-qualified jail key: the OS-level jail name, which
	// can never collide across projects. Boot.Depends holds keys as well.
	Name string
	ID   string
	// Project is the project of the jail.
	Project string
	Boot    api.BootPolicy
	// Attach holds, per network attachment, the host-phase steps of
	// render.AttachPlan.
	Attach [][]render.Step
	// Networks is the network of each attachment.
	Networks []string
	// Epairs are the host-side interface names the jail should have while it runs.
	Epairs []string
	// JailSide are the jail-phase description steps of the jail ends of the epairs: what ifconfig shows inside the
	// jail's vnet. The loop checks them once per start of the jail (per JID) and repairs a missing or different one.
	JailSide []render.Step
	// AnchorName and Ruleset are the PF anchor of the jail; Ruleset is empty
	// when the jail has no firewall.
	AnchorName string
	Ruleset    string
	// Anchor is the structured form of Ruleset, made by the same code: the rules in the order they are loaded, each
	// with what it matches. The firewall test walks it. It is nil when Ruleset is empty.
	Anchor *render.Anchor
	// ParentAnchors maps the parent anchors of AnchorName ("jailops/<project>")
	// to the ruleset that makes them evaluate their children.
	// UNVERIFIED: nested anchors on FreeBSD.
	ParentAnchors map[string]string
	// Proxy lists IPv6 addresses to answer for while the jail runs.
	Proxy []ProxyAddr
	// Problem is set when the jail's configuration could not be rendered.
	Problem string
}

// WireGuardDesired is one WireGuard tunnel.
type WireGuardDesired struct {
	Name  string
	Iface string
	// Down: the interface must not exist (the keys stay).
	Down bool
	// Apply is what the helper configures (public parts only).
	Apply wireguard.ApplyReq
	// Anchor and Ruleset are the pf anchor of a server (jailops/wg.<name>); an empty ruleset flushes it.
	Anchor  string
	Ruleset string
	// Problem is set when the tunnel could not be rendered.
	Problem string
}

// ProxyAddr is one address of an IPv6 proxy mode network.
type ProxyAddr struct {
	Addr string
	// Iface is the host end of the jail's epair: the interface the host route of the address leaves through.
	Iface  string
	Uplink string
}

// Source supplies desired state.
type Source interface {
	Desired(ctx context.Context) (Desired, error)
}

// Sink receives observed status. Implementations keep it in memory; it is
// never written to the spec.
type Sink interface {
	NetworkStatus(name string, st api.NetworkStatus)
	JailStatus(name string, conditions []api.Condition, drift []string)
}

// Actions are the effects the loop needs from the service layer.
type Actions interface {
	// TryLock takes the named resource locks or fails with api.CodeBusy.
	TryLock(holder string, keys ...string) (func(), error)
	// IsLocked reports whether a lock is held.
	IsLocked(key string) bool
	// StartJail starts a jail the way an operator's start does.
	StartJail(ctx context.Context, name string) error
}

// Clock is the injected time source.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// SystemClock is the real clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// After implements Clock.
func (SystemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// NDP is the part of the neighbor discovery proxy the loop drives.
type NDP interface {
	Sync(ctx context.Context, entries []ndproxy.Entry) error
	Run(ctx context.Context) error
	// Status says whether the capture is open (and why not) and carries the counters.
	Status() ndproxy.Status
	// Close releases what the proxy holds outside itself; it is called once the proxy has stopped.
	Close() error
}

// NDPFactory builds a proxy for one uplink. It is only called when proxy mode
// is enabled and a network needs it.
type NDPFactory func(uplink string) (NDP, error)

// Condition types reported by the loop.
const (
	CondReady = "Ready"
	CondDrift = "InSync"
	CondBoot  = "Autostart"
	CondProxy = "NDPProxy"
	// CondProxyFlood is False while the proxy dropped solicitations over its limits in the last hour.
	CondProxyFlood = "NDPFlood"
	CondNetwork    = "Network"
)

func cond(t string, ok bool, reason, msg string, now time.Time) api.Condition {
	st := api.ConditionTrue
	if !ok {
		st = api.ConditionFalse
	}
	return api.Condition{Type: t, Status: st, Reason: reason, Message: msg, Since: now.UTC()}
}
