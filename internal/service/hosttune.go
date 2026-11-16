package service

import (
	"context"
	"sort"
	"strings"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// Sysctl names JailOps manages itself.
const (
	// SysctlFallbackBrand makes ELF binaries without a brand run as Linux.
	// Alpine's musl binaries carry no Linux note and apk installs new ones at
	// any time, so branding files once is not enough (verified on FreeBSD 15.1).
	SysctlFallbackBrand = "kern.elf64.fallback_brand"
	fallbackBrandLinux  = "3"
	fallbackBrandOff    = "-1"
)

// SysctlOnlinkNS makes the kernel answer a unicast neighbor solicitation whose sender is not an on-link neighbour. On
// a shared IPv6 segment (proxy mode) the provider's routers probe the host's own address from their global addresses;
// with the default, 0, FreeBSD drops the probes (netstat -s -p icmp6 counts "bad neighbor solicitation messages"), the
// router marks the host unreachable for minutes at a time, and the jails behind it with it. JailOps never sets it: the
// administrator does, and the doctor says so.
const SysctlOnlinkNS = "net.inet6.icmp6.nd6_onlink_ns_rfc4861"

// onlinkNSHint is what the doctor and a network create say when SysctlOnlinkNS is off on a host with a proxy-mode
// network.
const onlinkNSHint = "the routers of a shared IPv6 segment probe the host's address from their global addresses and FreeBSD drops those solicitations as off-link, so the host (and its jails) is unreachable over IPv6 for minutes every few hours; run `sysctl " + SysctlOnlinkNS + "=1` and add `" + SysctlOnlinkNS + "=1` to /etc/sysctl.conf (JailOps never sets it)"

// hasProxyNetwork reports whether a network in IPv6 proxy mode exists.
func (s *Service) hasProxyNetwork() bool {
	nets, _ := s.netKind.list()
	for _, n := range nets {
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode == api.IPv6Proxy {
			return true
		}
	}
	return false
}

// onlinkNSWarning returns the warning of a proxy-mode network on a host whose SysctlOnlinkNS is 0, and nothing when it
// is 1 or cannot be read (the doctor reports that).
func (s *Service) onlinkNSWarning(ctx context.Context) string {
	if v, err := s.sysctl(ctx, SysctlOnlinkNS); err == nil && v == "0" {
		return SysctlOnlinkNS + " is 0: " + onlinkNSHint
	}
	return ""
}

func (s *Service) hasLinuxJail() bool {
	s.mu.RLock()
	for _, e := range s.jails {
		if e.jail.Spec.OS == api.OSLinux {
			s.mu.RUnlock()
			return true
		}
	}
	s.mu.RUnlock()
	// A Linux image build needs the same kernel state (apk and debootstrap run Linux binaries in a build jail), so a
	// build in progress counts like a jail: the first build must not wait for a jail that cannot exist before it, and
	// the host pass must not take the state away in the middle of it.
	return s.linuxBuilds.Load() > 0
}

// hostModules lists the kernel modules JailOps needs, in load order. The
// Linux ones only matter while a Linux jail exists.
func hostModules(linux bool) []string {
	m := []string{"if_epair", "pf"}
	if linux {
		m = append(m, "linux64", "linprocfs", "linsysfs", "fdescfs")
	}
	return m
}

// hostDesired is the kernel state the reconcile loop asserts: modules first,
// then the sysctls (which only exist once their module is loaded).
func (s *Service) hostDesired() reconcile.HostDesired {
	linux := s.hasLinuxJail()
	mods := hostModules(linux)
	if s.hasWireGuard() {
		mods = append(mods, wireguard.Module)
	}
	if s.hasShaping() {
		mods = append(mods, DummynetModule)
	}
	h := reconcile.HostDesired{
		Modules: mods,
		Sysctls: map[string]string{},
		Release: map[string]string{SysctlFallbackBrand: fallbackBrandOff},
	}
	if linux {
		h.Sysctls[SysctlFallbackBrand] = fallbackBrandLinux
	}
	return h
}

// doctorHost checks what the host pass manages and what only an operator can
// make persistent.
func (s *Service) doctorHost(ctx context.Context, c *checkSet) {
	want := s.hostDesired().Sysctls
	names := make([]string, 0, len(want))
	for k := range want {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		got, err := s.sysctl(ctx, n)
		switch {
		case err != nil:
			c.add("sysctl."+n, api.DoctorUnknown, err.Error(), "")
		case got == want[n]:
			c.add("sysctl."+n, api.DoctorOK, n+"="+got, "")
		case n == SysctlFallbackBrand:
			c.add("sysctl."+n, api.DoctorFail, n+" is "+got+", Linux jails need "+want[n]+" (unbranded ELF binaries such as apk must run as Linux)", "the daemon sets it at runtime; check that the helper allows it")
		default:
			c.add("sysctl."+n, api.DoctorWarn, n+" is "+got+", the configuration says "+want[n], "the daemon asserts it at runtime; check network.sysctl in jailopsd.yaml and the helper's allow-list")
		}
	}
	s.doctorForwardingPersistent(ctx, c)
}

// doctorForwardingPersistent warns when routing (or, with a proxy-mode network, the answer to off-link neighbor
// solicitations) is needed but /etc/sysctl.conf does not keep it across a reboot. The daemon never edits that file.
func (s *Service) doctorForwardingPersistent(ctx context.Context, c *checkSet) {
	nets, _ := s.netKind.list()
	need := map[string]bool{}
	for _, n := range nets {
		if n.Spec.IPv4 != nil && (n.Spec.IPv4.NAT || n.Spec.Uplink != "") {
			need["net.inet.ip.forwarding"] = true
		}
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode != api.IPv6None {
			need["net.inet6.ip6.forwarding"] = true
		}
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode == api.IPv6Proxy {
			need[SysctlOnlinkNS] = true
		}
	}
	if len(need) == 0 {
		return
	}
	if s.d.Files == nil {
		c.add("sysctl.persistent", api.DoctorUnknown, "cannot read /etc/sysctl.conf here", "")
		return
	}
	b, err := s.d.Files.ReadFile(ctx, "/etc/sysctl.conf")
	if err != nil {
		c.add("sysctl.persistent", api.DoctorUnknown, "cannot read /etc/sysctl.conf: "+err.Error(), "")
		return
	}
	set := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			set[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	// The usual FreeBSD way is rc.conf: gateway_enable and ipv6_gateway_enable set these sysctls at boot.
	if rc, err := s.d.Files.ReadFile(ctx, "/etc/rc.conf"); err == nil {
		for _, l := range strings.Split(string(rc), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
			if !ok || strings.HasPrefix(k, "#") || !strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "YES") {
				continue
			}
			switch strings.TrimSpace(k) {
			case "gateway_enable":
				set["net.inet.ip.forwarding"] = "1"
			case "ipv6_gateway_enable":
				set["net.inet6.ip6.forwarding"] = "1"
			}
		}
	}
	var missing []string
	for k := range need {
		if set[k] != "1" {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		what, hint := "routing stops working after a reboot until the daemon has run", "add "+missing[0]+"=1 to /etc/sysctl.conf, or gateway_enable=YES / ipv6_gateway_enable=YES to /etc/rc.conf (JailOps never edits them)"
		if missing[0] == SysctlOnlinkNS {
			what, hint = "after a reboot the host stops answering the probes of the routers of its shared IPv6 segment", "add "+SysctlOnlinkNS+"=1 to /etc/sysctl.conf (JailOps never edits it)"
		}
		c.add("sysctl.persistent", api.DoctorWarn, strings.Join(missing, ", ")+" is not set to 1 in /etc/sysctl.conf or /etc/rc.conf; "+what, hint)
		return
	}
	if need[SysctlOnlinkNS] {
		c.add("sysctl.persistent", api.DoctorOK, "forwarding and "+SysctlOnlinkNS+" are persistent (sysctl.conf or rc.conf)", "")
		return
	}
	c.add("sysctl.persistent", api.DoctorOK, "forwarding is persistent (sysctl.conf or rc.conf)", "")
}
