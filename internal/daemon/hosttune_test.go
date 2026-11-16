package daemon_test

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk/api"
)

func TestLinuxJailManagesTheFallbackBrandAndModules(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	// Without a Linux jail the brand stays as it is and no Linux module is wanted.
	e.D.Reconciler().Pass(ctx)
	if v := e.SysctlValue("kern.elf64.fallback_brand"); v != "-1" {
		t.Fatalf("the brand was set without a Linux jail: %s", v)
	}
	e.SeedLinux()
	// The image build sets the brand for its own jail. Once the build is over nothing needs it, and the reconcile loop
	// (which runs beside this test, kicked by the finished build) may give it back at any moment: so ask whether it was
	// ever set, not what it is now.
	hist := e.SysctlHistory("kern.elf64.fallback_brand")
	set := false
	for _, v := range hist {
		set = set || v == "3"
	}
	if !set {
		t.Fatalf("the Alpine build did not set the brand: %v", hist)
	}
	e.SetSysctl("kern.elf64.fallback_brand", "-1")
	op, err := e.Admin.Jails().Create(ctx, dtest.AlpineJail("alp1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(ctx)
	if v := e.SysctlValue("kern.elf64.fallback_brand"); v != "3" {
		t.Fatalf("brand %s", v)
	}
	rep, _ := e.Admin.Doctor(ctx)
	for _, c := range rep.Checks {
		if c.Name == "sysctl.kern.elf64.fallback_brand" && c.Status != api.DoctorOK {
			t.Fatalf("%+v", c)
		}
	}
	// the helper never touched /etc/sysctl.conf
	if _, ok := e.Files.Data["/etc/sysctl.conf"]; ok {
		t.Error("the daemon wrote /etc/sysctl.conf")
	}
	// The jail's mounts and the compat directory.
	if _, ok := e.Files.Dirs["/jailops/projects/alpha/jails/alp1/root/dev/shm"]; !ok {
		t.Errorf("no dev/shm in the root: %v", e.Files.Dirs)
	}
	// The last Linux jail goes away: the brand goes back.
	del, err := e.Admin.Jails().Delete(ctx, "alp1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := del.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(ctx)
	if v := e.SysctlValue("kern.elf64.fallback_brand"); v != "-1" {
		t.Fatalf("brand %s after the last Linux jail", v)
	}
}

func TestTheNetworkSectionIsNotAKey(t *testing.T) {
	for _, bad := range []string{"network:\n  sysctl:\n    net.inet.ip.forwarding: 1\n", "network:\n  pf_placement: host\n"} {
		if _, err := daemon.Decode(strings.NewReader("pool: tank\n" + bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestDoctorWarnsWhenForwardingIsNotPersistent(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	if _, err := e.Admin.Networks().Patch(ctx, "lan", map[string]any{"spec": map[string]any{"uplink": "em0"}}, ""); err != nil {
		t.Fatal(err)
	}
	check := func() api.DoctorCheck {
		rep, _ := e.Admin.Doctor(ctx)
		for _, c := range rep.Checks {
			if c.Name == "sysctl.persistent" {
				return c
			}
		}
		return api.DoctorCheck{}
	}
	e.Files.Data["/etc/sysctl.conf"] = []byte("# nothing\n")
	if c := check(); c.Status != api.DoctorWarn || !strings.Contains(c.Hint, "never edits") {
		t.Fatalf("%+v", c)
	}
	e.Files.Data["/etc/sysctl.conf"] = []byte("net.inet.ip.forwarding=1\n")
	if c := check(); c.Status != api.DoctorOK {
		t.Fatalf("%+v", c)
	}
	// the FreeBSD way, rc.conf, counts as well
	e.Files.Data["/etc/sysctl.conf"] = []byte("# nothing\n")
	e.Files.Data["/etc/rc.conf"] = []byte("gateway_enable=\"YES\"\n")
	if c := check(); c.Status != api.DoctorOK {
		t.Fatalf("gateway_enable in rc.conf was not accepted: %+v", c)
	}
	e.Files.Data["/etc/rc.conf"] = []byte("gateway_enable=\"NO\"\n")
	if c := check(); c.Status != api.DoctorWarn {
		t.Fatalf("%+v", c)
	}
}

// proxyNet is a network in IPv6 proxy mode (a shared switched segment behind em0).
func proxyNet() api.Network {
	return api.Network{Metadata: api.ObjectMeta{Name: "sw"}, Spec: api.NetworkSpec{Uplink: "em0",
		IPv6: &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: "2001:db8:1:2:100::/80", Range: "2001:db8:1:2:100::10-2001:db8:1:2:100::ff"}}}
}

func doctorCheck(t *testing.T, e *dtest.Env, name string) api.DoctorCheck {
	t.Helper()
	rep, err := e.Admin.Doctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %s in %+v", name, rep.Checks)
	return api.DoctorCheck{}
}

// The routers of a shared IPv6 segment probe the host from off-link addresses; FreeBSD drops the probes unless
// net.inet6.icmp6.nd6_onlink_ns_rfc4861 is 1. The doctor asks for it once a proxy-mode network exists, and for it
// to be persistent; JailOps never sets it.
func TestDoctorChecksOnlinkNSForProxyNetworks(t *testing.T) {
	const oid = "net.inet6.icmp6.nd6_onlink_ns_rfc4861"
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	e.SetSysctl(oid, "0")
	// No proxy network: the value does not matter.
	if c := doctorCheck(t, e, "sysctl."+oid); c.Status != api.DoctorOK || !strings.Contains(c.Message, "not needed now") {
		t.Fatalf("%+v", c)
	}
	if _, err := e.Admin.Networks().Create(ctx, proxyNet()); err != nil {
		t.Fatal(err)
	}
	c := doctorCheck(t, e, "sysctl."+oid)
	if c.Status != api.DoctorWarn || !strings.Contains(c.Hint, "sysctl "+oid+"=1") || !strings.Contains(c.Hint, "/etc/sysctl.conf") || !strings.Contains(c.Hint, "unreachable") {
		t.Fatalf("%+v", c)
	}
	e.SetSysctl(oid, "1")
	if c := doctorCheck(t, e, "sysctl."+oid); c.Status != api.DoctorOK || c.Message != oid+"=1" {
		t.Fatalf("%+v", c)
	}
	// Persistence: forwarding alone is not enough once a proxy network exists.
	e.Files.Data["/etc/rc.conf"] = []byte("ipv6_gateway_enable=\"YES\"\n")
	e.Files.Data["/etc/sysctl.conf"] = []byte("# nothing\n")
	c = doctorCheck(t, e, "sysctl.persistent")
	if c.Status != api.DoctorWarn || !strings.Contains(c.Message, oid) || strings.Contains(c.Message, "forwarding") || !strings.Contains(c.Hint, oid+"=1 to /etc/sysctl.conf") {
		t.Fatalf("%+v", c)
	}
	e.Files.Data["/etc/sysctl.conf"] = []byte(oid + "=1\n")
	if c := doctorCheck(t, e, "sysctl.persistent"); c.Status != api.DoctorOK || !strings.Contains(c.Message, oid) {
		t.Fatalf("%+v", c)
	}
}

// Creating a proxy-mode network on a host whose sysctl is 0 says so in the answer; a routed network and a host
// with the sysctl on say nothing.
func TestCreatingAProxyNetworkWarnsAboutOnlinkNS(t *testing.T) {
	const oid = "net.inet6.icmp6.nd6_onlink_ns_rfc4861"
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	e.SetSysctl(oid, "0")
	n, err := e.Admin.Networks().Create(ctx, proxyNet())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Status.Warnings) != 1 || !strings.Contains(n.Status.Warnings[0], "sysctl "+oid+"=1") || !strings.Contains(n.Status.Warnings[0], "/etc/sysctl.conf") {
		t.Fatalf("%+v", n.Status.Warnings)
	}
	// The warning is for the answer of the create only, never stored (a network is visible to the host-wide client
	// before a project is granted it).
	if got, err := e.Global().Networks().Get(ctx, "sw"); err != nil || len(got.Status.Warnings) != 0 {
		t.Fatalf("%v %+v", err, got.Status.Warnings)
	}
	routed := api.Network{Metadata: api.ObjectMeta{Name: "rt"}, Spec: api.NetworkSpec{
		IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: "2001:db8:9:1::/80", Range: "2001:db8:9:1::10-2001:db8:9:1::ff"}}}
	if n, err := e.Admin.Networks().Create(ctx, routed); err != nil || len(n.Status.Warnings) != 0 {
		t.Fatalf("%v %+v", err, n.Status.Warnings)
	}
	e.SetSysctl(oid, "1")
	p := proxyNet()
	p.Metadata.Name, p.Spec.IPv6.Subnet, p.Spec.IPv6.Range = "sw2", "2001:db8:1:2:200::/80", "2001:db8:1:2:200::10-2001:db8:1:2:200::ff"
	if n, err := e.Admin.Networks().Create(ctx, p); err != nil || len(n.Status.Warnings) != 0 {
		t.Fatalf("%v %+v", err, n.Status.Warnings)
	}
}
