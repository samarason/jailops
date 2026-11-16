package priv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

const hookUUID = "5f0a1c3e-9a7b-4c1d-8e2f-0123456789ab"

type hookEnv struct {
	*env
	host, jail string
	// jailErr, when set, is the stderr of every host-side ifconfig -j and
	// route -j the hook runs.
	jailErr string
	// devfs is the fake kernel's devfs rulesets: the sets that exist and the rules in each, and every devfs command
	// the hook ran. devfsFail, when set, is the stderr of every `devfs rule -s N add` (the load fails).
	devfs     map[int][]string
	devfsCmds []string
	devfsFail string
	// devfsKeepsSets makes `delset` fail as the kernel does for a ruleset that a mounted devfs uses.
	devfsKeepsSets bool
	// devfsEmptiesSets makes `delset` succeed on the rules but leave the (now empty) set in the kernel.
	devfsEmptiesSets bool
	// rctlStderr, when set, is the stderr of every rctl the hook runs (the command fails with it).
	rctlStderr string
}

// newHookEnv lays out one jail "web" attached to network "lan".
func newHookEnv(t *testing.T, os api.OS, ipv4, ipv6 string, devices ...string) *hookEnv {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	h := &hookEnv{env: e}
	h.host, h.jail, _ = ipam.EpairNames(hookUUID, 0)

	mp := filepath.Join(e.cfg.MountBase, "projects", "alpha", "jails", "web")
	e.managedDS("tank/jailops/projects")
	e.managedDS("tank/jailops/projects/alpha")
	e.managedDS("tank/jailops/projects/alpha/jails")
	if err := e.zfs.Create(ctx, zfs.CreateOpts{Name: "tank/jailops/projects/alpha/jails/web", Props: map[string]string{"jailops:managed": "on", "mountpoint": mp}}); err != nil {
		t.Fatal(err)
	}
	spec := api.JailSpec{Image: "freebsd-15-0@stable", OS: os, Network: []api.NetworkAttach{{Network: "lan", IPv4: ipv4, IPv6: ipv6}}}
	for _, d := range devices {
		spec.Devfs = append(spec.Devfs, api.DevfsDevice{Name: d, Device: d})
	}
	rec, _ := json.Marshal(map[string]any{"version": 1, "metadata": api.ObjectMeta{Name: "web", Project: "alpha", UUID: hookUUID}, "spec": spec})
	mustWrite(t, filepath.Join(mp, "spec.json"), string(rec))

	nw := api.NetworkSpec{Uplink: "em0", MTU: 1400,
		IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.200"},
		IPv6: &api.IPv6Net{Mode: api.IPv6Routed, Subnet: "fd00:20::/64", Range: "fd00:20::10-fd00:20::ff"}}
	doc, _ := json.Marshal(map[string]any{"apiVersion": "jailops/v1", "kind": "Network", "metadata": api.ObjectMeta{Name: "lan", UUID: "aaaa-1111-2222"}, "spec": nw})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "aaaa-1111-2222.json"), string(doc))
	// a second network with another name must not be picked
	other, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "dmz", UUID: "bbbb-1111-2222"}, "spec": api.NetworkSpec{Uplink: "em1"}})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "bbbb-1111-2222.json"), string(other))

	mustWrite(t, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), e.goodConf())
	// the rendered anchor of the jail: a jail with a link does not start without one
	mustWrite(t, e.cfg.PFAnchorFile("alpha_web"), "pass in quick on "+h.host+" all\n")
	e.runner.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}})
	e.runner.Add(run.Rule{Name: "rctl", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if h.rctlStderr != "" {
			return run.Result{ExitCode: 1, Stderr: []byte(h.rctlStderr)}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: h.rctlStderr}
		}
		return run.Result{}, nil
	}})
	h.devfs = map[int][]string{1: nil, 2: nil, 3: nil, 4: nil, 5: nil} // the stock rulesets of a running host
	for _, bin := range []string{"devfs", "/sbin/devfs"} {
		bin := bin
		e.runner.Add(run.Rule{Name: bin, Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
			line := strings.Join(c.Args, " ")
			h.devfsCmds = append(h.devfsCmds, line)
			switch {
			case line == "rule showsets":
				var out strings.Builder
				for n := range h.devfs {
					fmt.Fprintln(&out, n)
				}
				return run.Result{Stdout: []byte(out.String())}, nil
			case len(c.Args) == 4 && c.Args[3] == "show":
				n, _ := strconv.Atoi(c.Args[2])
				var out strings.Builder
				for i, r := range h.devfs[n] {
					fmt.Fprintf(&out, "%d %s\n", (i+1)*100, r)
				}
				return run.Result{Stdout: []byte(out.String())}, nil
			case len(c.Args) == 4 && c.Args[3] == "delset":
				if h.devfsKeepsSets {
					return run.Result{ExitCode: 1}, &run.ExitError{Name: bin, Args: c.Args, Code: 1, Stderr: "devfs: Device busy"}
				}
				if h.devfsEmptiesSets { // a mounted devfs keeps the set alive, but the rules are gone
					n, _ := strconv.Atoi(c.Args[2])
					h.devfs[n] = nil
					return run.Result{}, nil
				}
				n, _ := strconv.Atoi(c.Args[2])
				delete(h.devfs, n)
				return run.Result{}, nil
			case len(c.Args) > 4 && c.Args[3] == "add":
				if h.devfsFail != "" {
					return run.Result{ExitCode: 1}, &run.ExitError{Name: bin, Args: c.Args, Code: 1, Stderr: h.devfsFail}
				}
				n, _ := strconv.Atoi(c.Args[2])
				h.devfs[n] = append(h.devfs[n], strings.Join(c.Args[4:], " "))
				return run.Result{}, nil
			}
			return run.Result{ExitCode: 1}, &run.ExitError{Name: bin, Args: c.Args, Code: 1, Stderr: "unexpected devfs command"}
		}})
	}
	for _, bin := range []string{"/sbin/ifconfig", "/sbin/route"} {
		bin := bin
		e.runner.Add(run.Rule{Name: bin, Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
			if h.jailErr != "" {
				return run.Result{ExitCode: 1}, &run.ExitError{Name: bin, Args: c.Args, Code: 1, Stderr: h.jailErr}
			}
			return run.Result{}, nil
		}})
	}
	return h
}

func (h *hookEnv) ifaces() map[string]ifconfig.Iface {
	list, _ := h.net.List(context.Background())
	m := map[string]ifconfig.Iface{}
	for _, i := range list {
		m[i.Name] = i
	}
	return m
}

func (h *hookEnv) ifconfigCalls() []string {
	var out []string
	for _, c := range h.runner.Calls() {
		if c.Cmd.Name == "ifconfig" {
			out = append(out, strings.Join(c.Cmd.Args, " "))
		}
	}
	return out
}

func TestHookLifecycleFreeBSD(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12")
	ctx := context.Background()
	l := h.local
	mustWrite(t, h.cfg.PFAnchorFile("alpha_web"), "pass in on "+h.host+" all\n")

	if err := l.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatalf("prestart: %v", err)
	}
	ifs := h.ifaces()
	if _, ok := ifs[h.host]; !ok {
		t.Fatalf("host epair end %s missing: %v", h.host, ifs)
	}
	if _, ok := ifs[h.jail]; !ok {
		t.Fatalf("jail epair end %s missing before start", h.jail)
	}
	he := ifs[h.host]
	if he.Description != "jailops jail=alpha/web net=lan (host side)" || !he.Up() {
		t.Errorf("host end %+v", he)
	}
	// the host end carries the network's gateway as a /32 and the link-local gateway, and the routes to the jail's
	// addresses leave through it; the jail end is not given any
	if got := fmt.Sprint(he.Inet, he.Inet6); got != "[10.20.0.1/32] [fe80::1/64]" {
		t.Errorf("host end addresses: %s", got)
	}
	wantRoutes := []string{"-inet 10.20.0.12/32 -interface " + h.host, "-inet6 fd00:20::12/128 -interface " + h.host}
	if got := h.net.Routes(); strings.Join(got, "|") != strings.Join(wantRoutes, "|") {
		t.Errorf("routes %q, want %q", got, wantRoutes)
	}
	calls := h.ifconfigCalls()
	if len(calls) != 4 || !strings.Contains(calls[0], h.host+" ether ") || !strings.Contains(calls[1], h.jail+" ether ") ||
		calls[2] != h.host+" mtu 1400" || calls[3] != h.jail+" mtu 1400" {
		t.Errorf("ifconfig calls %q", calls)
	}
	// the jail's anchor is loaded before the jail starts, so that the whole of /etc/rc runs behind it
	if h.pf.LoadCalls["jailops/alpha/web"] != 1 || h.pf.LoadCalls["jailops/alpha"] != 1 {
		t.Errorf("anchor loads after prestart: %v", h.pf.LoadCalls)
	}

	// idempotent
	before := h.ifaces()
	if err := l.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatalf("second prestart: %v", err)
	}
	if got := h.ifaces(); len(got) != len(before) || len(h.net.Routes()) != 2 {
		t.Errorf("state changed on the second run: %v vs %v", got, before)
	}

	// the rendered anchor is left by the reconcile loop; prestart loads it
	// the jail starts: jail.conf's vnet.interface moves the jail end
	if err := h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := l.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatalf("poststart: %v", err)
	}
	if _, ok := h.ifaces()[h.jail]; ok {
		t.Error("the jail end was not moved into the jail")
	}
	if h.pf.LoadCalls["jailops/alpha/web"] != 2 {
		t.Errorf("the anchor is loaded by prestart (twice here) and not again by poststart: %v", h.pf.LoadCalls)
	}
	for _, c := range h.jails.Calls() {
		if c.Op == "exec" {
			t.Errorf("a FreeBSD jail configures itself, but the hook ran %v", c.Argv)
		}
	}
	if err := l.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatalf("second poststart: %v", err)
	}

	if err := l.RunHook(ctx, PhasePreStop, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.ifaces()[h.host]; !ok {
		t.Error("prestop removed the interface while the jail still runs")
	}

	// stop: the kernel removes the jail, poststop undoes the host side
	if err := h.jails.Remove(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := l.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
		t.Fatalf("poststop: %v", err)
	}
	ifs = h.ifaces()
	if _, ok := ifs[h.host]; ok {
		t.Error("host epair end survived poststop")
	}
	if a, _ := h.pf.Read(ctx, "jailops/alpha/web"); a != "" {
		t.Errorf("anchor still loaded: %q", a)
	}
	if rt := h.net.Routes(); len(rt) != 0 {
		t.Errorf("routes survived poststop: %q", rt)
	}
	if err := l.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
		t.Errorf("second poststop: %v", err)
	}
	// the whole cycle again
	if err := l.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Errorf("restart: %v", err)
	}
}

func TestHookConfiguresLinuxJailFromTheHost(t *testing.T) {
	h := newHookEnv(t, api.OSLinux, "10.20.0.12", "fd00:20::12")
	ctx := context.Background()
	if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range h.runner.Calls() {
		if c.Cmd.Name == "/sbin/ifconfig" || c.Cmd.Name == "/sbin/route" {
			got = append(got, c.Cmd.Name+" "+strings.Join(c.Cmd.Args, " "))
		}
	}
	want := []string{
		"/sbin/ifconfig -j alpha_web " + h.jail + " description jailops jail=alpha/web net=lan (jail side)",
		"/sbin/ifconfig -j alpha_web " + h.jail + " inet 10.20.0.12/32 up",
		"/sbin/ifconfig -j alpha_web " + h.jail + " inet6 fd00:20::12 prefixlen 128",
		"/sbin/ifconfig -j alpha_web " + h.jail + " up",
		"/sbin/route -j alpha_web add -host 10.20.0.1 -interface " + h.jail,
		"/sbin/route -j alpha_web add default 10.20.0.1",
		"/sbin/route -j alpha_web add -inet6 default fe80::1%" + h.jail,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("host-side commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range h.jails.Calls() {
		if c.Op == "exec" {
			t.Errorf("a command ran inside the jail: %v", c.Argv)
		}
	}
	// running poststart again is safe
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Errorf("second poststart: %v", err)
	}
}

func TestHookAlreadyExistsInJailIsTolerated(t *testing.T) {
	h := newHookEnv(t, api.OSLinux, "10.20.0.12", "none")
	ctx := context.Background()
	h.local.RunHook(ctx, PhasePreStart, "alpha_web")
	h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web")
	h.jailErr = "route: writing to routing socket: File exists"
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Errorf("File exists must not fail the hook: %v", err)
	}
	h.jailErr = "ifconfig: interface does not exist"
	if err := h.local.RunHook(ctx, PhasePostStart, "alpha_web"); err == nil {
		t.Error("a real failure inside the jail was swallowed")
	}
}

func TestHookRefusals(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	ctx := context.Background()
	l := h.local
	for _, name := range []string{"-x", "", "a b", "a/b", "../web", "web;id"} {
		if err := l.RunHook(ctx, PhasePreStart, name); err == nil {
			t.Errorf("jail %q accepted", name)
		}
	}
	if err := l.RunHook(ctx, "prestartx", "alpha_web"); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("unknown phase: %v", err)
	}
	if err := l.RunHook(ctx, PhasePreStart, "ghost"); err == nil {
		t.Error("a jail without a dataset")
	}
}

func TestHookSpecProblems(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		ipv4, ipv6 string
		mutate     func(h *hookEnv)
	}{
		"auto address": {ipv4: "auto", ipv6: "none"},
		"bad address":  {ipv4: "10.20.0.999", ipv6: "none"},
		"wrong family": {ipv4: "fd00::1", ipv6: "none"},
		"no network":   {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) { _ = removeAll(filepath.Join(h.cfg.StateDir, "objects", "Network")) }},
		"spec names other": {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) {
			mustWrite(t, filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json"), `{"metadata":{"name":"db","project":"alpha","uuid":"`+hookUUID+`"},"spec":{}}`)
		}},
		"no uuid": {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) {
			mustWrite(t, filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json"), `{"metadata":{"name":"web","project":"alpha"},"spec":{}}`)
		}},
		"no project": {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) {
			mustWrite(t, filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json"), `{"metadata":{"name":"web","uuid":"`+hookUUID+`"},"spec":{}}`)
		}},
		"corrupt spec": {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) {
			mustWrite(t, filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json"), `{"metadata":`)
		}},
		"mountpoint outside the roots": {ipv4: "none", ipv6: "none", mutate: func(h *hookEnv) {
			if err := h.zfs.Set(ctx, "tank/jailops/projects/alpha/jails/web", map[string]string{"mountpoint": "/etc"}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		h := newHookEnv(t, api.OSFreeBSD, tc.ipv4, tc.ipv6)
		if tc.mutate != nil {
			tc.mutate(h)
		}
		if err := h.local.RunHook(ctx, PhasePreStart, "alpha_web"); err == nil {
			t.Errorf("%s: prestart succeeded", name)
		}
		if _, ok := h.ifaces()[h.host]; ok {
			t.Errorf("%s: an epair was created for a broken spec", name)
		}
	}
}

func TestHookUsesTheSpecPreviousCopy(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	mp := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web")
	b, _ := h.local.ReadFile(context.Background(), filepath.Join(mp, "spec.json"))
	mustWrite(t, filepath.Join(mp, "spec.json.previous"), string(b))
	if err := removeAll(filepath.Join(mp, "spec.json")); err != nil {
		t.Fatal(err)
	}
	if err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web"); err != nil {
		t.Errorf("fallback to spec.json.previous: %v", err)
	}
}

func TestHookPostStopWithoutSpecStillDropsTheAnchor(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "none")
	ctx := context.Background()
	h.pf.Load(ctx, "jailops/alpha/web", "pass all\n")
	_ = removeAll(filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "spec.json"))
	_ = h.local.RunHook(ctx, PhasePostStop, "alpha_web")
	if a, _ := h.pf.Read(ctx, "jailops/alpha/web"); a != "" {
		t.Errorf("anchor survived: %q", a)
	}
}

// A host that still has what an earlier version made for the network: the gateway pair whose host end carries the
// gateway address with the network's prefix, and an epair of this jail left from its last run on the bridge. The start
// takes the address from the old interface and replaces the leftover epair; a stop, started or not, always succeeds
// and leaves nothing of the jail.
func TestHookStartAndStopOnAHostWithTheOldBridgeNetwork(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12")
	ctx := context.Background()
	l := h.local
	mustWrite(t, h.cfg.PFAnchorFile("alpha_web"), "pass in on "+h.host+" all\n")
	if _, _, err := h.net.EpairCreate(ctx, "lan"+"g"); err != nil { // the old gateway pair: langa and langb
		t.Fatal(err)
	}
	if err := h.net.AddrAdd(ctx, "langb", netip.MustParsePrefix("10.20.0.1/24")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.net.EpairCreate(ctx, strings.TrimSuffix(h.host, "a")); err != nil { // this jail's epair of its last run
		t.Fatal(err)
	}

	if err := l.RunHook(ctx, PhasePreStart, "alpha_web"); err != nil {
		t.Fatalf("prestart beside the old bridge network: %v", err)
	}
	ifs := h.ifaces()
	if got := fmt.Sprint(ifs[h.host].Inet); got != "[10.20.0.1/32]" {
		t.Errorf("the link of the jail has no gateway address: %s", got)
	}
	if got := ifs["langb"].Inet; len(got) != 0 {
		t.Errorf("the old gateway interface still holds the address: %v", got)
	}
	if err := h.jails.Create(ctx, filepath.Join(h.cfg.ConfDir, "alpha_web.conf"), "alpha_web"); err != nil {
		t.Fatal(err)
	}
	if err := l.RunHook(ctx, PhasePostStart, "alpha_web"); err != nil {
		t.Fatalf("poststart: %v", err)
	}
	for i := 0; i < 2; i++ { // the second stop finds nothing to do
		if err := l.RunHook(ctx, PhasePostStop, "alpha_web"); err != nil {
			t.Fatalf("poststop %d: %v", i+1, err)
		}
	}
	if _, ok := h.ifaces()[h.host]; ok {
		t.Error("the host end of the link is still there after the stop")
	}
	if len(h.net.Routes()) != 0 {
		t.Errorf("routes left: %v", h.net.Routes())
	}
}

// An address that belongs to a link of another jail, or to an interface JailOps does not manage, is not taken.
func TestHookStartDoesNotTakeAnAddressFromAnInterfaceThatIsNotTheOldGateway(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "fd00:20::12")
	mustWrite(t, h.cfg.PFAnchorFile("alpha_web"), "pass in on "+h.host+" all\n")
	h.net.AddHost(ifconfig.Iface{Name: "em0", Inet: []netip.Prefix{netip.MustParsePrefix("10.20.0.1/24")}, Flags: []string{"UP"}})
	err := h.local.RunHook(context.Background(), PhasePreStart, "alpha_web")
	if err == nil || !strings.Contains(err.Error(), "em0") {
		t.Fatalf("got %v, want a refusal naming em0", err)
	}
	if got := h.ifaces()["em0"].Inet; len(got) != 1 {
		t.Errorf("em0 lost its address: %v", got)
	}
}

// A stop that did not finish leaves devfs mounts below the root of the jail, one more on each failed stop; the root
// dataset stays busy for good. mounts.heal takes every one of them off a jail that does not run, deepest first,
// whatever their number, and touches nothing that lies outside the root of this jail.
func TestHealMountsTakesStaleMountsOffTheRootOfAStoppedJail(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "")
	ctx := context.Background()
	root := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	other := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "db", "root")
	table := []string{ // mount -p: device, mount point, type, options, dump, pass
		"tank/jailops/projects/alpha/jails/web/root " + root + " zfs rw 0 0",
		"devfs " + root + "/dev devfs rw 0 0",
		"devfs " + root + "/dev devfs rw 0 0", // stacked by a second failed stop
		"/usr/local/www " + root + "/srv/www nullfs rw 0 0",
		"devfs " + other + "/dev devfs rw 0 0", // another jail's: not touched
	}
	var umounts []string
	h.runner.Add(run.Rule{Name: "mount", Args: []string{"-p"}, Fn: func(c run.Cmd) (run.Result, error) {
		return run.Result{Stdout: []byte(strings.Join(table, "\n") + "\n")}, nil
	}})
	h.runner.Add(run.Rule{Name: "umount", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		mp := c.Args[len(c.Args)-1]
		umounts = append(umounts, mp)
		for i, line := range table { // one layer comes off
			if f := strings.Fields(line); f[1] == mp && f[2] != "zfs" {
				table = append(table[:i], table[i+1:]...)
				break
			}
		}
		return run.Result{}, nil
	}})
	l := h.local

	stale, err := l.StaleMounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 4 {
		t.Fatalf("stale mounts %+v, want the 3 of web and the 1 of db", stale)
	}
	res, err := l.HealJail(ctx, "alpha_web")
	if err != nil {
		t.Fatalf("heal: %v", err)
	}
	if len(res.Unmounted) != 3 || len(res.Left) != 0 {
		t.Errorf("healed %+v", res)
	}
	for _, mp := range umounts {
		if strings.HasPrefix(mp, other) || mp == root {
			t.Errorf("unmounted %s, which is not below the root of this jail", mp)
		}
	}
	if len(table) != 2 {
		t.Errorf("mounts left: %v", table)
	}
}

// The hooks of a jail never unmount anything: jail(8) mounts the devfs of the jail before exec.prestart and unmounts
// it after exec.poststop, so a cleanup in a hook would take /dev away from the jail that is being started.
func TestHooksNeverUnmountTheMountsOfJail8(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "")
	ctx := context.Background()
	root := filepath.Join(h.cfg.MountBase, "projects", "alpha", "jails", "web", "root")
	h.runner.Add(run.Rule{Name: "mount", Args: []string{"-p"}, Fn: func(run.Cmd) (run.Result, error) {
		return run.Result{Stdout: []byte("devfs " + root + "/dev devfs rw 0 0\n")}, nil
	}})
	h.runner.Add(run.Rule{Name: "umount", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		t.Errorf("a hook unmounted %v", c.Args)
		return run.Result{}, nil
	}})
	l := h.local
	for _, phase := range []string{PhasePreStart, PhasePostStart, PhasePostStop} {
		if err := l.RunHook(ctx, phase, "alpha_web"); err != nil {
			t.Fatalf("%s: %v", phase, err)
		}
	}
}

// The interfaces of the earlier network layout (a bridge named after the network and its gateway pair) are destroyed
// when no jail that runs uses them: a bridge that still has the link of a running jail as a member stays, the links
// of jails and everything without the JailOps marker are never touched.
func TestHealNetworkDestroysTheOldLayoutThatNoRunningJailUses(t *testing.T) {
	h := newHookEnv(t, api.OSFreeBSD, "10.20.0.12", "")
	ctx := context.Background()
	h.net.AddIface(ifconfig.Iface{Name: "lan", Groups: []string{"bridge"}, Description: ifconfig.Marker, Members: []ifconfig.Member{{Name: h.host}}})
	h.net.AddIface(ifconfig.Iface{Name: "langa", Groups: []string{"epair"}, Description: ifconfig.Marker})
	h.net.AddIface(ifconfig.Iface{Name: "langb", Groups: []string{"epair"}, Description: ifconfig.Marker})
	h.net.AddIface(ifconfig.Iface{Name: "bridge7", Groups: []string{"bridge"}, Description: "someone's bridge"}) // not ours
	h.net.AddIface(ifconfig.Iface{Name: "em0", Flags: []string{"UP"}})                                           // the uplink
	var destroyed []string
	h.runner.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		if len(c.Args) == 2 && c.Args[1] == "destroy" {
			destroyed = append(destroyed, c.Args[0])
		}
		return run.Result{}, nil
	}})
	l := h.local

	// the jail runs on the old bridge: the bridge stays, the gateway pair goes
	if err := h.jails.Create(ctx, "/etc/jails/alpha_web.conf", "alpha_web"); err != nil {
		t.Fatal(err)
	}
	res, err := l.HealNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(res.Destroyed, "lan") || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "lan") {
		t.Errorf("a bridge that a running jail hangs on was touched: %+v", res)
	}
	if !slices.Contains(res.Destroyed, "langa") || slices.Contains(res.Destroyed, "langb") {
		t.Errorf("destroyed %v, want the gateway pair once (langa takes langb with it)", res.Destroyed)
	}

	// the jail is stopped: the bridge goes too
	destroyed = nil
	if err := h.jails.Remove(ctx, "/etc/jails/alpha_web.conf", "alpha_web"); err != nil {
		t.Fatal(err)
	}
	res, err = l.HealNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Destroyed, "lan") {
		t.Errorf("the bridge of a network that no running jail uses is still there: %+v", res)
	}
	for _, d := range destroyed {
		if d == "bridge7" || d == "em0" {
			t.Errorf("destroyed %s, which is not JailOps's", d)
		}
	}
}
