package reconcile_test

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/wireguard"
)

func wgWorld(t *testing.T) (*world, *wireguard.Fake) {
	w := newWorld(t, reconcile.Config{})
	wg := wireguard.NewFake()
	w.R = reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: privateRunner(),
		Sysctl: sysctl, Clock: w.clock, WG: wg})
	t.Cleanup(w.R.Close)
	return w, wg
}

func officeDesired() reconcile.WireGuardDesired {
	tun := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")}
	rs, _ := render.PFWireGuard("office", "wg-office", tun, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")})
	return reconcile.WireGuardDesired{Name: "office", Iface: "wg-office", Anchor: wireguard.Anchor("office"), Ruleset: rs,
		Apply: wireguard.ApplyReq{Name: "office", Iface: "wg-office", ListenPort: 51820, Addresses: []netip.Prefix{netip.MustParsePrefix("10.99.0.1/24")},
			Peers: []wireguard.PeerConf{{PublicKey: wireguard.FakeKey(7), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}}}}}
}

// After a reboot the interface is gone; the loop makes it again, loads the anchor, and then leaves it alone.
func TestWireGuardPassRecreates(t *testing.T) {
	w, wg := wgWorld(t)
	if _, err := wg.WGKeys(bg, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	w.des = reconcile.Desired{WireGuard: []reconcile.WireGuardDesired{officeDesired()}}
	rep := w.R.Pass(bg)
	if len(rep.Failures) != 0 || !strings.Contains(strings.Join(rep.Applied, ";"), "wireguard office: created wg-office") {
		t.Fatalf("%+v", rep)
	}
	if live, _ := w.PF.Read(bg, "jailops/wg.office"); !strings.Contains(live, "pass in quick on wg-office") {
		t.Fatalf("anchor %q", live)
	}
	rep = w.R.Pass(bg)
	if len(rep.Applied) != 0 {
		t.Fatalf("a second pass changed %v", rep.Applied)
	}
	// down: the interface goes, the keys stay
	d := officeDesired()
	d.Down = true
	w.des.WireGuard = []reconcile.WireGuardDesired{d}
	w.R.Pass(bg)
	if _, ok := wg.Iface("office"); ok || !wg.HasKeys("office") {
		t.Fatal("down did not remove the interface, or removed the keys")
	}
	// a tunnel being changed by an operation is left to it
	w.des.WireGuard = []reconcile.WireGuardDesired{officeDesired()}
	unlock, _ := w.TryLock("op", "wireguard/office")
	w.R.Pass(bg)
	if _, ok := wg.Iface("office"); ok {
		t.Fatal("the loop applied a locked tunnel")
	}
	unlock()
	w.R.Pass(bg)
	if _, ok := wg.Iface("office"); !ok {
		t.Fatal("not applied once unlocked")
	}
	// a tunnel that cannot be rendered is a failure, nothing else
	w.des.WireGuard = []reconcile.WireGuardDesired{{Name: "bad", Problem: "network \"x\" not found"}}
	if rep := w.R.Pass(bg); rep.Failures["wireguard/bad"] == "" {
		t.Fatalf("%+v", rep.Failures)
	}
}

// jailRunner answers `ifconfig -j <jail> <if>` with what the jail's interface carries and records the descriptions set.
type jailRunner struct {
	mu    sync.Mutex
	desc  string
	reads int
	sets  []string
}

func (r *jailRunner) Run(_ context.Context, c run.Cmd) (run.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := c.Args
	switch {
	case c.Name == "ifconfig" && len(a) == 3 && a[0] == "-j":
		r.reads++
		out := a[2] + ": flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n"
		if r.desc != "" {
			out += "\tdescription: " + r.desc + "\n"
		}
		return run.Result{Stdout: []byte(out)}, nil
	case c.Name == "ifconfig" && len(a) == 5 && a[0] == "-j" && a[3] == "description":
		r.desc = a[4]
		r.sets = append(r.sets, strings.Join(a, " "))
	}
	return run.Result{}, nil
}

// The jail end of an epair lives in the jail's vnet: its description is read and set from the host, once per start.
func TestJailSideDescriptionRepair(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	jr := &jailRunner{desc: "jailops:" + jailID}
	w.R = reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: w.PF, Jails: w.Jails, Run: jr, Sysctl: sysctl, Clock: w.clock})
	t.Cleanup(w.R.Close)
	j := jailDesired("p_web")
	_, jailEnd := epairOf(jailID, 0)
	want := render.JailIfaceDesc("p", "web", "lan", false)
	j.JailSide = []render.Step{{Op: render.OpSetDescription, Phase: render.PhaseJail, Iface: jailEnd, Arg: want}}
	w.des = reconcile.Desired{Networks: []reconcile.NetworkDesired{lan()}, Jails: []reconcile.JailDesired{j}}
	w.R.Pass(bg)
	_ = w.Jails.Create(bg, "/etc/jailops/jails/p_web/jail.conf", "p_web")
	h := j.Epairs[0]
	_, _, _ = w.Net.EpairCreate(bg, h[:len(h)-1])
	w.R.Pass(bg)
	if jr.desc != want || len(jr.sets) != 1 || jr.sets[0] != "-j p_web "+jailEnd+" description "+want {
		t.Fatalf("set %v, now %q", jr.sets, jr.desc)
	}
	reads := jr.reads
	w.R.Pass(bg)
	w.R.Pass(bg)
	if jr.reads != reads {
		t.Fatalf("the jail is asked every pass: %d then %d", reads, jr.reads)
	}
	// a new start (another JID) is checked again
	_ = w.Jails.Remove(bg, "/etc/jailops/jails/p_web/jail.conf", "p_web")
	_ = w.Jails.Create(bg, "/etc/jailops/jails/p_web/jail.conf", "p_web")
	w.R.Pass(bg)
	if jr.reads != reads+1 || len(jr.sets) != 1 {
		t.Fatalf("after a restart: reads %d, sets %v", jr.reads, jr.sets)
	}
}

// Epairs are matched to jails by name, whatever their description says (either format); one whose name belongs to
// no jail and that carries a JailOps description is removed; one with a foreign description stays.
func TestOrphansByName(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	j := jailDesired("p_web")
	w.des = reconcile.Desired{Networks: []reconcile.NetworkDesired{lan()}, Jails: []reconcile.JailDesired{j}}
	w.R.Pass(bg)
	_ = w.Jails.Create(bg, "/etc/jailops/jails/p_web/jail.conf", "p_web")
	mk := func(id string, desc string) string {
		h, _ := epairOf(id, 0)
		if !ifconfig.HasMarker(desc) { // someone else's: made by hand, the helper would not write it
			w.Net.AddIface(ifconfig.Iface{Name: h, Groups: []string{"epair"}, Description: desc})
			return h
		}
		if _, _, err := w.Net.EpairCreate(bg, h[:len(h)-1]); err != nil {
			t.Fatal(err)
		}
		if err := w.Net.SetDescription(bg, h, desc); err != nil {
			t.Fatal(err)
		}
		return h
	}
	mine := mk(jailID, render.JailIfaceDesc("p", "web", "lan", true))
	gone := mk("55555555-5555-4555-8555-555555555555", render.JailIfaceDesc("p", "old", "lan", true))
	foreign := mk("66666666-6666-4666-8666-666666666666", "the administrator's")
	rep := w.R.Pass(bg)
	if len(rep.Cleaned) != 1 || rep.Cleaned[0] != gone {
		t.Fatalf("cleaned %v", rep.Cleaned)
	}
	ifs, _ := w.Net.List(bg)
	for _, n := range []string{mine, foreign} {
		if _, ok := find(ifs, n); !ok {
			t.Errorf("%s was removed", n)
		}
	}
}
