package service_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

func leftoversCheck(t *testing.T, e *dtest.Env) api.DoctorCheck {
	t.Helper()
	for _, c := range e.D.Service().Doctor(as(globalAdmin, "")).Checks {
		if c.Name == "network.leftovers" {
			return c
		}
	}
	t.Fatal("no network.leftovers check")
	return api.DoctorCheck{}
}

// A host that was upgraded from a version with a bridge per network: the bridge, the gateway pair holding the gateway
// address, and the link of a jail that is still a member of the bridge. The check names them, says which jails to
// restart first and gives the commands.
func TestDoctorWarnsForTheBridgeNetworkOfAnEarlierVersion(t *testing.T) {
	e := dtest.New(t, dtest.Options{Clients: func(c *daemon.Clients) {
		c.Runner = noBridgeModule{c.Runner} // the module is not loaded on a clean host
	}})
	e.Seed()
	if ok := leftoversCheck(t, e); ok.Status != api.DoctorOK {
		t.Fatalf("a clean host: %+v", ok)
	}
	ctx := context.Background()
	if _, _, err := e.Net.EpairCreate(ctx, "lang"); err != nil { // langa and langb: the gateway pair
		t.Fatal(err)
	}
	if err := e.Net.AddrAdd(ctx, "langb", netip.MustParsePrefix("10.20.0.1/24")); err != nil {
		t.Fatal(err)
	}
	e.Net.AddIface(ifconfig.Iface{Name: "lan", Description: ifconfig.Marker, Groups: []string{"bridge"},
		Members: []ifconfig.Member{{Name: "jo3c11ddcb1400a"}}})
	c := leftoversCheck(t, e)
	if c.Status != api.DoctorWarn {
		t.Fatalf("%+v", c)
	}
	for _, want := range []string{"lan (bridge)", "langa (gateway)", "langb (gateway)", "10.20.0.1/24 on langb", "1 jail links are still members"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message %q lacks %q", c.Message, want)
		}
	}
	for _, want := range []string{"ifconfig lan destroy", "ifconfig langa destroy", "kldunload if_bridge", "/boot/loader.conf"} {
		if !strings.Contains(c.Hint, want) {
			t.Errorf("hint %q lacks %q", c.Hint, want)
		}
	}
}

type noBridgeModule struct{ run.Runner }

func (r noBridgeModule) Run(ctx context.Context, c run.Cmd) (run.Result, error) {
	if c.Name == "kldstat" && strings.Contains(strings.Join(c.Args, " "), "if_bridge") {
		return run.Result{ExitCode: 1}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1}
	}
	return r.Runner.Run(ctx, c)
}
