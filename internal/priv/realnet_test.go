package priv

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// A real FreeBSD host, only when JAILOPS_REAL_NET=1 (the test makes interfaces and destroys them): a host that still
// has the gateway pair of the bridge network of an earlier version, whose host end holds the gateway address with the
// network's prefix. The kernel answers "File exists" to the /32 alias of the same address on the link of a jail, and
// "Can't assign requested address" to the removal of an alias that never got there.
func TestRealHostGatewayAddressOfTheOldBridgeNetwork(t *testing.T) {
	if os.Getenv("JAILOPS_REAL_NET") != "1" {
		t.Skip("set JAILOPS_REAL_NET=1 on a FreeBSD host to run this (it creates and destroys interfaces)")
	}
	ctx := context.Background()
	e := newEnv(t)
	e.storeLan(t, "10.99.0.0/24") // the network the helper knows
	real := ifconfig.NewCommand(run.NewExec(), ifconfig.Options{})
	e.local.d.Net = real
	sh := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	bridge := sh("ifconfig", "bridge", "create")
	sh("ifconfig", bridge, "description", ifconfig.Marker)
	ga, gb, err := real.EpairCreate(ctx, "jotestgw")
	if err != nil {
		t.Fatal(err)
	}
	ja, _, err := real.EpairCreate(ctx, "jotestln")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, n := range []string{ja, ga} {
			_ = exec.Command("ifconfig", n, "destroy").Run()
		}
		_ = exec.Command("ifconfig", bridge, "destroy").Run()
	})
	sh("ifconfig", bridge, "addm", ga, "addm", ja, "up")
	gw := netip.MustParsePrefix("10.99.0.1/24")
	if err := real.AddrAdd(ctx, gb, gw); err != nil {
		t.Fatal(err)
	}

	link := netip.MustParsePrefix("10.99.0.1/32")
	if err := real.AddrAdd(ctx, ja, link); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("the kernel took the gateway address twice (or answered otherwise): %v", err)
	}
	if err := real.AddrRemove(ctx, ja, link); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("removing an address that is not there: %v", err)
	}
	if err := e.local.addAddr(ctx, ja, link); err != nil {
		t.Fatalf("addAddr beside the old gateway: %v", err)
	}
	if out := sh("ifconfig", ja); !strings.Contains(out, "inet 10.99.0.1 netmask 0xffffffff") {
		t.Fatalf("the link has no gateway address:\n%s", out)
	}
	if out := sh("ifconfig", gb); strings.Contains(out, "10.99.0.1") {
		t.Fatalf("the old gateway interface still holds the address:\n%s", out)
	}
	if err := ignoreNotFound(real.AddrRemove(ctx, ja, link)); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := ignoreNotFound(real.AddrRemove(ctx, ja, link)); err != nil {
		t.Fatalf("stop again: %v", err)
	}
}
