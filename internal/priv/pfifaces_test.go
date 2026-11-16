package priv

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// A rule of an anchor decides for the whole host: the helper loads one only when it stands on an interface of JailOps, or
// on the uplink of a network in the shapes of a translation and a forward.
func TestAnchorRulesStandOnJailInterfacesOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, _, err := e.net.EpairCreate(ctx, "jo0123456789a0"); err != nil {
		t.Fatal(err)
	}
	nw, _ := json.Marshal(map[string]any{"kind": "Network", "metadata": api.ObjectMeta{Name: "lan", UUID: "aaaa-1111-2222"},
		"spec": api.NetworkSpec{Uplink: "em0", IPv4: &api.IPv4Net{Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20"}}})
	mustWrite(t, filepath.Join(e.cfg.StateDir, "objects", "Network", "aaaa-1111-2222.json"), string(nw))
	p := e.local.PF()
	const jif = "jo0123456789a0a"
	for _, rs := range []string{
		"pass in quick on " + jif + " all\n",
		"table <host> persist { 192.0.2.1 }\nblock drop in quick on " + jif + " from any to <host>\n",
		"match in on " + jif + " all dnpipe (40001, 59999)\nmatch out on " + jif + " all dnpipe (59999, 40001)\n",
		"match in on " + jif + " all dnpipe (40001, 0)\nmatch out on " + jif + " all dnpipe (0, 40001)\n",
		"match out on em0 inet from 10.20.0.0/24 to ! 10.20.0.0/24 nat-to (em0:0)\n",
		"match in on em0 inet proto tcp from any to (em0) port 8080 rdr-to 10.20.0.10 port 80\npass in quick on em0 inet proto tcp from any to 10.20.0.10 port 80\n",
		"anchor \"*\"\n",
	} {
		if err := p.Load(ctx, "jailops/web/db", rs); err != nil {
			t.Errorf("%q: %v", rs, err)
		}
	}
	for _, rs := range []string{
		"pass quick on em0 all\n",                                             // the uplink, any traffic
		"block drop in quick on em0 from any to any\n",                        // closes the host
		"pass in quick on em0 inet proto tcp from any to any\n",               // names no destination
		"pass in quick on em0 inet proto tcp from any to 127.0.0.1 port 22\n", // an address of the host
		"pass in quick on lo0 all\n",                                          // not JailOps's
		"pass in quick on mybr all\n",                                         // a bridge of the administrator's
		"pass all\n",                                                          // on no interface
		"block drop all\n",                                                    // on no interface
		"match in on " + jif + " all dnpipe 1\n",                              // a pipe outside JailOps's range
		"match out on " + jif + " all dnpipe (0, 1)\n",                        // the reverse pipe is outside the range as well
		"antispoof for em0\n",                                                 // not a rule the renderer writes
		"pass in quick on { " + jif + ", em0 } all\n",                         // a list that holds the uplink
	} {
		err := p.Load(ctx, "jailops/web/db", rs)
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%q was not refused: %v", rs, err)
		} else if strings.Contains(err.Error(), "block drop") || strings.Contains(err.Error(), "127.0.0.1 port") {
			t.Errorf("the error quotes the ruleset, which may hold what must not reach the audit log: %v", err)
		}
	}
	// the operator may allow raw rulesets (admin-raw-pf)
	cfg := e.cfg
	cfg.Admin.RawPF = true
	l2, _ := NewLocal(cfg, Deps{PF: e.pf, Net: e.net}, WithoutChown())
	if err := l2.PF().Load(ctx, "jailops/web/db", "pass quick on em0 all\n"); err != nil {
		t.Errorf("a raw ruleset the operator allowed: %v", err)
	}
}
