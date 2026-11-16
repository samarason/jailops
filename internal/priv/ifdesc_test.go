package priv

import (
	"context"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// net.set_description writes only the descriptions JailOps makes: "jailops ..." (or the marker of earlier
// releases), at most 64 characters of a fixed set, on an interface JailOps owns. Clearing is allowed.
func TestSetDescriptionOverTheWire(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	n := f.client.Net()
	if _, _, err := n.EpairCreate(ctx, "jo0"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"jailops jail=web/nginx net=lan (host side)", "jailops wireguard=office", ""} {
		if err := n.SetDescription(ctx, "jo0a", d); err != nil {
			t.Errorf("%q: %v", d, err)
		}
	}
	for _, d := range []string{"uplink", "jailops a;b", "jailops a\nb", "jailops \"x\"", "jailops $(id)", "jailops `id`", "jailops " + strings.Repeat("x", 57), "jailopsx", "jailops:0b0e7f3e-5c4b-4f6e-9d3e-111111111111", "JAILOPS net=lan", "jailops ä"} {
		if err := n.SetDescription(ctx, "jo0a", d); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%q: %v", d, err)
		}
	}
	if err := n.SetDescription(ctx, "em0", "jailops jail=web/nginx net=lan (host side)"); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a foreign interface: %v", err)
	}
}
