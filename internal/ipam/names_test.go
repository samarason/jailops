package ipam

import (
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestLinkLocalFromMAC(t *testing.T) {
	got, err := LinkLocalFromMAC("2a:58:8a:88:fc:d2")
	if err != nil || got.String() != "fe80::2858:8aff:fe88:fcd2" { // observed on FreeBSD 15.1
		t.Fatal(got, err)
	}
	if _, err := LinkLocalFromMAC("nonsense"); err == nil {
		t.Fatal("accepted")
	}
}

// In both modes a jail holds a /128 and reaches everything through the host's link-local gateway.
func TestGuestAddressingIsTheSameInBothModes(t *testing.T) {
	for _, m := range []api.IPv6Mode{api.IPv6Routed, api.IPv6Proxy} {
		if GuestPrefixLen6(m, 80) != 128 {
			t.Errorf("%s: jail prefix is not /128", m)
		}
	}
	if GatewayLinkLocal6.String() != "fe80::1" {
		t.Errorf("gateway %s", GatewayLinkLocal6)
	}
}
