package ifconfig

import (
	"net/netip"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	text := `Routing tables

Internet:
Destination        Gateway            Flags     Nhop#    Mtu      Netif Expire
default            192.0.2.1          UGS           1   1500     vtnet0
10.77.0.0/24       127.0.0.1          URS           4  16384        lo0
10.77.0.5          link#9             UHS           3   1500   jo0123456789a0a

Internet6:
Destination                       Gateway                       Flags     Nhop#    Mtu      Netif Expire
default                           fe80::1%vtnet0                UGS           1   1500     vtnet0
fe80::%jo0123456789a0a/64         link#9                        U             2   1500   jo0123456789a0a
2001:db8:1::/64                   ::1                           URS           4  16384        lo0
2001:db8:1::5                     link#9                        UHS           3   1500   jo0123456789a0a
`
	got := ParseRoutes(text)
	want := []RouteEntry{
		{Dest: netip.MustParsePrefix("10.77.0.0/24"), Iface: "lo0", Flags: "URS"},
		{Dest: netip.MustParsePrefix("10.77.0.5/32"), Iface: "jo0123456789a0a", Flags: "UHS"},
		{Dest: netip.MustParsePrefix("2001:db8:1::/64"), Iface: "lo0", Flags: "URS"},
		{Dest: netip.MustParsePrefix("2001:db8:1::5/128"), Iface: "jo0123456789a0a", Flags: "UHS"},
	}
	// the default routes and the link-local entry are left out; the host's own network routes are kept
	var filtered []RouteEntry
	for _, r := range got {
		if r.Dest.Bits() == 0 {
			continue
		}
		filtered = append(filtered, r)
	}
	if len(filtered) != len(want) {
		t.Fatalf("got %d routes %v, want %d", len(filtered), filtered, len(want))
	}
	for i := range want {
		if filtered[i] != want[i] {
			t.Errorf("route %d: got %+v, want %+v", i, filtered[i], want[i])
		}
	}
	if !filtered[0].Reject() || filtered[1].Reject() {
		t.Error("only the lo0 routes are reject routes")
	}
}
