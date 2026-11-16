package ipam

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// DeriveMAC returns the stable MAC address of a jail's first interface,
// derived from the jail UUID. The result is unicast and locally administered.
func DeriveMAC(uuid string) (string, error) { return DeriveMACN(uuid, 0, false) }

// DeriveMACN derives the MAC of attachment index. host selects the host-side
// end of the epair rather than the jail-side end.
func DeriveMACN(uuid string, index int, host bool) (string, error) {
	u := strings.ToLower(strings.TrimSpace(uuid))
	if u == "" {
		return "", invalid("uuid", "cannot derive a MAC address without a UUID")
	}
	if index < 0 {
		return "", invalid("index", "negative interface index")
	}
	end := "j"
	if host {
		end = "h"
	}
	sum := sha256.Sum256([]byte("jailops-mac\x00" + u + "\x00" + strconv.Itoa(index) + "\x00" + end))
	b := sum[:6]
	b[0] = (b[0] | 0x02) &^ 0x01 // locally administered, unicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]), nil
}

// MaxEpairIndex is the largest attachment index EpairName can encode.
const MaxEpairIndex = 36*36 - 1

const b36 = "0123456789abcdefghijklmnopqrstuvwxyz"

// EpairNames returns the host-side and jail-side interface names for
// attachment index of a jail. Names are "jo" + 10 hex digits of
// sha256(jailID) + 2 base-36 digits of the index + "a" (host) or "b" (jail):
// 15 characters, the FreeBSD limit. The index must be 0..MaxEpairIndex.
func EpairNames(jailID string, index int) (host, jail string, err error) {
	if jailID == "" {
		return "", "", invalid("jail", "epair name needs a jail id")
	}
	if index < 0 || index > MaxEpairIndex {
		return "", "", invalid("index", "interface index %d out of range", index)
	}
	sum := sha256.Sum256([]byte("jailops-epair\x00" + jailID))
	base := "jo" + hex.EncodeToString(sum[:5]) + string(b36[index/36]) + string(b36[index%36])
	return base + "a", base + "b", nil
}

// EpairName returns the host-side name, or the empty
// string for invalid input (EpairNames reports the error).
func EpairName(jailID string, index int) string {
	h, _, err := EpairNames(jailID, index)
	if err != nil {
		return ""
	}
	return h
}

var epairRE = regexp.MustCompile(`^jo[0-9a-f]{10}[0-9a-z]{2}[ab]$`)

// IsEpairName reports whether name has the shape of a JailOps epair end. The
// caller still checks the interface description before touching it.
func IsEpairName(name string) bool { return epairRE.MatchString(name) }

// GuestPrefixLen6 is the prefix length a jail configures for its IPv6
// address: /128 in every mode, so that the jail believes no prefix is on-link and reaches everything, the other
// jails included, through the host.
func GuestPrefixLen6(mode api.IPv6Mode, subnetBits int) int {
	return 128
}

// GuestPrefixLen4 is the prefix length a jail configures for its IPv4 address: /32, so that the jail has no on-link
// neighbour and reaches the gateway, and through it the other jails, by a host route to the gateway.
func GuestPrefixLen4() int { return 32 }

// GatewayLinkLocal6 is the link-local address of the host on every jail's link: the IPv6 default gateway of every
// jail, in both IPv6 modes. Every host end of an epair carries it (a link-local address is per interface, so the
// same address can be on all of them). A jail has no on-link prefix, so nothing reaches another jail without
// passing the host and its PF.
var GatewayLinkLocal6 = netip.MustParseAddr("fe80::1")

// LinkLocalFromMAC returns the IPv6 link-local address FreeBSD derives from an interface's MAC address (the modified
// EUI-64 form, fe80::/64). A VNET jail's epair end gets the MAC JailOps sets, and the kernel forms its link-local
// address from it (verified on FreeBSD 15.1 amd64). It is wrong only if the jail changes its own link-local address
// or the host enables net.inet6.ip6.stableaddr.
func LinkLocalFromMAC(mac string) (netip.Addr, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return netip.Addr{}, invalid("mac", "not a 48-bit MAC address")
	}
	var a [16]byte
	a[0], a[1] = 0xfe, 0x80
	a[8], a[9], a[10] = hw[0]^0x02, hw[1], hw[2]
	a[11], a[12] = 0xff, 0xfe
	a[13], a[14], a[15] = hw[3], hw[4], hw[5]
	return netip.AddrFrom16(a), nil
}
