// Package ipam allocates addresses from managed network ranges and derives
// deterministic interface identities (names, MAC addresses). Everything here
// is a pure function of its inputs; IPv6 ranges are never enumerated.
package ipam

import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Range is an inclusive span of addresses of one family.
type Range struct {
	First, Last netip.Addr
}

func invalid(field, format string, args ...any) *api.Error {
	return api.Errorf(api.CodeInvalid, format, args...).WithDetail("field", field)
}

func norm(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }

// ParseRange parses "a-b" (inclusive) or a single address "a".
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, invalid("range", "empty range")
	}
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	a, err := parseAddr(lo)
	if err != nil {
		return Range{}, invalid("range", "bad range %q: %v", s, err)
	}
	b, err := parseAddr(hi)
	if err != nil {
		return Range{}, invalid("range", "bad range %q: %v", s, err)
	}
	if a.Is4() != b.Is4() {
		return Range{}, invalid("range", "range %q mixes address families", s)
	}
	if b.Less(a) {
		return Range{}, invalid("range", "range %q ends before it starts", s)
	}
	return Range{First: a, Last: b}, nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, err
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("zone not allowed")
	}
	return a.Unmap(), nil
}

// ParseExclusions parses single addresses, "a-b" spans and CIDR prefixes.
func ParseExclusions(list []string) ([]Range, error) {
	out := make([]Range, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, invalid("exclude", "bad exclusion %q: %v", s, err)
			}
			p = p.Masked()
			out = append(out, Range{First: norm(p.Addr()), Last: lastOf(p)})
			continue
		}
		r, err := ParseRange(s)
		if err != nil {
			return nil, invalid("exclude", "bad exclusion %q", s)
		}
		out = append(out, r)
	}
	return out, nil
}

// lastOf returns the last address of a (masked) prefix.
func lastOf(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Contains reports whether a is inside the range.
func (r Range) Contains(a netip.Addr) bool {
	a = norm(a)
	return a.IsValid() && a.BitLen() == r.First.BitLen() && !a.Less(r.First) && !r.Last.Less(a)
}

// Size is the number of addresses in the range.
func (r Range) Size() *big.Int {
	n := new(big.Int).Sub(toInt(r.Last), toInt(r.First))
	return n.Add(n, big.NewInt(1))
}

func toInt(a netip.Addr) *big.Int {
	b := a.AsSlice()
	return new(big.Int).SetBytes(b)
}

// merge sorts and coalesces overlapping or adjacent ranges.
func merge(in []Range) []Range {
	if len(in) == 0 {
		return nil
	}
	rs := append([]Range(nil), in...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].First.Less(rs[j].First) })
	out := []Range{rs[0]}
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if next := last.Last.Next(); !next.IsValid() || !next.Less(r.First) {
			if last.Last.Less(r.Last) {
				last.Last = r.Last
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// ClampSize converts a count to int, saturating at the platform maximum.
func ClampSize(n *big.Int) int {
	if n.Sign() < 0 {
		return 0
	}
	if !n.IsInt64() || n.Int64() > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(n.Int64())
}

// Prefix length limits of IPv6 networks. The helper accepts proxied prefixes between /48 and /120 only (a prefix
// shorter than /48 would let the daemon answer for a whole site's worth of addresses), so the subnet of a proxy-mode
// network is between /48 and /120. A routed subnet is the operator's
// own routed prefix, from the smallest RIR allocation (/32) down to a /126.
const (
	ProxyApproveMin6 = 48
	ProxyApproveMax6 = 120
	ProxySubnetMin6  = 48
	RoutedSubnetMin6 = 32
	SubnetMax6       = 126
)
