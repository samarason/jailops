package render

import (
	"strings"

	"jailops.net/jailops/internal/sys/ifconfig"
)

// Interface descriptions. Every interface JailOps creates carries a short, fixed, one-line text that says what it is,
// shown by ifconfig(8) as "description: TEXT". The text is built from names only (never from free text or secrets),
// uses the characters of IfaceDescCharset and is at most IfaceDescMax bytes long. A name that does not fit is cut
// and ends in "..", so the same names always give the same text and the reconcile loop can compare it.

// IfaceDescMax is the longest description JailOps writes.
const IfaceDescMax = 64

// IfaceDescCharset lists the characters a description may hold besides letters and digits.
const IfaceDescCharset = " ._:/=()-"

// IsJailOpsDesc reports whether a description is one JailOps writes. It is the helper's ownership
// marker (ifconfig.HasMarker): the helper changes only interfaces that carry it.
func IsJailOpsDesc(d string) bool { return ifconfig.HasMarker(d) }

// OwnsIface reports whether an interface whose name JailOps derives from one of its objects is that object's: it carries
// the wanted text, or the bare marker the helper writes when it creates an interface (ifconfig.Marker: made, not
// described yet). An interface without a description, or with another one, may be someone else's and is left alone.
func OwnsIface(desc, want string) bool {
	return desc != "" && (desc == want || desc == ifconfig.Marker)
}

// ValidIfaceDesc reports whether d is a description JailOps may write: at most IfaceDescMax bytes of letters,
// digits and IfaceDescCharset. The empty description (clearing it) is valid.
func ValidIfaceDesc(d string) bool {
	if len(d) > IfaceDescMax {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(IfaceDescCharset, c) >= 0) {
			return false
		}
	}
	return true
}

// JailIfaceDesc is the description of one end of a jail's epair: the host side is the routed link of the jail on the
// host, the jail side lives in the jail's vnet.
func JailIfaceDesc(project, jail, network string, hostSide bool) string {
	side := " (jail side)"
	if hostSide {
		side = " (host side)"
	}
	return buildDesc([]descField{{"jail", project + "/" + jail}, {"net", network}}, side)
}

// WireGuardDesc is the description of a WireGuard interface.
func WireGuardDesc(name string) string {
	return buildDesc([]descField{{"wireguard", name}}, "")
}

type descField struct{ key, val string }

// buildDesc renders "jailops key=val ... suffix", cutting the longest values until the text fits.
func buildDesc(fields []descField, suffix string) string {
	vals := make([]string, len(fields))
	fixed := len("jailops") + len(suffix)
	for i, f := range fields {
		vals[i] = descValue(f.val)
		fixed += 1 + len(f.key) + 1
	}
	vals = fitValues(fixed, vals)
	var b strings.Builder
	b.WriteString("jailops")
	for i, f := range fields {
		b.WriteString(" " + f.key + "=" + vals[i])
	}
	b.WriteString(suffix)
	return b.String()
}

// descValue keeps the characters a value may hold; anything else becomes '.'. Names are validated long before they
// get here; this only makes sure a text never carries what it must not.
func descValue(v string) string {
	b := []byte(v)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '/' || c == ':') {
			b[i] = '.'
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

// fitValues shortens the longest value, one character at a time, until fixed plus the values fit IfaceDescMax. A cut
// value ends in "..". Values of four characters or less are never cut.
func fitValues(fixed int, vals []string) []string {
	total := fixed
	for _, v := range vals {
		total += len(v)
	}
	cut := make([]bool, len(vals))
	for total > IfaceDescMax {
		i := -1
		for k, v := range vals {
			if len(v) > 4 && (i < 0 || len(v) > len(vals[i])) {
				i = k
			}
		}
		if i < 0 {
			break
		}
		v := vals[i]
		if !cut[i] {
			vals[i], cut[i] = v[:len(v)-3]+"..", true
		} else {
			vals[i] = v[:len(v)-3] + ".."
		}
		total--
	}
	return vals
}
