package ipam

import "strings"

// driverNames are the names FreeBSD's network drivers and interface cloners give their interfaces (a unit number
// follows the name: vmx0, em1, bridge0, epair3a, tap0, wg0, lo0, vlan5) and the interface groups the kernel makes of
// them (every interface is in the group of its driver and in "all"). The list is conservative: a name on it is refused
// for an interface JailOps creates although no such driver may be loaded, so that a device the kernel attaches later,
// or a group a packet filter rule names, is never confused with an interface of JailOps.
var driverNames = map[string]bool{
	// groups and pseudo interfaces of the base system
	"all": true, "lo": true, "bridge": true, "epair": true, "tap": true, "tun": true, "vmnet": true, "vlan": true,
	"lagg": true, "gif": true, "gre": true, "stf": true, "me": true, "ipsec": true, "vxlan": true, "geneve": true,
	"wg": true, "ovpn": true, "pflog": true, "pfsync": true, "enc": true, "carp": true, "disc": true, "edsc": true,
	"faith": true, "ipfw": true, "ng": true, "ngeth": true, "ppp": true, "sl": true, "usbus": true, "wlan": true,
	// Ethernet drivers
	"ae": true, "age": true, "al": true, "alc": true, "ale": true, "an": true, "aue": true, "awg": true, "axe": true,
	"axge": true, "bce": true, "bfe": true, "bge": true, "bnxt": true, "bxe": true, "cas": true, "cc": true,
	"cdce": true, "cgem": true, "cpsw": true, "cue": true, "cxl": true, "cxgbe": true, "dc": true, "dwc": true,
	"em": true, "ena": true, "enetc": true, "eqos": true, "et": true, "ffec": true, "fxp": true, "gem": true,
	"genet": true, "gve": true, "hme": true, "hn": true, "iavf": true, "ice": true, "igb": true, "igc": true,
	"ipheth": true, "ix": true, "ixl": true, "ixv": true, "jme": true, "kue": true, "lge": true, "lio": true,
	"mana": true, "mce": true, "mgb": true, "mlxen": true, "mos": true, "msk": true, "muge": true, "mvneta": true,
	"mxge": true, "my": true, "neta": true, "nfe": true, "nge": true, "oce": true, "ql": true, "qlnxe": true,
	"qlxgb": true, "qlxgbe": true, "qlxge": true, "re": true, "rl": true, "rue": true, "sf": true, "sfxge": true,
	"sge": true, "sis": true, "sk": true, "smsc": true, "ste": true, "stge": true, "ti": true, "tl": true,
	"tx": true, "txp": true, "udav": true, "ue": true, "ure": true, "urndis": true, "vcc": true, "vcxl": true,
	"vge": true, "vmx": true, "vr": true, "vtnet": true, "wb": true, "xae": true, "xe": true, "xl": true,
	"xn": true, "xnb": true,
	// wireless drivers
	"ath": true, "bwi": true, "bwn": true, "ipw": true, "iwi": true, "iwlwifi": true, "iwm": true, "iwn": true,
	"iwx": true, "malo": true, "mtw": true, "mwl": true, "otus": true, "ral": true, "rsu": true, "rtw": true,
	"rtwn": true, "rum": true, "run": true, "uath": true, "upgt": true, "ural": true, "urtw": true, "wi": true,
	"wpi": true, "zyd": true,
}

// DriverLikeName reports whether name has the form of an interface a FreeBSD driver, a cloner or the kernel names:
// a driver name from the list above alone (an interface group), or followed by a unit number, optionally with the end
// of an epair (a, b) or a vlan tag (.N): "vmx0", "lo0", "bridge0", "epair0a", "vlan0.10", "tap0", "wg0", "pflog0",
// "bridge". It returns the driver name it matched. Case does not matter.
func DriverLikeName(name string) (string, bool) {
	n := strings.ToLower(name)
	i := 0
	for i < len(n) && n[i] >= 'a' && n[i] <= 'z' {
		i++
	}
	drv, rest := n[:i], n[i:]
	if !driverNames[drv] {
		return "", false
	}
	if rest == "" {
		return drv, true
	}
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return "", false
	}
	switch tail := rest[j:]; {
	case tail == "", tail == "a", tail == "b":
		return drv, true
	case len(tail) > 1 && tail[0] == '.' && strings.Trim(tail[1:], "0123456789") == "":
		return drv, true
	}
	return "", false
}
