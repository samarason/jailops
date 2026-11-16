package render

import (
	"net/netip"
	"regexp"

	"jailops.net/jailops/internal/validate"
)

var wgIfaceRE = regexp.MustCompile(`^wg[A-Za-z0-9_.-]{1,13}$`)

// PFWireGuard renders the anchor jailops/wg.<name> of a WireGuard server: traffic that comes in on the tunnel from
// the tunnel's own subnets may go to the subnets of the JailOps networks the server names, and everything else a peer
// sends is dropped (the jails' own policies still apply to what is admitted). Without networks the anchor is empty
// ("" is returned and the anchor is flushed).
func PFWireGuard(name, iface string, tunnels, networks []netip.Prefix) (string, error) {
	if err := validate.Name("wireguard", name); err != nil {
		return "", err
	}
	if !wgIfaceRE.MatchString(iface) {
		return "", validate.Invalid("interface", "invalid wireguard interface %q", iface)
	}
	var b builder
	n := 0
	for _, to := range networks {
		for _, from := range tunnels {
			if !from.IsValid() || !to.IsValid() || from.Addr().Is4() != to.Addr().Is4() {
				continue
			}
			if n == 0 {
				b.line("%s", Header)
				b.line("# anchor jailops/wg.%s: the peers of the tunnel reach these JailOps networks", name)
			}
			fam := "inet"
			if from.Addr().Is6() {
				fam = "inet6"
			}
			b.line("pass in quick on %s %s from %s to %s", iface, fam, from.Masked(), to.Masked()) // labelPassRules adds the label and keep state (if-bound)
			n++
		}
	}
	if n == 0 {
		return "", nil
	}
	// The anchor confines the tunnel: whatever a peer sends that the rules above do not admit is dropped here, so the
	// host's own ruleset does not decide what a peer may reach (the host itself and its LAN included).
	b.line("# nothing else from the peers")
	b.line("block drop in quick on %s all", iface)
	out, err := b.result()
	if err != nil {
		return "", err
	}
	// The pass rules carry the label and the interface-bound state of every other anchor: a floating state would carry
	// a connection through the second hop (the jail's anchor) without that hop's rules looking at it.
	return labelPassRules("jailops/wg."+name, out, 0), nil
}
