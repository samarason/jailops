package priv

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Rules of an anchor decide for the whole host: a rule that stands on the uplink, or on no interface at all, with the
// verdict quick, passes or blocks traffic of the host itself before the host's own rules look at it. The helper therefore
// loads a rule only when it names an interface JailOps owns, or the uplink of a network in one of three shapes the
// renderer writes (a translation, a forward and the pass that belongs to it), with a destination that is no address of
// the host. A ruleset that stands on anything else is the operator's to allow (AdminPolicy.RawPF).

var (
	reOnIfaces = regexp.MustCompile(`\bon\s+(\{[^}]*\}|\S+)`)
	reTo       = regexp.MustCompile(`\bto\s+(\S+)`)
	reDnpipe   = regexp.MustCompile(`\bdnpipe\s*(\([0-9, ]+\)|[0-9]+)`)
)

// checkAnchorInterfaces checks the ruleset of an anchor the helper is asked to load.
func (l *Local) checkAnchorInterfaces(ctx context.Context, anchor, rs string) error {
	if l.cfg.Admin.RawPF {
		return nil
	}
	var uplinks map[string]bool // read when a rule needs it
	for k, ln := range strings.Split(rs, "\n") {
		t := strings.TrimSpace(ln)
		at := "ruleset line " + strconv.Itoa(k+1) // never the text of the line: it may hold what must not reach the audit log
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "table ") {
			continue
		}
		f := strings.Fields(t)
		switch f[0] {
		case "anchor":
			continue // the project anchor's own wildcard
		case "pass", "block", "match":
		default:
			return forbidden("%s: an anchor holds pass, block and match rules and tables only", at)
		}
		m := reOnIfaces.FindStringSubmatch(t)
		if m == nil {
			return forbidden("%s names no interface: every rule of an anchor stands on an interface of a jail (on IFACE)", at)
		}
		for _, d := range reDnpipe.FindAllStringSubmatch(t, -1) {
			for _, n := range strings.FieldsFunc(d[1], func(r rune) bool { return r < '0' || r > '9' }) {
				if v, err := strconv.Atoi(n); err != nil || (v != 0 && !render.IsManagedPipe(v)) { // 0: no pipe for that direction
					return forbidden("%s: dnpipe %s is not a pipe of JailOps's range", at, n)
				}
			}
		}
		names := strings.FieldsFunc(strings.Trim(m[1], "{}"), func(r rune) bool { return r == ',' || r == ' ' })
		for _, n := range names {
			if err := ifconfig.ValidateIfName(n); err != nil {
				return err
			}
			if l.ifOwned(ctx, n) == nil || strings.HasPrefix(anchor, AnchorPrefix+"wg.") && l.ifIsTunnel(ctx, n) {
				continue
			}
			if uplinks == nil {
				uplinks = l.networkUplinks()
			}
			if !uplinks[n] {
				return forbidden("%s stands on %s, which is not an interface of JailOps or the uplink of a network", at, n)
			}
			if err := l.uplinkShape(ctx, at, t); err != nil {
				return err
			}
		}
	}
	return nil
}

// ifIsTunnel says whether name is a WireGuard interface JailOps made (its description carries the marker).
func (l *Local) ifIsTunnel(ctx context.Context, name string) bool {
	rd, err := l.ifReader(name)
	if err != nil {
		return false
	}
	i, err := rd.Show(ctx, name)
	if err != nil || !ifconfig.HasMarker(i.Description) {
		return false
	}
	for _, g := range i.Groups {
		if g == "wg" {
			return true
		}
	}
	return false
}

// uplinkShape accepts a rule on an uplink only in the forms the renderer writes for a network's translation and a
// jail's port forwards.
func (l *Local) uplinkShape(ctx context.Context, at, t string) error {
	switch {
	case strings.HasPrefix(t, "match in on ") && strings.Contains(t, " rdr-to "):
		return l.checkForward(ctx, at, t)
	case strings.HasPrefix(t, "match out on ") && strings.Contains(t, " nat-to "):
		return nil
	case strings.HasPrefix(t, "pass in quick on "):
		m := reTo.FindStringSubmatch(t)
		if m == nil {
			return forbidden("%s: a rule on the uplink names its destination", at)
		}
		a, err := netip.ParseAddr(strings.Trim(m[1], "{}"))
		if err != nil {
			return forbidden("%s: a rule on the uplink names one address of a jail as its destination", at)
		}
		local, _ := localAddrs()
		for _, h := range local {
			if h == a.Unmap() {
				return forbidden("%s: the destination %s is an address of the host", at, a)
			}
		}
		return nil
	}
	return forbidden("%s: a rule on the uplink must be a translation, a forward or the pass of a forward", at)
}

// networkUplinks are the uplinks of the networks JailOps has stored.
func (l *Local) networkUplinks() map[string]bool {
	out := map[string]bool{}
	dir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindNetwork))
	names, err := l.listState(dir)
	if err != nil {
		return out
	}
	for _, n := range names {
		if !strings.HasSuffix(n, ".json") {
			continue
		}
		b, err := l.readState(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		var d networkDoc
		if json.Unmarshal(b, &d) == nil && d.Spec.Uplink != "" {
			out[d.Spec.Uplink] = true
		}
	}
	return out
}

var reForward = regexp.MustCompile(`\bto\s+(\S+)\s+port\s+([0-9]+)\s+rdr-to\s+(\S+)\s+port\s+([0-9]+)\s*$`)

// checkForward accepts a forward (match in on UPLINK ... to ADDR port N rdr-to JAIL port M) when it leads to a jail and
// leaves the host's own ports alone: the target is an address of a network JailOps has stored, never one of the host,
// and the port it takes over on the host is neither a privileged port nor one a host process listens on, unless the
// request carries the admin assertion (the API asks for a global administrator for that). Without it a compromised
// daemon, or a project administrator, could send the host's ssh or console port into a jail of their own.
func (l *Local) checkForward(ctx context.Context, at, t string) error {
	m := reForward.FindStringSubmatch(t)
	if m == nil {
		return forbidden("%s: a forward names its port and its target as the renderer writes them", at)
	}
	target, err := netip.ParseAddr(strings.Trim(m[3], "{}"))
	if err != nil {
		return forbidden("%s: the target of a forward is one address of a jail", at)
	}
	local, _ := localAddrs()
	for _, h := range local {
		if h == target.Unmap() {
			return forbidden("%s: the target %s is an address of the host", at, target)
		}
	}
	if err := l.checkStoredNetworkAddr(target, "the target of a forward"); err != nil {
		return forbidden("%s: %v", at, err)
	}
	port, _ := strconv.Atoi(m[2])
	if isAdmin(ctx) {
		return nil
	}
	if port < 1024 {
		return forbidden("%s: the host's port %d is a privileged port: forwarding it needs the admin assertion", at, port)
	}
	if hostListens(ctx, l, port) {
		return forbidden("%s: a process of the host listens on port %d: forwarding it needs the admin assertion", at, port)
	}
	return nil
}

// hostListens says whether a process of the host listens on the port (sockstat(1), any address, tcp or udp). A lookup
// that fails says no.
func hostListens(ctx context.Context, l *Local, port int) bool {
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "sockstat", Args: []string{"-46l"}, Timeout: 10 * time.Second})
	if err != nil {
		return false
	}
	want := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && strings.HasSuffix(f[5], want) {
			return true
		}
	}
	return false
}
