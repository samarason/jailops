package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Hook phases, the first argument of "jailops-priv hook". They are the exec.*
// hooks of jail.conf (render.JailConf).
const (
	PhasePreStart  = "prestart"
	PhasePostStart = "poststart"
	PhasePreStop   = "prestop"
	PhasePostStop  = "poststop"
)

// PFAnchorFile is where the reconcile loop leaves the rendered PF anchor of a
// jail (named by its internal name), below StateDir. The hook loads it when
// it exists.
func (c Config) PFAnchorFile(jail string) string {
	return filepath.Join(c.StateDir, "rendered", "pf", jail+".conf")
}

// jailRecord is the part of spec.json the hook reads.
type jailRecord struct {
	Metadata api.ObjectMeta `json:"metadata"`
	Spec     api.JailSpec   `json:"spec"`
}

type networkDoc struct {
	Kind     api.Kind        `json:"kind"`
	Metadata api.ObjectMeta  `json:"metadata"`
	Spec     api.NetworkSpec `json:"spec"`
}

// attachment is one planned interface of a jail.
type attachment struct {
	in    render.AttachInput
	steps []render.Step
	host  string // host side epair end
	jail  string // jail side epair end
}

// readState reads a file below the daemon's state directory. That directory is the daemon's, so the helper opens
// it as an untrusted tree: no component may leave it, and what is read is size-bounded.
func (l *Local) readState(path string) ([]byte, error) {
	rel, err := filepath.Rel(l.cfg.StateDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, forbidden("%q is outside the state directory", path)
	}
	root, err := os.OpenRoot(l.cfg.StateDir)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, invalid("%q is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

// listState lists a directory below the state directory (see readState).
func (l *Local) listState(path string) ([]string, error) {
	rel, err := filepath.Rel(l.cfg.StateDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, forbidden("%q is outside the state directory", path)
	}
	root, err := os.OpenRoot(l.cfg.StateDir)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer root.Close()
	d, err := root.Open(rel)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, mapFSErr(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}

func (l *Local) listDir(rel string) ([]string, error) {
	r, err := l.cfg.resolve(rel)
	if err != nil {
		return nil, err
	}
	root, err := r.openRoot()
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer root.Close()
	d, err := root.Open(r.rel)
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, mapFSErr(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out, nil
}

// jailDataset finds the container dataset of a jail: the first candidate
// that exists in a registered root. Two roots holding the same jail is a
// conflict, not a choice.
func (l *Local) jailDataset(ctx context.Context, n JailName) (string, error) {
	var found []string
	for _, root := range l.cfg.Roots() {
		for _, ds := range jailDatasets(root, n) {
			ok, err := l.ZFS().Exists(ctx, ds)
			if err != nil {
				return "", err
			}
			if ok {
				found = append(found, ds)
				break
			}
		}
	}
	switch len(found) {
	case 0:
		return "", api.Errorf(api.CodeNotFound, "no dataset for jail %s in any storage root", n.Internal())
	case 1:
		return found[0], nil
	}
	return "", api.Errorf(api.CodeConflict, "jail %s exists in more than one storage root: %s", n.Internal(), strings.Join(found, ", "))
}

// loadRecord reads spec.json (or its .previous copy) of a jail from the
// mountpoint of its container dataset.
func (l *Local) loadRecord(ctx context.Context, n JailName) (*jailRecord, error) {
	ds, err := l.jailDataset(ctx, n)
	if err != nil {
		return nil, err
	}
	props, err := l.ZFS().Get(ctx, ds, "mountpoint")
	if err != nil {
		return nil, fmt.Errorf("jail dataset %s: %w", ds, err)
	}
	mp := props["mountpoint"].Value
	if !filepath.IsAbs(mp) {
		return nil, api.Errorf(api.CodeNotFound, "dataset %s has no mountpoint (%q)", ds, mp)
	}
	var b []byte
	for _, f := range []string{"spec.json", "spec.json.previous"} {
		if b, err = l.ReadFile(ctx, filepath.Join(mp, f)); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read spec.json of %s: %w", n.Internal(), err)
	}
	var rec jailRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("spec.json of %s: %w", n.Internal(), err)
	}
	if rec.Metadata.Name != n.Name {
		return nil, api.Errorf(api.CodeConflict, "spec.json in %s names jail %q, not %q", ds, rec.Metadata.Name, n.Name)
	}
	proj := rec.Metadata.Project
	if proj == "" {
		return nil, api.Errorf(api.CodeInvalid, "spec.json of %s names no project", n.Internal())
	}
	if proj != n.Project {
		return nil, api.Errorf(api.CodeConflict, "spec.json in %s belongs to project %q, not %q", ds, proj, n.Project)
	}
	if rec.Metadata.UUID == "" {
		return nil, api.Errorf(api.CodeInvalid, "spec.json of %s has no uuid", n.Internal())
	}
	return &rec, nil
}

// loadNetwork finds the Network object with the given name in the state
// directory (objects/Network/<uuid>.json).
func (l *Local) loadNetwork(ctx context.Context, name string) (*networkDoc, error) {
	dir := filepath.Join(l.cfg.StateDir, "objects", string(api.KindNetwork))
	names, err := l.listState(dir)
	if err != nil {
		return nil, fmt.Errorf("network objects: %w", err)
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
		if json.Unmarshal(b, &d) == nil && d.Metadata.Name == name {
			return &d, nil
		}
	}
	return nil, api.Errorf(api.CodeNotFound, "network %q is not in the state directory", name)
}

func guestAddr(raw string, bits int, v6 bool) (netip.Prefix, error) {
	switch raw {
	case "", "none":
		return netip.Prefix{}, nil
	case "auto":
		return netip.Prefix{}, api.Errorf(api.CodeInvalid, "address is still \"auto\"; it must be allocated before the jail starts")
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Is6() != v6 {
		return netip.Prefix{}, api.Errorf(api.CodeInvalid, "invalid address %q", raw)
	}
	return netip.PrefixFrom(a, bits), nil
}

// planJail builds the attachments of a jail from its spec and networks.
func (l *Local) planJail(ctx context.Context, name JailName) ([]attachment, error) {
	rec, err := l.loadRecord(ctx, name)
	if err != nil {
		return nil, err
	}
	var out []attachment
	for i, att := range rec.Spec.Network {
		nw, err := l.loadNetwork(ctx, att.Network)
		if err != nil {
			return nil, err
		}
		in := render.AttachInput{
			JailID: rec.Metadata.UUID, JailUUID: rec.Metadata.UUID, Index: i,
			Project: name.Project, Jail: name.Name, Network: att.Network,
			MAC: att.MAC, MTU: nw.Spec.MTU, Uplink: nw.Spec.Uplink,
			HostConfigured: rec.Spec.OS == api.OSLinux,
		}
		if v4 := nw.Spec.IPv4; v4 != nil {
			var err error
			if in.IPv4, err = guestAddr(att.IPv4, ipam.GuestPrefixLen4(), false); err != nil {
				return nil, err
			}
			if gw, err := netip.ParseAddr(v4.Gateway); err == nil && in.IPv4.IsValid() {
				in.Gateway4 = gw
			}
		}
		if v6 := nw.Spec.IPv6; v6 != nil && v6.Mode != api.IPv6None {
			p, err := netip.ParsePrefix(v6.Subnet)
			if err != nil {
				return nil, fmt.Errorf("network %s: %w", att.Network, err)
			}
			in.IPv6Mode = v6.Mode
			if in.IPv6, err = guestAddr(att.IPv6, ipam.GuestPrefixLen6(v6.Mode, p.Bits()), true); err != nil {
				return nil, err
			}
			if in.IPv6.IsValid() {
				in.Gateway6 = ipam.GatewayLinkLocal6
			}
		}
		steps, err := render.AttachPlan(in)
		if err != nil {
			return nil, fmt.Errorf("attachment %d: %w", i, err)
		}
		h, j, _ := ipam.EpairNames(rec.Metadata.UUID, i)
		out = append(out, attachment{in: in, steps: steps, host: h, jail: j})
	}
	return out, nil
}

// RunHook implements "jailops-priv hook <phase> <jail>". It is idempotent:
// running a phase twice leaves the same state as running it once, and a
// poststop of a jail that was never started succeeds.
func (l *Local) RunHook(ctx context.Context, phase, jail string) error {
	jn, err := ParseJailName(jail)
	if err != nil {
		return err
	}
	switch phase {
	case PhasePreStop:
		return nil // nothing to undo while the jail still runs
	case PhasePreStart, PhasePostStart, PhasePostStop:
	default:
		return invalid("unknown hook phase %q", phase)
	}
	atts, err := l.planJail(ctx, jn)
	if err != nil {
		if phase == PhasePostStop {
			// The spec may be gone with the jail; still drop the anchor and the rctl rules,
			return errors.Join(err, l.dropJailAnchor(ctx, jn), l.dropLimits(ctx, jn))
		}
		return err
	}
	switch phase {
	case PhasePreStart:
		rec, err := l.loadRecord(ctx, jn)
		if err != nil {
			return err
		}
		if err := l.loadDevfs(ctx, rec); err != nil {
			return err // the jail must never start on a devfs ruleset that was not loaded
		}
		return l.hookPreStart(ctx, jn, atts)
	case PhasePostStart:
		return l.hookPostStart(ctx, jn, atts)
	}
	return l.hookPostStop(ctx, jn, atts)
}

func ignoreNotFound(err error) error {
	if err == nil || api.IsCode(err, api.CodeNotFound) {
		return nil
	}
	return err
}

func ignoreExists(err error) error {
	if err == nil || api.IsCode(err, api.CodeAlreadyExists) {
		return nil
	}
	return err
}

func (l *Local) hostIfaces(ctx context.Context) (map[string]ifconfig.Iface, error) {
	list, err := l.Net().List(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string]ifconfig.Iface{}
	for _, i := range list {
		m[i.Name] = i
	}
	return m, nil
}

func (l *Local) hookPreStart(ctx context.Context, jn JailName, atts []attachment) error {
	for _, a := range atts {
		for _, st := range hostSteps(a.steps) {
			if err := l.applyHost(ctx, st); err != nil {
				return fmt.Errorf("%s: %w", st.Describe(), err)
			}
		}
	}
	// pf must run: with pf disabled the anchor is loaded and nothing evaluates it, and the jail would run with no
	// firewall at all (and no NAT). A host where pfctl does not answer is not judged.
	if len(atts) > 0 && !l.cfg.AllowStartWithoutPF {
		if on := l.pfEnabled(ctx); on != nil && !*on {
			return fmt.Errorf("pf is disabled: not starting jail %s with a network link without its firewall (enable pf with `service pf onestart` or pfctl -e, or set allow-start-without-pf in priv.conf)", jn.Internal())
		}
	}
	// The jail's anchor is in place before its first process runs: jail(8) runs exec.start next, and the whole of
	// /etc/rc would otherwise run with the host's rules alone. The host end of every epair exists now, which the rules
	// name.
	return l.loadJailAnchor(ctx, jn, len(atts) > 0)
}

// loadJailAnchor loads the rendered anchor of a jail and the parent anchor of its project that makes pf evaluate it.
// A jail without a link has no anchor; a jail with a link and no rendered anchor does not start: it would be open to
// the rules of the host alone.
func (l *Local) loadJailAnchor(ctx context.Context, jn JailName, hasLinks bool) error {
	b, err := l.readState(l.cfg.PFAnchorFile(jn.Internal()))
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			if hasLinks {
				return fmt.Errorf("jail %s has a network link and no rendered pf anchor: refusing to start it without a firewall", jn.Internal())
			}
			return nil
		}
		return fmt.Errorf("read rendered pf anchor: %w", err)
	}
	// The parent anchor jailops/<project> must exist first, or PF never evaluates the jail's anchor. The reconcile loop
	// loads it too.
	parent := render.ProjectAnchor(jn.Project)
	if cur, perr := l.PF().Read(ctx, parent); perr != nil || strings.TrimSpace(cur) == "" {
		if err := l.PF().Load(ctx, parent, render.ProjectAnchorRules()); err != nil {
			return fmt.Errorf("load parent pf anchor %s: %w", parent, err)
		}
	}
	if err := l.PF().Load(ctx, JailAnchor(jn), string(b)); err != nil {
		return fmt.Errorf("load pf anchor: %w", err)
	}
	return nil
}

func (l *Local) hookPostStart(ctx context.Context, jn JailName, atts []attachment) error {
	jail := jn.Internal()
	for _, a := range atts {
		have, err := l.hostIfaces(ctx)
		if err != nil {
			return err
		}
		// jail.conf's vnet.interface normally moved the jail end already.
		if _, still := have[a.jail]; still {
			if err := l.Net().MoveToJail(ctx, a.jail, jail); err != nil {
				return fmt.Errorf("move %s into %s: %w", a.jail, jail, err)
			}
		}
		for _, s := range a.steps {
			if s.Phase != render.PhaseJail {
				continue
			}
			if err := l.applyJail(ctx, jail, s); err != nil {
				return fmt.Errorf("%s: %w", s.Describe(), err)
			}
		}
	}
	if err := l.applyLimits(ctx, jn); err != nil {
		return fmt.Errorf("resource limits: %w", err)
	}
	return nil
}

// hookPostStop takes down what the jail's start put on the host. It is best effort and every step runs whatever the
// steps before it did: a jail that stops must never be reported as failed because an address, a route or a rule was
// already gone (a jail started by an earlier version has other addresses and routes than the ones this version
// removes). What did not work is logged as a warning and not returned; the epair goes last and always, and a leftover
// is removed by the next start.
func (l *Local) hookPostStop(ctx context.Context, jn JailName, atts []attachment) error {
	var errs []error
	if err := l.dropLimits(ctx, jn); err != nil {
		errs = append(errs, fmt.Errorf("resource limits: %w", err))
	}
	if err := l.dropJailAnchor(ctx, jn); err != nil {
		errs = append(errs, err)
	}
	for k := len(atts) - 1; k >= 0; k-- {
		var destroy []render.Step
		for _, s := range render.Rollback(hostSteps(atts[k].steps)) {
			if s.Op == render.OpEpairDestroy {
				destroy = append(destroy, s)
				continue
			}
			if err := ignoreNotFound(l.applyHost(ctx, s)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Describe(), err))
			}
		}
		for _, s := range destroy {
			if err := ignoreNotFound(l.applyHost(ctx, s)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Describe(), err))
			}
		}
	}
	if len(errs) > 0 {
		l.note("jail teardown finished with warnings", "jail", jn.Internal(), "warnings", errors.Join(errs...).Error())
		fmt.Fprintf(os.Stderr, "jailops-priv: stopped %s; cleanup warnings: %v\n", jn.Internal(), errors.Join(errs...))
	}
	return nil
}

// dropJailAnchor ends the states of the rules of a jail's anchor and empties the anchor. The states go first: pf keeps
// the state of a connection that a rule admitted after the rule is gone, and the address of a jail that is deleted
// goes to the next jail, whose connection a state of the old one would carry.
func (l *Local) dropJailAnchor(ctx context.Context, jn JailName) error {
	anchor := JailAnchor(jn)
	var errs []error
	if live, err := l.PF().Read(ctx, anchor); err == nil {
		labels := make([]string, 0)
		for lb := range pfctl.LabelsOf(live) {
			labels = append(labels, lb)
		}
		slices.Sort(labels)
		for _, lb := range labels {
			if err := ignoreNotFound(l.PF().KillLabel(ctx, lb)); err != nil {
				errs = append(errs, fmt.Errorf("end the states of rule %s: %w", lb, err))
			}
		}
	}
	if err := ignoreNotFound(l.PF().Flush(ctx, anchor)); err != nil {
		errs = append(errs, fmt.Errorf("flush pf anchor: %w", err))
	}
	return errors.Join(errs...)
}

func hostSteps(steps []render.Step) []render.Step {
	var out []render.Step
	for _, s := range steps {
		if s.Phase == render.PhaseHost {
			out = append(out, s)
		}
	}
	return out
}

func (l *Local) ifconfigRun(ctx context.Context, args ...string) error {
	_, err := l.d.Runner.Run(ctx, run.Cmd{Name: "ifconfig", Args: args, Timeout: 20 * time.Second})
	if ee, ok := run.IsExit(err); ok {
		low := strings.ToLower(ee.Stderr)
		if strings.Contains(low, "does not exist") || strings.Contains(low, "interface not found") {
			return api.Errorf(api.CodeNotFound, "ifconfig: %s", strings.TrimSpace(ee.Stderr))
		}
		return api.Errorf(api.CodeInternal, "ifconfig: %s", strings.TrimSpace(ee.Stderr))
	}
	return err
}

// applyHost runs one host phase step (or the inverse of one). Steps are
// idempotent: an object that already is in the wanted state is not an error.
// UNVERIFIED: every command on FreeBSD.
func (l *Local) applyHost(ctx context.Context, s render.Step) error {
	net := l.Net()
	switch s.Op {
	case render.OpEpairCreate:
		have, err := l.hostIfaces(ctx)
		if err != nil {
			return err
		}
		if _, ok := have[s.Iface]; ok {
			// There already: the name is derived from this jail and this jail is starting, so nothing runs on it. It is
			// what a teardown left behind (a start or stop that failed half way, or a jail started by a version that
			// joined the epair to a bridge): destroy it, with the bridge membership it carries, and make a new one. A
			// name that is not JailOps's is refused.
			if err := l.ifOwned(ctx, s.Iface); err != nil {
				return err
			}
			if err := net.EpairDestroy(ctx, s.Iface); ignoreNotFound(err) != nil {
				return fmt.Errorf("remove the leftover interface %s: %w", s.Iface, err)
			}
		}
		a, b, err := net.EpairCreate(ctx, strings.TrimSuffix(s.Iface, "a"))
		if err != nil {
			return err
		}
		if a != s.Iface || b != s.Arg2 {
			return api.Errorf(api.CodeInternal, "epair created as %s/%s, wanted %s/%s", a, b, s.Iface, s.Arg2)
		}
		return nil
	case render.OpEpairDestroy:
		return net.EpairDestroy(ctx, s.Iface)
	case render.OpSetMAC:
		// The jail end may already live in a running jail's vnet: not found on the host is not an error.
		if err := l.ifOwned(ctx, s.Iface); err != nil {
			return ignoreNotFound(err)
		}
		if err := validMAC(s.Arg); err != nil {
			return err
		}
		// The jail end may already live in a running jail's vnet.
		return ignoreNotFound(l.ifconfigRun(ctx, s.Iface, "ether", s.Arg))
	case render.OpSetMTU:
		if err := ifconfig.ValidateIfName(s.Iface); err != nil {
			return err
		}
		if s.Arg == "" || len(s.Arg) > 5 || strings.Trim(s.Arg, "0123456789") != "" {
			return invalid("invalid mtu %q", s.Arg)
		}
		n, _ := strconv.Atoi(s.Arg)
		return ignoreNotFound(l.SetMTU(ctx, s.Iface, n))
	case render.OpSetDescription:
		return net.SetDescription(ctx, s.Iface, s.Arg)
	case render.OpAddAddr, render.OpRemoveAddr:
		p, err := netip.ParsePrefix(s.Arg)
		if err != nil {
			return invalid("invalid address %q", s.Arg)
		}
		if s.Op == render.OpAddAddr {
			return l.addAddr(ctx, s.Iface, p)
		}
		return ignoreNotFound(net.AddrRemove(ctx, s.Iface, p))
	case render.OpIfaceUp:
		return net.SetLink(ctx, s.Iface, true)
	case render.OpIfaceDown:
		return net.SetLink(ctx, s.Iface, false)
	case render.OpAddHostRoute:
		return ignoreExists(net.RouteAdd(ctx, ifconfig.Route{Dest: s.Arg, Interface: s.Iface}))
	case render.OpDelHostRoute:
		return net.RouteDelete(ctx, ifconfig.Route{Dest: s.Arg, Interface: s.Iface})
	case render.OpNDPProxyAdd, render.OpNDPProxyDel:
		return nil // answered by the daemon's built-in proxy, not by the hook
	}
	return api.Errorf(api.CodeUnsupported, "hook cannot apply step %q", s.Op)
}

// addAddr puts a prefix on an interface. "File exists" means the address is on an interface already: this one (done),
// or another one, because the kernel refuses the same address twice in one subnet. The other one is what an earlier
// version left behind when it is an interface of JailOps (the gateway pair of the bridge network, which carried the
// gateway address with the network's prefix): the address is taken from it, the jails that still run on that bridge
// have to be restarted anyway. An interface that is not JailOps's is never touched.
func (l *Local) addAddr(ctx context.Context, iface string, p netip.Prefix) error {
	net := l.Net()
	err := net.AddrAdd(ctx, iface, p)
	if err == nil || !api.IsCode(err, api.CodeAlreadyExists) {
		return err
	}
	list, lerr := net.List(ctx)
	if lerr != nil {
		return err
	}
	for _, i := range list {
		var have []netip.Prefix
		for _, q := range append(slices.Clone(i.Inet), i.Inet6...) {
			if q.Addr() == p.Addr() {
				have = append(have, q)
			}
		}
		if len(have) == 0 {
			continue
		}
		if i.Name == iface {
			return nil
		}
		if oerr := l.ifOwned(ctx, i.Name); oerr != nil {
			return api.Errorf(api.CodeConflict, "the address %s is in use on %s, which JailOps does not manage", p.Addr(), i.Name)
		}
		if strings.HasPrefix(i.Name, "jo") && strings.HasSuffix(i.Name, "a") {
			// the host end of the link of a jail: its own gateway address, never taken from it
			return api.Errorf(api.CodeConflict, "the address %s is in use on %s, the link of another jail", p.Addr(), i.Name)
		}
		for _, q := range have {
			if rerr := ignoreNotFound(net.AddrRemove(ctx, i.Name, q)); rerr != nil {
				return fmt.Errorf("take %s from %s: %w", q, i.Name, rerr)
			}
		}
		l.note("took an address from an interface an earlier version left", "address", p.Addr().String(), "from", i.Name, "to", iface)
		fmt.Fprintf(os.Stderr, "jailops-priv: took %s from %s (left by an earlier version); jails still running on that bridge need a restart\n", p.Addr(), i.Name)
		return ignoreExists(net.AddrAdd(ctx, iface, p))
	}
	return err
}

func famWord(arg string) string {
	if strings.Contains(arg, ":") {
		return "inet6"
	}
	return "inet"
}

// applyJail runs one jail phase step from the host: the Linux userland has no
// usable network tools, so the host configures the jail's vnet with
// ifconfig -j and route -j through the validated command rules (verified on
// FreeBSD 15.1: addresses with "inet <addr>/<n> up" and "inet6 <addr>
// prefixlen <n>", never inet and inet6 in one command).
func (l *Local) applyJail(ctx context.Context, jail string, s render.Step) error {
	var cmd string
	var args []string
	switch s.Op {
	case render.OpAddAddr, render.OpRemoveAddr:
		p, err := netip.ParsePrefix(s.Arg)
		if err != nil {
			return invalid("invalid address %q", s.Arg)
		}
		cmd, args = "ifconfig", []string{"-j", jail, s.Iface}
		switch {
		case p.Addr().Is6() && s.Op == render.OpAddAddr:
			args = append(args, "inet6", p.Addr().String(), "prefixlen", strconv.Itoa(p.Bits()))
		case p.Addr().Is6():
			args = append(args, "inet6", p.Addr().String(), "-alias")
		case s.Op == render.OpAddAddr:
			args = append(args, "inet", p.String(), "up")
		default:
			args = append(args, "inet", p.Addr().String(), "-alias")
		}
	case render.OpIfaceUp, render.OpIfaceDown:
		verb := "up"
		if s.Op == render.OpIfaceDown {
			verb = "down"
		}
		cmd, args = "ifconfig", []string{"-j", jail, s.Iface, verb}
	case render.OpSetDescription:
		if s.Arg == "" || !render.ValidIfaceDesc(s.Arg) {
			return invalid("invalid interface description %q", s.Arg)
		}
		cmd, args = "ifconfig", []string{"-j", jail, s.Iface, "description", s.Arg}
	case render.OpAddGatewayLink, render.OpDelGatewayLink:
		a, err := netip.ParseAddr(s.Arg)
		if err != nil || !a.Is4() {
			return invalid("invalid gateway %q", s.Arg)
		}
		if s.Op == render.OpDelGatewayLink {
			cmd, args = "route", []string{"-j", jail, "delete", "-host", a.String()}
		} else {
			cmd, args = "route", []string{"-j", jail, "add", "-host", a.String(), "-interface", s.Iface}
		}
	case render.OpAddDefaultRte, render.OpDelDefaultRte:
		gw := s.Arg
		if a, _, ok := strings.Cut(gw, "%"); ok {
			gw = a
		}
		if _, err := netip.ParseAddr(gw); err != nil {
			return invalid("invalid gateway %q", s.Arg)
		}
		verb := "add"
		if s.Op == render.OpDelDefaultRte {
			verb = "delete"
		}
		cmd, args = "route", []string{"-j", jail, verb}
		if strings.Contains(s.Arg, ":") {
			args = append(args, "-inet6")
		}
		args = append(args, "default", s.Arg)
	default:
		return api.Errorf(api.CodeUnsupported, "hook cannot apply jail step %q", s.Op)
	}
	// the command rules (verifyIfconfig, verifyRoute) read the interface in the jail's vnet before they run it
	if err := ifconfig.ValidateIfName(s.Iface); err != nil {
		return err
	}
	_, err := l.Runner().Run(ctx, run.Cmd{Name: cmd, Args: args, Timeout: 20 * time.Second})
	if ee, ok := run.IsExit(err); ok {
		low := strings.ToLower(ee.Stderr)
		if strings.Contains(low, "file exists") || strings.Contains(low, "already") || strings.Contains(low, "not in table") {
			return nil
		}
	}
	return err
}
