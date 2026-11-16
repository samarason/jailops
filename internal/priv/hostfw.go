package priv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Host management, module firewall (docs/appliance.md). With the module in host-manage of priv.conf, and only then,
// the helper owns /etc/pf.conf as a whole file and the rc.conf variables pf_enable and pf_rules. The daemon sends a
// validated HostFirewallSpec, never a file: the helper validates it again, renders the file itself around the three
// anchor lines the jails need, checks it with pfctl -n, refuses a ruleset that would shut out the caller, keeps a
// copy of what it replaces, writes the pending record (hostpending.go) and only then writes and loads the file. Every
// change reverts itself unless it is confirmed.
//
// The block of scripts/ci-freebsd-e2e.sh with JAILOPS_E2E_HOSTFW=1 runs the module against a real pf (it rewrites the
// machine's pf.conf, so CI does not set it). Not covered by it: a host whose pf was disabled before the first apply, and
// sources of the other address family than the one the test connects with.

// pfctlBin is the one program the firewall module runs, with the forms checkHostPfctl accepts.
const pfctlBin = "/sbin/pfctl"

// hostFirewallFiles are the files of /etc the firewall module touches.
var hostFirewallFiles = []string{"pf.conf", "rc.conf"}

// hostFirewallRecord is firewall.json in host-dir: what the module applied last, and the digest of the file it wrote.
type hostFirewallRecord struct {
	Spec   api.HostFirewallSpec `json:"spec"`
	Time   time.Time            `json:"time"`
	SHA256 string               `json:"sha256"`
}

// checkHostPfctl is the module's own allow-list of pfctl forms. It is not in CommandRules: the daemon can never
// ask for any of these through run.exec. "-n -f -" checks the text the helper rendered (on standard input); "-f"
// loads only <etc>/pf.conf; "-e" and "-d" turn pf on and off (only to put back the state a snapshot recorded); "-s
// info" and "-s rules" read.
func checkHostPfctl(etc string, args []string) error {
	ok := [][]string{{"-n", "-f", "-"}, {"-f", etc + "/pf.conf"}, {"-e"}, {"-d"}, {"-s", "info"}, {"-s", "rules"}}
	for _, f := range ok {
		if slices.Equal(f, args) {
			return nil
		}
	}
	return forbidden("pfctl %s is not a form the host firewall module runs", strings.Join(args, " "))
}

// hostPfctl runs one allow-listed pfctl form; stdin feeds "-n -f -".
func (l *Local) hostPfctl(ctx context.Context, stdin string, args ...string) (string, error) {
	if err := checkHostPfctl(l.etcDir(), args); err != nil {
		return "", err
	}
	c := run.Cmd{Name: pfctlBin, Args: args, Timeout: 30 * time.Second, MaxOutput: 1 << 20}
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	res, err := l.d.Runner.Run(ctx, c)
	return string(res.Stdout), err
}

// pfEnabled asks pfctl -s info whether pf runs; nil when pfctl does not answer (pf is not loaded).
func (l *Local) pfEnabled(ctx context.Context) *bool {
	out, err := l.hostPfctl(ctx, "", "-s", "info")
	if err != nil {
		return nil
	}
	for _, ln := range splitLines(out) {
		if f := strings.Fields(ln); len(f) >= 2 && f[0] == "Status:" {
			on := f[1] == "Enabled"
			return &on
		}
	}
	return nil
}

// ---- rendering (pure) ----

func pfSources(list []string) string {
	if len(list) == 0 {
		return "any"
	}
	out := make([]string, len(list))
	for i, v := range list {
		if name, ok := strings.CutPrefix(v, "@"); ok {
			out[i] = "<" + hostFWTable(name) + ">"
		} else {
			out[i] = v
		}
	}
	if len(out) == 1 {
		return out[0]
	}
	return "{ " + strings.Join(out, ", ") + " }"
}

func pfPorts(ports []string) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strings.Replace(p, "-", ":", 1)
	}
	if len(out) == 1 {
		return out[0]
	}
	return "{ " + strings.Join(out, ", ") + " }"
}

// hostFWTable is the pf table of a set (at most 30 characters: pf allows 31).
func hostFWTable(set string) string { return "jo_hf_" + strings.ReplaceAll(set, "-", "_") }

// renderHostPF renders the whole of /etc/pf.conf from a canonical spec, in the order pf requires: tables, options,
// normalisation, then the rules. The anchor line the jails need is always there; it comes first among the rules,
// because the jails' anchors hold the NAT and the port forwards of their networks and are final (quick) for their own
// interfaces, and a broad pass before them would decide for them.
func renderHostPF(s api.HostFirewallSpec) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("%s", HostResolvHeader)
	w("# Rendered from `jailops host firewall`; a change made here is reported as drift and replaced by the next apply.")
	if len(s.Sets) > 0 {
		w("")
		w("# address sets")
		for _, set := range s.Sets {
			w("table <%s> const { %s }", hostFWTable(set.Name), strings.Join(set.Members, ", "))
		}
	}
	w("")
	w("# options: loopback is not filtered; states are bound to their interface (the jails' NAT needs it)")
	w("set skip on lo0")
	w("set state-policy if-bound")
	w("scrub in all fragment reassemble")
	w("")
	w("# the jails' anchors first: their filter rules and the NAT and port forwards of their networks")
	w(`anchor "jailops/*"`)
	if a := s.ACME; a != nil {
		// after the jails' anchors: a port forward of a jail on the same port wins over the challenge
		from := api.ACMEChallengePort(a.Challenge)
		w("# ACME %s challenges of the console's certificate: port %d to the daemon's unprivileged port %d", a.Challenge, from, a.Port)
		w("match in inet proto tcp from any to (self) port %d rdr-to 127.0.0.1 port %d", from, a.Port)
		w("match in inet6 proto tcp from any to (self) port %d rdr-to ::1 port %d", from, a.Port)
	}
	switch {
	case s.Template == api.HostFirewallOpen:
		w("# open template: everything may reach the host")
		w("pass in all")
	case s.Logging:
		w("block log in all")
	default:
		w("block in all")
	}
	w("pass out all keep state")
	w("# neighbour discovery, router advertisements, path MTU discovery and ICMP errors: always passed")
	w("pass in inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv, routersol, routeradv } no state")
	w("pass in inet6 proto icmp6 icmp6-type { toobig, unreach, timex, paramprob } no state")
	w("pass in inet proto icmp icmp-type unreach code needfrag no state")
	if s.Template == api.HostFirewallOpen {
		return b.String()
	}
	if a := s.ACME; a != nil {
		w("# the ACME challenges redirected above: the CA's addresses are not known, so from any")
		w("pass in proto tcp from any to { 127.0.0.1, ::1 } port %d", a.Port)
	}
	if s.SSH != nil && len(s.SSH.Ports) > 0 {
		ports := make([]string, len(s.SSH.Ports))
		for i, p := range s.SSH.Ports {
			ports[i] = strconv.Itoa(p)
		}
		w("# ssh")
		w("pass in proto tcp from %s to (self) port %s", pfSources(s.SSH.AllowFrom), pfPorts(ports))
	}
	if c := s.Console; c != nil && c.Port != 0 {
		w("# the JailOps console and API")
		w("pass in proto tcp from %s to (self) port %d", pfSources(c.AllowFrom), c.Port)
	} else {
		w("# the JailOps console and API: the daemon has no TLS listener, nothing to open")
	}
	if s.Template == api.HostFirewallCustom {
		for i, a := range s.Allow {
			if a.Comment != "" {
				w("# allow %d: %s", i+1, a.Comment)
			} else {
				w("# allow %d", i+1)
			}
			w("pass in proto %s from %s to (self) port %s", a.Proto, pfSources(a.From), pfPorts(a.Ports))
		}
	}
	if s.ICMP {
		w("# ping")
		w("pass in inet proto icmp icmp-type echoreq")
		w("pass in inet6 proto icmp6 icmp6-type echoreq")
	}
	return b.String()
}

func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// ---- read ----

type firewallFiles struct {
	files map[string]hostFile
	pf    *bool
}

// readFirewall reads the files and, with askPF, whether pf runs (at boot pf is not asked: it is not up yet).
func (l *Local) readFirewall(ctx context.Context, askPF bool) (firewallFiles, error) {
	out := firewallFiles{files: map[string]hostFile{}}
	for _, n := range hostFirewallFiles {
		f, err := l.readEtc(n)
		if err != nil {
			return out, err
		}
		out.files[n] = f
	}
	if askPF {
		out.pf = l.pfEnabled(ctx)
	}
	return out, nil
}

func (l *Local) readFirewallRecord() (*hostFirewallRecord, error) {
	var r hostFirewallRecord
	ok, err := l.readHostJSON("firewall.json", &r)
	if err != nil || !ok {
		return nil, err
	}
	return &r, nil
}

func (l *Local) writeFirewallRecord(r *hostFirewallRecord) error {
	return l.writeHostJSON("firewall.json", r)
}

// readHostJSON reads a record of host-dir; false when it does not exist.
func (l *Local) readHostJSON(name string, v any) (bool, error) {
	if _, err := os.Lstat(l.cfg.HostDir); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	root, err := l.hostDir()
	if err != nil {
		return false, err
	}
	defer root.Close()
	b, err := root.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, mapFSErr(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("%s/%s: %w", l.cfg.HostDir, name, err)
	}
	return true, nil
}

// writeHostJSON replaces a record of host-dir (synced), or removes it when v is a nil pointer.
func (l *Local) writeHostJSON(name string, v any) error {
	root, err := l.hostDir()
	if err != nil {
		return err
	}
	defer root.Close()
	if isNilPtr(v) {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return mapFSErr(err)
		}
		return nil
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return l.writeAtomic(l.cfg.HostDir, name, append(b, '\n'), 0o600, 0, 0)
}

func isNilPtr(v any) bool {
	switch p := v.(type) {
	case *hostFirewallRecord:
		return p == nil
	case *hostPendingRec:
		return p == nil
	case *api.HostPendingOutcome:
		return p == nil
	}
	return v == nil
}

// firewallDrift names what changed since the record: the file, and the two rc.conf variables.
func (l *Local) firewallDrift(f firewallFiles, rec *hostFirewallRecord) []string {
	if rec == nil {
		return nil
	}
	var d []string
	if pf := f.files["pf.conf"]; !pf.exists || sha256Hex(pf.data) != rec.SHA256 {
		d = append(d, "pf.conf")
	}
	rc := parseRC(f.files["rc.conf"].data)
	if !strings.EqualFold(rc["pf_enable"], "YES") {
		d = append(d, "pf_enable")
	}
	if v, ok := rc["pf_rules"]; ok && v != l.etcPath("pf.conf") {
		d = append(d, "pf_rules")
	}
	return d
}

// HostFirewallRead implements Host. It changes nothing and needs no assertion; the file never leaves the helper.
func (l *Local) HostFirewallRead(ctx context.Context) (service.HostFirewallState, error) {
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	f, err := l.readFirewall(ctx, true)
	if err != nil {
		return service.HostFirewallState{}, err
	}
	pf := f.files["pf.conf"]
	st := service.HostFirewallState{FileExists: pf.exists, FileManaged: pf.exists && strings.HasPrefix(pf.data, HostResolvHeader+"\n"),
		PFEnabled: f.pf, Modules: append([]string(nil), l.cfg.HostManage...)}
	if pf.exists {
		b := service.PFBindsStates(pf.data)
		st.StatePolicyIfBound = &b
	}
	rec, err := l.readFirewallRecord()
	if err != nil {
		return st, err
	}
	if rec != nil {
		spec := rec.Spec
		st.Applied, st.AppliedAt, st.Drift = &spec, rec.Time, l.firewallDrift(f, rec)
	}
	if p, err := l.readPending(); err == nil && p != nil {
		v := l.pendingView(*p)
		st.Pending = &v
	}
	return st, nil
}

// ---- apply ----

// planFirewall compares the rendered file and the two rc.conf variables with the host.
func (l *Local) planFirewall(f firewallFiles, data string) *hostPlan {
	p := &hostPlan{}
	l.planFile(p, f.files["pf.conf"], data, true, "")
	rc := parseRC(f.files["rc.conf"].data)
	var rcDiff []string
	set := func(name, value string) {
		old, ok := rc[name]
		if ok && old == value {
			return
		}
		p.rc = append(p.rc, [2]string{name, value})
		was := " (not set)"
		if ok {
			rcDiff = append(rcDiff, fmt.Sprintf("-%s=%q", name, old))
			was = fmt.Sprintf(" (was %q)", old)
		}
		rcDiff = append(rcDiff, fmt.Sprintf("+%s=%q", name, value))
		p.actions = append(p.actions, fmt.Sprintf("sysrc -f %s %s=%s%s", l.etcPath("rc.conf"), name, value, was))
	}
	set("pf_enable", "YES")
	if v, ok := rc["pf_rules"]; ok && v != l.etcPath("pf.conf") {
		set("pf_rules", l.etcPath("pf.conf"))
	}
	if len(rcDiff) > 0 {
		fmt.Fprintf(&p.diff, "--- %s\n+++ %s (variables set with sysrc)\n%s\n", l.etcPath("rc.conf"), l.etcPath("rc.conf"), strings.Join(rcDiff, "\n"))
	}
	return p
}

// lockoutGuard refuses rules that would shut out the caller: from its address it must still reach an ssh port or
// the console. When the address is unknown, the caller must say it knows (and the confirmation window stays).
func lockoutGuard(spec api.HostFirewallSpec, peer string, iKnow bool) error {
	if peer == "" {
		if iKnow {
			return nil
		}
		return api.Errorf(api.CodeInvalid, "the address this request came from is unknown (the unix socket or a hub), so the lock-out check cannot run").
			WithHint("check that you keep a way in, then repeat with --confirm-lockout (confirm_lockout in the API); the change still reverts unless you confirm it").
			WithDetail("guard", "unknown_peer")
	}
	a, err := netip.ParseAddr(peer)
	if err != nil {
		return invalid("invalid peer address %q", peer)
	}
	if spec.AdmitsAdmin(a) {
		return nil
	}
	what := "ssh"
	if spec.SSH != nil {
		ports := make([]string, len(spec.SSH.Ports))
		for i, p := range spec.SSH.Ports {
			ports[i] = strconv.Itoa(p)
		}
		what = "ssh (port " + strings.Join(ports, ", ") + ")"
	}
	if spec.Console != nil && spec.Console.Port != 0 {
		what += fmt.Sprintf(" nor the console (port %d)", spec.Console.Port)
	}
	return api.Errorf(api.CodeForbidden, "these rules would shut you out: %s could reach neither %s", a.Unmap(), what).
		WithHint("add "+a.Unmap().String()+", or a prefix or set that holds it, to ssh allow_from or console allow_from").WithDetail("guard", "lockout")
}

// HostFirewallApply implements Host.
func (l *Local) HostFirewallApply(ctx context.Context, q service.HostFirewallRequest) (api.HostChange, error) {
	if err := l.hostAllowed(ctx, api.HostModuleFirewall); err != nil {
		return api.HostChange{}, err
	}
	if err := q.Spec.Validate(); err != nil {
		return api.HostChange{}, err
	}
	within, err := api.ConfirmWindow(q.ConfirmWithin)
	if err != nil {
		return api.HostChange{}, err
	}
	if q.Peer != "" {
		if a, err := netip.ParseAddr(q.Peer); err != nil || a.Zone() != "" {
			return api.HostChange{}, invalid("invalid peer address %q", q.Peer)
		}
	}
	spec := q.Spec.Canonical()
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	pend, err := l.readPending()
	if err != nil {
		return api.HostChange{}, err
	}
	if pend != nil && !q.DryRun {
		return api.HostChange{}, l.busyPending(*pend)
	}
	f, err := l.readFirewall(ctx, true)
	if err != nil {
		return api.HostChange{}, err
	}
	data := renderHostPF(spec)
	if out, err := l.hostPfctl(ctx, data, "-n", "-f", "-"); err != nil {
		if _, ok := run.IsExit(err); ok {
			return api.HostChange{}, api.Errorf(api.CodeInvalid, "pfctl -n refuses the rendered pf.conf: %v", err).WithDetail("output", strings.TrimSpace(out))
		}
		return api.HostChange{}, err
	}
	p := l.planFirewall(f, data)
	pfOn := f.pf != nil && *f.pf
	load := len(p.files) > 0 || !pfOn
	changed := p.changed() || load
	res := api.HostChange{DryRun: q.DryRun, Changed: changed, Diff: p.diff.String(), Actions: p.actions, Rules: spec.Rules(), Warnings: spec.Warnings()}
	if load {
		res.Actions = append(res.Actions, "pfctl -f "+l.etcPath("pf.conf"))
		if !pfOn {
			res.Actions = append(res.Actions, "pfctl -e (pf does not run now)")
		}
	}
	if res.Actions == nil {
		res.Actions = []string{}
	}
	if pend != nil {
		res.Warnings = append(res.Warnings, l.busyPending(*pend).Error())
	}
	guard := lockoutGuard(spec, q.Peer, q.ConfirmLockout)
	if q.DryRun || !changed {
		if guard != nil && changed {
			res.Warnings = append(res.Warnings, "the apply would be refused: "+guard.Error())
		}
		if !changed {
			res.Actions = []string{}
			if !q.DryRun {
				return res, l.writeFirewallRecord(&hostFirewallRecord{Spec: spec, Time: l.now().UTC(), SHA256: sha256Hex(data)})
			}
			return res, nil
		}
		res.Actions = append([]string{"check the rendered file with pfctl -n (it parses)",
			"keep a copy of " + strings.Join(l.etcPaths(snapNames(p)), ", ") + " (snapshot)",
			fmt.Sprintf("write the pending record: the change reverts in %d seconds unless it is confirmed", within)}, res.Actions...)
		res.Actions = append(res.Actions, "wait for the confirmation (jailops host confirm)")
		return res, nil
	}
	if guard != nil {
		return api.HostChange{}, guard
	}
	prev, err := l.readFirewallRecord()
	if err != nil {
		return api.HostChange{}, err
	}
	reason := "apply"
	if prev == nil {
		reason = "adopt"
	}
	m := hostManifest{Module: api.HostModuleFirewall, Reason: reason, Firewall: prev}
	if f.pf != nil {
		on := *f.pf
		m.PFEnabled = &on
	}
	snap, err := l.keepSnapshot(m, f.files, snapNames(p))
	if err != nil {
		return api.HostChange{}, err
	}
	res.Snapshot = snap
	now := l.now().UTC()
	rec := hostPendingRec{ID: newPendingID(), Module: api.HostModuleFirewall, Snapshot: snap, Created: now,
		Deadline: now.Add(time.Duration(within) * time.Second), ConfirmWithin: within}
	// The record is on disk (synced) before anything of the host changes: whatever happens next, it is reverted.
	if err := l.writeHostJSON("pending.json", &rec); err != nil {
		return res, err
	}
	res.Actions = append([]string{"keep a copy of " + strings.Join(l.etcPaths(snapNames(p)), ", ") + " in snapshot " + snap,
		fmt.Sprintf("write the pending record %s: the change reverts at %s unless it is confirmed", rec.ID, rec.Deadline.Format(time.RFC3339))}, res.Actions...)
	if err := l.firewallExecute(ctx, p, !pfOn); err != nil {
		uerr := l.undo(ctx, snap, err)
		_ = l.writeHostJSON("pending.json", (*hostPendingRec)(nil))
		_ = l.writeHostJSON("pending.last.json", &api.HostPendingOutcome{ID: rec.ID, Module: rec.Module, Snapshot: snap, Outcome: api.HostPendingReverted,
			Time: l.now().UTC(), Detail: "the apply failed and was undone: " + err.Error()})
		return res, uerr
	}
	if err := l.writeFirewallRecord(&hostFirewallRecord{Spec: spec, Time: now, SHA256: sha256Hex(data)}); err != nil {
		return res, err
	}
	l.armPending(rec)
	v := l.pendingView(rec)
	res.Pending = &v
	l.note("host.pending.armed", "id", rec.ID, "module", rec.Module, "snapshot", snap, "deadline", rec.Deadline.Format(time.RFC3339))
	return res, nil
}

// snapNames are the files a firewall plan changes: pf.conf always (a first apply keeps the administrator's file or
// its absence), rc.conf when a variable changes.
func snapNames(p *hostPlan) []string {
	names := []string{"pf.conf"}
	if len(p.rc) > 0 {
		names = append(names, "rc.conf")
	}
	return names
}

// firewallExecute writes and loads: the files and variables of the plan, pfctl -f, pfctl -e when pf did not run,
// and a read-back that the main ruleset calls the jails' anchors.
func (l *Local) firewallExecute(ctx context.Context, p *hostPlan, enable bool) error {
	if err := l.execute(ctx, p); err != nil {
		return err
	}
	if _, err := l.hostPfctl(ctx, "", "-f", l.etcPath("pf.conf")); err != nil {
		return err
	}
	if enable {
		if _, err := l.hostPfctl(ctx, "", "-e"); err != nil {
			return err
		}
	}
	out, err := l.hostPfctl(ctx, "", "-s", "rules")
	if err != nil {
		return err
	}
	if !strings.Contains(out, `anchor "jailops/*"`) {
		return api.Errorf(api.CodeInternal, "the loaded ruleset does not call the anchor jailops/* (pfctl -s rules)")
	}
	return nil
}

// restoreFirewall puts the files of a firewall snapshot back and, with effective, loads them and puts pf's state
// back (on or off) as the snapshot recorded it. force reloads even when no file differs (a revert of a change that
// only turned pf on).
func (l *Local) restoreFirewall(ctx context.Context, root *os.Root, name string, m hostManifest, dryRun, keep, effective, force bool) (api.HostChange, error) {
	f, err := l.readFirewall(ctx, effective)
	if err != nil {
		return api.HostChange{}, err
	}
	p, err := l.planRestoreFiles(root, name, m, f.files)
	if err != nil {
		return api.HostChange{}, err
	}
	pfAfter := f.files["pf.conf"].exists
	for _, fc := range p.files {
		if fc.cur.name == "pf.conf" {
			pfAfter = fc.keep
		}
	}
	nowOn := f.pf != nil && *f.pf
	reload := effective && pfAfter && (len(p.files) > 0 || force)
	toggle := ""
	if effective && m.PFEnabled != nil && *m.PFEnabled != nowOn {
		toggle = map[bool]string{true: "-e", false: "-d"}[*m.PFEnabled]
	}
	if reload {
		p.actions = append(p.actions, "pfctl -f "+l.etcPath("pf.conf"))
	}
	if toggle != "" {
		p.actions = append(p.actions, "pfctl "+toggle)
	}
	if effective && !pfAfter && nowOn && (m.PFEnabled == nil || *m.PFEnabled) {
		p.actions = append(p.actions, "note: the snapshot has no pf.conf; pf keeps the ruleset it has loaded")
	}
	res := api.HostChange{DryRun: dryRun, Changed: p.changed() || reload || toggle != "", Diff: p.diff.String(), Actions: p.actions}
	if res.Actions == nil {
		res.Actions = []string{}
	}
	if dryRun || !res.Changed {
		return res, nil
	}
	if keep {
		prev, err := l.readFirewallRecord()
		if err != nil {
			return res, err
		}
		km := hostManifest{Module: api.HostModuleFirewall, Reason: "restore", Firewall: prev}
		if f.pf != nil {
			km.PFEnabled = &nowOn
		}
		var names []string
		for _, sf := range m.Files {
			names = append(names, sf.Name)
		}
		snap, err := l.keepSnapshot(km, f.files, names)
		if err != nil {
			return res, err
		}
		res.Snapshot = snap
		res.Actions = append([]string{"keep a copy of " + strings.Join(l.etcPaths(names), ", ") + " in snapshot " + snap}, res.Actions...)
	}
	if err := l.execute(ctx, p); err != nil {
		return res, err
	}
	if reload {
		if _, err := l.hostPfctl(ctx, "", "-f", l.etcPath("pf.conf")); err != nil {
			return res, err
		}
	}
	if toggle != "" {
		if _, err := l.hostPfctl(ctx, "", toggle); err != nil {
			return res, err
		}
	}
	return res, l.writeFirewallRecord(m.Firewall)
}

// planRestoreFiles plans putting the files of a snapshot back, with the mode and owner each one had; of rc.conf only
// the module's variables.
func (l *Local) planRestoreFiles(root *os.Root, name string, m hostManifest, cur map[string]hostFile) (*hostPlan, error) {
	p := &hostPlan{}
	for _, sf := range m.Files {
		c := cur[sf.Name]
		if sf.Name == "rc.conf" {
			if _, err := l.planRestoreRC(p, root, name, m, sf, c); err != nil {
				return nil, err
			}
			continue
		}
		data, err := readSnapCopy(root, name, sf)
		if err != nil {
			return nil, err
		}
		before := len(p.files)
		l.planFile(p, c, data, sf.Exists, "")
		if len(p.files) > before && sf.Exists {
			last := &p.files[len(p.files)-1]
			last.cur.mode, last.cur.uid, last.cur.gid, last.cur.exists = os.FileMode(sf.Mode).Perm(), sf.UID, sf.GID, true
		}
	}
	return p, nil
}

// ---- wire ----

type hostPendingIDArgs struct {
	ID string `json:"id,omitempty"`
}

func init() {
	register(OpHostFirewallRead, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.HostFirewallRead(ctx)
	})
	register(OpHostFirewallApply, false, func(ctx context.Context, h Host, a service.HostFirewallRequest, _ *callIO) (any, error) {
		return h.HostFirewallApply(ctx, a)
	})
	register(OpHostPendingRead, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.HostPending(ctx)
	})
	register(OpHostPendingConfirm, false, func(ctx context.Context, h Host, a hostPendingIDArgs, _ *callIO) (any, error) {
		return h.HostPendingConfirm(ctx, a.ID)
	})
	register(OpHostPendingRevert, false, func(ctx context.Context, h Host, a hostPendingIDArgs, _ *callIO) (any, error) {
		return h.HostPendingRevert(ctx, a.ID)
	})
}

// HostFirewallRead implements Host.
func (c *Client) HostFirewallRead(ctx context.Context) (service.HostFirewallState, error) {
	return callJSON[service.HostFirewallState](ctx, c, OpHostFirewallRead, empty{}, callOpts{})
}

// HostFirewallApply implements Host.
func (c *Client) HostFirewallApply(ctx context.Context, q service.HostFirewallRequest) (api.HostChange, error) {
	return callJSON[api.HostChange](ctx, c, OpHostFirewallApply, q, callOpts{})
}

// HostPending implements Host.
func (c *Client) HostPending(ctx context.Context) (api.HostPending, error) {
	return callJSON[api.HostPending](ctx, c, OpHostPendingRead, empty{}, callOpts{})
}

// HostPendingConfirm implements Host.
func (c *Client) HostPendingConfirm(ctx context.Context, id string) (api.HostPending, error) {
	return callJSON[api.HostPending](ctx, c, OpHostPendingConfirm, hostPendingIDArgs{ID: id}, callOpts{})
}

// HostPendingRevert implements Host.
func (c *Client) HostPendingRevert(ctx context.Context, id string) (api.HostPending, error) {
	return callJSON[api.HostPending](ctx, c, OpHostPendingRevert, hostPendingIDArgs{ID: id}, callOpts{})
}
