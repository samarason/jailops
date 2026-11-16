package reconcile

import (
	"context"
	"fmt"
	"io"
	"jailops.net/jailops/internal/supervise"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// Config tunes the loop.
type Config struct {
	// Interval is the period of the timer trigger (default 60s).
	Interval time.Duration
	// Debounce coalesces bursts of triggers (default 250ms).
	Debounce time.Duration
	// PFWatch is how often the loop looks at whether pf was flushed (default 5s).
	PFWatch time.Duration
	// Autostart starts jails with boot.autostart on the first pass after the host booted.
	Autostart bool
	// BootStateFile remembers the boot of the host (kern.boottime) that the boot pass ran for. A daemon that starts
	// again while the host stays up (a restart, a package upgrade) starts no jails: an operator may have stopped
	// them on purpose. Empty: every daemon start is a boot.
	BootStateFile string
	// NDP builds the neighbor discovery proxies of networks in IPv6 proxy mode; without it those networks report
	// that no proxy is available.
	NDP NDPFactory
}

// Env is everything the loop talks to.
type Env struct {
	Source  Source
	Sink    Sink
	Actions Actions
	Net     ifconfig.Client
	PF      pfctl.Client
	Jails   jailos.Jails
	Run     run.Runner
	// Sysctl reads sysctl values (optional; the runner is used otherwise).
	Sysctl func(ctx context.Context, name string) (string, error)
	Clock  Clock
	Log    *slog.Logger
	// Routes reads the routing table. Optional: without it the loop does not look at routes, and a route that went
	// missing is not put back.
	Routes func(ctx context.Context) ([]ifconfig.RouteEntry, error)
	// Trigger is an optional extra trigger (state watch events).
	Trigger <-chan struct{}
	// WG configures WireGuard interfaces (optional: without it tunnels are reported as not applied).
	WG wireguard.Host
	// AfterPass is called once after each pass of Run (optional): the names of the jails for the host's resolver follow
	// what the pass found running.
	AfterPass func(ctx context.Context)
}

// Report summarises one pass; tests and `doctor` read it.
type Report struct {
	At       time.Time
	Err      error
	Applied  []string            // steps executed
	Drift    map[string][]string // by jail
	Orphans  []string            // epairs found without a jail
	Cleaned  []string            // orphans removed
	Started  []string            // autostarted jails
	Failures map[string]string   // resource -> reason
}

// Reconciler is the loop.
type Reconciler struct {
	cfg Config
	env Env
	log *slog.Logger

	passMu sync.Mutex
	passes int
	kick   chan struct{}

	mu       sync.Mutex
	last     Report
	bootDone bool
	bootCond map[string]api.Condition
	proxies  map[string]*proxyHandle
	// setSysctl records the sysctls this daemon changed, for Release.
	setSysctl map[string]bool
	// jailSideOK maps a jail to the JID whose jail-side descriptions were found right (checked once per start).
	jailSideOK map[string]int
	// pipeRates is the bandwidth this daemon last set on each dummynet pipe of JailOps's range.
	pipeRates map[int]uint64
	// sentinel is the anchor of a running jail the last pass found in place: when it is empty, pf was flushed
	// (service pf restart runs pfctl -F all) and the watch asks for a pass at once.
	sentinel string
}

// New builds a Reconciler.
func New(cfg Config, env Env) *Reconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = 250 * time.Millisecond
	}
	if cfg.PFWatch <= 0 {
		cfg.PFWatch = defaultPFWatch
	}
	if env.Clock == nil {
		env.Clock = SystemClock{}
	}
	if env.Log == nil {
		env.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Reconciler{cfg: cfg, env: env, log: env.Log, kick: make(chan struct{}, 1),
		bootCond: map[string]api.Condition{}, proxies: map[string]*proxyHandle{}, setSysctl: map[string]bool{},
		jailSideOK: map[string]int{}}
}

// Kick asks for a pass soon. It never blocks.
func (r *Reconciler) Kick() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Last returns the report of the latest pass.
func (r *Reconciler) Last() Report {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// debounceWait is the wait before a pass that a kick asked for: the configured one, or three times what the last pass
// took when that is longer, up to maxDebounce.
func debounceWait(base, took time.Duration) time.Duration {
	if t := 3 * took; t > base {
		return min(t, maxDebounce)
	}
	return base
}

// maxDebounce is the longest wait between two passes that kicks cause.
const maxDebounce = 10 * time.Second

// defaultPFWatch is how often the loop looks at whether pf still holds the anchors it loaded.
const defaultPFWatch = 5 * time.Second

// watchPF asks for a pass at once when the anchor of a running jail is empty: starting or restarting pf flushes every
// anchor (rc.d/pf runs pfctl -F all), and the jails would be unfiltered until the next pass a minute later.
func (r *Reconciler) watchPF(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.cfg.PFWatch): // wall time, not the injected clock: the watch is about the host, not about the loop's timers
		}
		r.mu.Lock()
		an := r.sentinel
		r.mu.Unlock()
		if an == "" || r.env.PF == nil {
			continue
		}
		if live, err := r.env.PF.Read(ctx, an); err == nil && len(pfctl.RuleLines(live)) == 0 {
			r.log.Warn("reconcile: the firewall anchor of a running jail is empty (pf was flushed): loading the anchors again", "anchor", an)
			r.Kick()
		}
	}
}

// Run loops until ctx ends.
func (r *Reconciler) Run(ctx context.Context) error {
	defer r.stopProxies()
	go supervise.Run(ctx, r.log, "pf-watch", r.watchPF)
	for {
		began := r.env.Clock.Now()
		r.Pass(ctx)
		if r.env.AfterPass != nil {
			r.env.AfterPass(ctx)
		}
		took := r.env.Clock.Now().Sub(began)
		select {
		case <-ctx.Done():
			return nil
		case <-r.kick:
		case <-r.env.Trigger:
		case <-r.env.Clock.After(r.cfg.Interval):
			continue
		}
		// Debounce: let a burst settle, then drain what arrived meanwhile. A pass of a host with thousands of jails
		// takes a second: under a steady stream of kicks (a bulk create) passes would follow each other at once and
		// take a third of the machine, so the wait grows with the time a pass took (a quarter of the time at most).
		wait := debounceWait(r.cfg.Debounce, took)
		select {
		case <-ctx.Done():
			return nil
		case <-r.env.Clock.After(wait):
		}
		select {
		case <-r.kick:
		default:
		}
	}
}

// Pass runs one observe, render, plan, apply, verify cycle.
func (r *Reconciler) Pass(ctx context.Context) Report {
	r.passMu.Lock()
	defer r.passMu.Unlock()
	r.passes++
	now := r.env.Clock.Now()
	rep := Report{At: now, Drift: map[string][]string{}, Failures: map[string]string{}}
	defer func() {
		r.mu.Lock()
		r.last = rep
		r.mu.Unlock()
	}()
	des, err := r.env.Source.Desired(ctx)
	if err != nil {
		rep.Err = err
		r.log.Warn("reconcile: desired state unavailable", "err", err)
		return rep
	}
	r.hostPass(ctx, des.Host, &rep)
	r.pipePass(ctx, des, &rep)
	obs, err := r.observe(ctx)
	if err != nil {
		rep.Err = err
		r.log.Warn("reconcile: observation failed", "err", err)
		return rep
	}
	anchors := map[string]string{}
	for _, n := range des.Networks {
		for k, v := range n.Anchors {
			anchors[k] = v
		}
	}
	ex := &NetExec{Net: r.env.Net, PF: r.env.PF, Run: r.env.Run, Jail: r.env.Jails, Sysctl: r.env.Sysctl, Anchors: anchors}

	netStatus := map[string]*api.NetworkStatus{}
	for _, n := range des.Networks {
		st := r.networkPass(ctx, n, obs, ex, &rep, now)
		netStatus[n.Name] = st
	}
	// Networks changed interfaces; look again before judging jails.
	if len(rep.Applied) > 0 {
		if o2, err := r.observe(ctx); err == nil {
			obs = o2
		}
	}
	jailConds := map[string][]api.Condition{}
	for _, j := range des.Jails {
		jailConds[j.Name] = r.jailPass(ctx, j, obs, ex, &rep, now)
	}
	for _, j := range des.Jails {
		if _, up := obs.Running[j.Name]; !up {
			continue
		}
		for idx, ep := range j.Epairs {
			if idx < len(j.Networks) {
				if st := netStatus[j.Networks[idx]]; st != nil {
					st.Links = append(st.Links, ep)
				}
			}
		}
	}
	for _, st := range netStatus {
		if st != nil {
			slices.Sort(st.Links)
		}
	}
	r.pipeCleanup(ctx, des, &rep) // after the anchors: no anchor names a pipe that goes away
	r.orphanPass(ctx, des, obs, ex, netStatus, &rep)
	if r.cfg.Autostart && !r.bootDone {
		if r.hostBooted(ctx) {
			r.bootPass(ctx, des, obs, &rep, now)
		}
		r.bootDone = true
	}
	r.proxyPass(ctx, des, obs, netStatus, &rep, now)
	r.wireguardPass(ctx, des, &rep)
	for _, n := range des.Networks {
		if st := netStatus[n.Name]; st != nil && r.env.Sink != nil {
			r.env.Sink.NetworkStatus(n.Name, *st)
		}
	}
	if r.env.Sink != nil {
		r.mu.Lock()
		for _, j := range des.Jails {
			conds := jailConds[j.Name]
			if c, ok := r.bootCond[j.Name]; ok {
				conds = append(conds, c)
			}
			r.env.Sink.JailStatus(j.Name, conds, rep.Drift[j.Name])
		}
		r.mu.Unlock()
	}
	return rep
}

// observe reads the interfaces, the running jails and, when the loop can, the routing table.
func (r *Reconciler) observe(ctx context.Context) (*Observed, error) {
	o, err := Observe(ctx, r.env.Net, r.env.Jails)
	if err != nil {
		return nil, err
	}
	if r.env.Routes != nil {
		if rt, err := r.env.Routes(ctx); err == nil {
			o.Routes = rt
		}
	}
	return o, nil
}

// ---- networks ----

func (r *Reconciler) networkPass(ctx context.Context, n NetworkDesired, obs *Observed, ex *NetExec, rep *Report, now time.Time) *api.NetworkStatus {
	st := &api.NetworkStatus{Allocated: n.Allocated, Free: n.Free}
	fail := func(reason, msg string) *api.NetworkStatus {
		st.Conditions = append(st.Conditions, cond(CondReady, false, reason, msg, now))
		rep.Failures["network/"+n.Name] = msg
		return st
	}
	if n.Problem != "" {
		return fail("Invalid", n.Problem)
	}
	unlock, err := r.env.Actions.TryLock("reconcile "+n.Name, "network/"+n.Name)
	if err != nil {
		// An operation is changing this network; keep what we reported before.
		return nil
	}
	defer unlock()
	for _, step := range n.Steps {
		if Satisfied(step, obs) {
			continue
		}
		// The network's anchor is loaded only when what is live differs from what is rendered.
		if step.Op == render.OpLoadAnchor && r.anchorDrift(ctx, JailDesired{AnchorName: step.Arg, Ruleset: n.Anchors[step.Arg]}) == "" {
			continue
		}
		if step.Op == render.OpRequireSysctl {
			// A precondition, checked every pass; it changes nothing.
			if err := ex.Exec(ctx, step, ""); err != nil {
				return fail("Precondition", err.Error())
			}
			continue
		}
		if err := ex.Exec(ctx, step, ""); err != nil {
			rep.Applied = append(rep.Applied, step.Describe()+" (failed)")
			return fail("ApplyFailed", fmt.Sprintf("%s: %v", step.Describe(), err))
		}
		rep.Applied = append(rep.Applied, step.Describe())
	}
	st.Conditions = append(st.Conditions, cond(CondReady, true, "Applied", "the network is configured", now))
	return st
}

// ---- jails ----

func (r *Reconciler) jailPass(ctx context.Context, j JailDesired, obs *Observed, ex *NetExec, rep *Report, now time.Time) []api.Condition {
	if j.Problem != "" {
		rep.Failures["jail/"+j.Name] = j.Problem
		return []api.Condition{cond(CondReady, false, "Invalid", j.Problem, now)}
	}
	if _, up := obs.Running[j.Name]; !up {
		return []api.Condition{cond(CondReady, true, "Stopped", "the jail is stopped", now)}
	}
	var drift []string
	// Interfaces: the host end of every epair must exist, carry the gateway addresses, be up and have the routes to
	// the jail's addresses.
	for idx, ep := range j.Epairs {
		if _, ok := obs.Ifaces[ep]; !ok {
			drift = append(drift, fmt.Sprintf("epair %s is missing; restart the jail to recreate it", ep))
			continue
		}
		if idx >= len(j.Attach) {
			continue
		}
		for _, s := range j.Attach[idx] {
			switch s.Op {
			case render.OpAddAddr, render.OpIfaceUp, render.OpSetDescription, render.OpAddHostRoute:
			default:
				continue
			}
			if s.Phase != render.PhaseHost || Satisfied(s, obs) {
				continue
			}
			unlock, err := r.env.Actions.TryLock("reconcile "+j.Name, "jail/"+j.Name)
			if err != nil {
				break
			}
			if err := ex.Exec(ctx, s, j.Name); err != nil {
				drift = append(drift, fmt.Sprintf("%s: %v", s.Describe(), err))
			} else {
				rep.Applied = append(rep.Applied, s.Describe())
			}
			unlock()
		}
	}
	drift = append(drift, r.jailSidePass(ctx, j, obs, ex, rep)...)
	// Firewall anchor, and the parent anchors that lead to it.
	if j.Ruleset != "" && r.env.PF != nil {
		r.mu.Lock()
		r.sentinel = j.AnchorName
		r.mu.Unlock()
		for _, an := range sortedAnchors(j.ParentAnchors) {
			pj := JailDesired{Name: j.Name, AnchorName: an, Ruleset: j.ParentAnchors[an]}
			if r.anchorDrift(ctx, pj) == "" {
				continue
			}
			unlock, err := r.env.Actions.TryLock("reconcile "+an, "anchor/_parent/"+an)
			if err != nil {
				continue
			}
			if err := r.env.PF.Load(ctx, an, pj.Ruleset); err != nil {
				drift = append(drift, fmt.Sprintf("parent anchor %s: %v", an, err))
			} else if d := r.verifyLoaded(ctx, pj); d != "" {
				drift = append(drift, d)
			} else {
				rep.Applied = append(rep.Applied, "pfctl -a "+an+" -f <rendered>")
			}
			unlock()
		}
		if d := r.anchorDrift(ctx, j); d != "" {
			unlock, err := r.env.Actions.TryLock("reconcile "+j.Name, "anchor/"+j.Name)
			if err == nil {
				if err := r.loadAnchor(ctx, j.AnchorName, j.Ruleset); err != nil {
					drift = append(drift, fmt.Sprintf("firewall anchor %s: %v", j.AnchorName, err))
				} else if d := r.verifyLoaded(ctx, j); d != "" {
					drift = append(drift, d)
				} else {
					rep.Applied = append(rep.Applied, "pfctl -a "+j.AnchorName+" -f <rendered>")
				}
				unlock()
			}
		}
	}
	if len(drift) > 0 {
		rep.Drift[j.Name] = drift
		return []api.Condition{cond(CondReady, true, "Running", "the jail is running", now),
			cond(CondDrift, false, "Drift", strings.Join(drift, "; "), now)}
	}
	return []api.Condition{cond(CondReady, true, "Running", "the jail is running", now), cond(CondDrift, true, "InSync", "rendered and live state agree", now)}
}

// jailSidePass checks the description of every jail end of a running jail from the host (ifconfig -j <jail> <if>)
// and sets the wanted one where it is missing or different. The jail ends are the jail's own (their names derive
// from its id), so nothing foreign is touched. Once all are right for a JID, the jail is not asked again until it is
// started anew.
func (r *Reconciler) jailSidePass(ctx context.Context, j JailDesired, obs *Observed, ex *NetExec, rep *Report) []string {
	rj, up := obs.Running[j.Name]
	if !up || len(j.JailSide) == 0 || r.env.Run == nil {
		return nil
	}
	r.mu.Lock()
	done := r.jailSideOK[j.Name] == rj.JID && rj.JID != 0
	r.mu.Unlock()
	if done {
		return nil
	}
	var drift []string
	ok := true
	for _, s := range j.JailSide {
		if s.Op != render.OpSetDescription || s.Phase != render.PhaseJail {
			continue
		}
		res, err := r.env.Run.Run(ctx, jailIfaceRead(j.Name, s.Iface))
		if err != nil {
			ok = false // the interface may still be moving into the jail; try again next pass
			continue
		}
		ifs := ifconfig.ParseIfconfig(string(res.Stdout))
		if len(ifs) == 1 && ifs[0].Description == s.Arg {
			continue
		}
		unlock, err := r.env.Actions.TryLock("reconcile "+j.Name, "jail/"+j.Name)
		if err != nil {
			ok = false
			continue
		}
		if err := ex.Exec(ctx, s, j.Name); err != nil {
			drift = append(drift, fmt.Sprintf("%s: %v", s.Describe(), err))
			ok = false
		} else {
			rep.Applied = append(rep.Applied, s.Describe())
		}
		unlock()
	}
	if ok {
		r.mu.Lock()
		r.jailSideOK[j.Name] = rj.JID
		r.mu.Unlock()
	}
	return drift
}

// jailIfaceRead is the read of one interface inside a jail's vnet.
func jailIfaceRead(jail, iface string) run.Cmd {
	return run.Cmd{Name: "ifconfig", Args: []string{"-j", jail, iface}, Timeout: 20 * time.Second}
}

// wireguardPass keeps every tunnel applied: the helper creates a missing interface (after a reboot), repairs its
// description, addresses and configuration, and changes nothing that matches. A tunnel that is down has no
// interface. The pf anchor of a server is loaded when it differs.
func (r *Reconciler) wireguardPass(ctx context.Context, des Desired, rep *Report) {
	for _, w := range des.WireGuard {
		key := "wireguard/" + w.Name
		if w.Problem != "" {
			rep.Failures[key] = w.Problem
			continue
		}
		if r.env.WG == nil {
			rep.Failures[key] = "no WireGuard support (helper) in this daemon"
			continue
		}
		unlock, err := r.env.Actions.TryLock("reconcile "+w.Name, key)
		if err != nil {
			continue // an operation is changing it
		}
		if w.Down {
			if err := r.env.WG.WGRemove(ctx, wireguard.RemoveReq{Name: w.Name, Iface: w.Iface}); err != nil {
				rep.Failures[key] = err.Error()
			}
			unlock()
			continue
		}
		res, err := r.env.WG.WGApply(ctx, w.Apply)
		if err != nil {
			rep.Failures[key] = err.Error()
			unlock()
			continue
		}
		for _, c := range res.Changed {
			rep.Applied = append(rep.Applied, "wireguard "+w.Name+": "+c)
		}
		if r.env.PF != nil {
			if w.Ruleset != "" {
				if d := r.anchorDrift(ctx, JailDesired{AnchorName: w.Anchor, Ruleset: w.Ruleset}); d != "" {
					if err := r.loadAnchor(ctx, w.Anchor, w.Ruleset); err != nil {
						rep.Failures[key] = fmt.Sprintf("anchor %s: %v", w.Anchor, err)
					} else {
						rep.Applied = append(rep.Applied, "pfctl -a "+w.Anchor+" -f <rendered>")
					}
				}
			} else if live, err := r.env.PF.Read(ctx, w.Anchor); err == nil && len(pfctl.RuleLines(live)) > 0 {
				if err := r.env.PF.Flush(ctx, w.Anchor); err == nil {
					rep.Applied = append(rep.Applied, "pfctl -a "+w.Anchor+" -F all")
				}
			}
		}
		unlock()
	}
}

// verifyLoaded reads the anchor back (pfctl -a <anchor> -sr) after a load and
// checks that the rules the loop loaded are present. A load that pfctl
// accepted but that did not take effect is drift, not success.
func (r *Reconciler) verifyLoaded(ctx context.Context, j JailDesired) string {
	if d := r.anchorDrift(ctx, j); d != "" {
		return fmt.Sprintf("anchor %s: after loading, %s", j.AnchorName, d)
	}
	return ""
}

func sortedAnchors(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// anchorDrift returns a description when the loaded anchor differs from the
// rendered ruleset, "" when they agree.
func (r *Reconciler) anchorDrift(ctx context.Context, j JailDesired) string {
	norm, err := r.env.PF.Validate(ctx, j.AnchorName, j.Ruleset)
	if err != nil {
		return "rendered ruleset does not validate: " + err.Error()
	}
	live, err := r.env.PF.Read(ctx, j.AnchorName)
	if err != nil {
		return "anchor cannot be read: " + err.Error()
	}
	if !slices.Equal(pfctl.RuleLines(norm), pfctl.RuleLines(live)) {
		return "loaded rules differ from the rendered ruleset"
	}
	// Rule lines name tables but do not show their members: compare those too.
	for name, want := range tableDefs(j.Ruleset) {
		got, ok := r.liveTable(ctx, j.AnchorName, name, live)
		if ok && !slices.Equal(want, got) {
			return fmt.Sprintf("table <%s> differs from the rendered address set", name)
		}
	}
	return ""
}

// liveTable returns the members of a table of the anchor: from pfctl when it
// knows the table, else from the table definition in the anchor text.
func (r *Reconciler) liveTable(ctx context.Context, anchor, name, anchorText string) ([]string, bool) {
	if m, err := r.env.PF.TableShow(ctx, anchor, name); err == nil {
		out := normMembers(m)
		return out, true
	}
	if d, ok := tableDefs(anchorText)[name]; ok {
		return d, true
	}
	return nil, false
}

var tableRe = regexp.MustCompile(`table\s+<([A-Za-z][A-Za-z0-9_]*)>[^{\n]*\{([^}]*)\}`)

// tableDefs extracts "table <name> ... { members }" definitions.
func tableDefs(text string) map[string][]string {
	out := map[string][]string{}
	for _, m := range tableRe.FindAllStringSubmatch(text, -1) {
		out[m[1]] = normMembers(strings.FieldsFunc(m[2], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }))
	}
	return out
}

func normMembers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ---- orphans ----

func (r *Reconciler) orphanPass(ctx context.Context, des Desired, obs *Observed, ex *NetExec, netStatus map[string]*api.NetworkStatus, rep *Report) {
	// An epair is a jail's when its name carries the jail's prefix (ipam.EpairNames); the description says only
	// that it is JailOps's.
	byBase := map[string]JailDesired{}
	for _, j := range des.Jails {
		if h, _, err := ipam.EpairNames(j.ID, 0); err == nil {
			byBase[h[:len(h)-3]] = j
		}
	}
	for _, name := range sortedIfaces(obs) {
		i := obs.Ifaces[name]
		if !ipam.IsEpairName(name) || !ours(i) || !strings.HasSuffix(name, "a") {
			continue
		}
		j, known := byBase[name[:len(name)-3]]
		orphan := !known
		if known {
			if _, up := obs.Running[j.Name]; !up && !r.env.Actions.IsLocked("jail/"+j.Name) {
				orphan = true // left over from a stopped jail
			}
		}
		if !orphan {
			continue
		}
		rep.Orphans = append(rep.Orphans, name)
		if nw := netOfDesc(i.Description); nw != "" {
			if st := netStatus[nw]; st != nil {
				st.Orphans = append(st.Orphans, name)
			}
		}
		step := render.Step{Op: render.OpEpairDestroy, Phase: render.PhaseHost, Iface: name}
		if err := ex.Exec(ctx, step, ""); err != nil {
			rep.Failures["interface/"+name] = err.Error()
			continue
		}
		rep.Cleaned = append(rep.Cleaned, name)
		rep.Applied = append(rep.Applied, step.Describe())
	}
}

// netOfDesc names the network the host end of a jail's epair was made for: its description is
// "jailops jail=PROJECT/JAIL net=NAME (host side)". "" for any other description.
func netOfDesc(d string) string {
	_, rest, ok := strings.Cut(d, " net=")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, " ")
	return name
}

func sortedIfaces(o *Observed) []string {
	out := make([]string, 0, len(o.Ifaces))
	for k := range o.Ifaces {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// loadAnchor loads the rules of an anchor and then ends the flows of the rules that are gone. pf keeps the state of a
// connection that a rule once admitted even after the rule is removed or changed, so without this a policy that was
// tightened would let the open connections go on until they closed. Rules that did not change keep their label, so
// their connections are not touched (a policy edit does not cut what is still allowed).
func (r *Reconciler) loadAnchor(ctx context.Context, name, ruleset string) error {
	// What is loaded now says which flows the new rules may end. An anchor that does not exist yet has nothing to end;
	// any other failure to read must not be taken for that, or the flows of a removed rule would never be ended:
	// the load is tried again on the next pass.
	old, err := r.env.PF.Read(ctx, name)
	if err != nil && !api.IsCode(err, api.CodeNotFound) {
		return fmt.Errorf("reading the loaded rules of %s before replacing them: %w", name, err)
	}
	if err := r.env.PF.Load(ctx, name, ruleset); err != nil {
		return err
	}
	keep := pfctl.LabelsOf(ruleset)
	var gone []string
	for l := range pfctl.LabelsOf(old) {
		if !keep[l] {
			gone = append(gone, l)
		}
	}
	slices.Sort(gone)
	for _, l := range gone {
		if err := r.env.PF.KillLabel(ctx, l); err != nil {
			r.log.Warn("reconcile: ending the states of a removed rule failed", "anchor", name, "label", l, "err", err)
		}
	}
	return nil
}
