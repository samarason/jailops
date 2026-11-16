package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

type checkSet struct{ list []api.DoctorCheck }

func (c *checkSet) add(name string, st api.DoctorStatus, msg, hint string) {
	c.list = append(c.list, api.DoctorCheck{Name: name, Status: st, Message: msg, Hint: hint})
}

// Doctor runs the diagnostics. Checks that need FreeBSD report "unknown"
// elsewhere; nothing is faked.
func (s *Service) Doctor(ctx context.Context) api.DoctorReport {
	c := &checkSet{}
	s.doctorState(ctx, c)
	s.doctorRelease(ctx, c)
	s.doctorKernel(ctx, c)
	s.doctorSysctl(ctx, c)
	s.doctorHost(ctx, c)
	s.doctorHostIdentity(ctx, c)
	s.doctorHostFirewall(ctx, c)
	s.doctorAppliance(ctx, c)
	s.doctorTLS(ctx, c)
	s.doctorZFS(ctx, c)
	s.doctorVolumes(ctx, c)
	s.doctorHostDirs(ctx, c)
	s.doctorLeftovers(ctx, c)
	s.doctorDelegation(ctx, c)
	s.doctorEncryption(ctx, c)
	s.doctorPF(ctx, c)
	s.doctorNDPProxy(c)
	s.doctorNDPUplink(ctx, c)
	s.doctorDNS(ctx, c)
	s.doctorUnbound(ctx, c)
	s.doctorNameLengths(ctx, c)
	s.doctorRuntime(ctx, c)
	s.doctorOldNetwork(ctx, c)
	s.doctorMounts(ctx, c)
	s.doctorLoops(c)
	s.doctorLongOperations(ctx, c)
	s.doctorDescriptions(ctx, c)
	s.doctorWireGuard(ctx, c)
	s.doctorAppsLocal(c)
	s.doctorAppsAccess(ctx, c)
	s.doctorPolicyDefaults(c)
	s.doctorFirewallSize(c)
	s.doctorJailRefs(c)
	s.doctorLogForward(c)
	s.doctorDevd(c)
	rep := api.DoctorReport{Time: s.now().UTC(), Host: s.d.Hostname, Checks: c.list, Status: api.DoctorOK}
	rank := map[api.DoctorStatus]int{api.DoctorOK: 0, api.DoctorInfo: 0, api.DoctorUnknown: 1, api.DoctorWarn: 2, api.DoctorFail: 3}
	for _, ch := range c.list {
		if rank[ch.Status] > rank[rep.Status] {
			rep.Status = ch.Status
		}
	}
	if !isGlobalAdmin(ActorFrom(ctx)) {
		// what a failing check says can be a raw error with paths and command lines of the host: for administrators
		for i := range rep.Checks {
			if ch := &rep.Checks[i]; ch.Status != api.DoctorOK && ch.Status != api.DoctorInfo {
				ch.Message, ch.Hint, ch.Detail = "details are shown to global administrators", "", nil
			}
		}
	}
	return rep
}

func (s *Service) doctorState(ctx context.Context, c *checkSet) {
	if rs := s.d.State.Recoveries(); len(rs) > 0 {
		var l []string
		for _, r := range rs {
			l = append(l, r.Path+": "+r.Action)
		}
		c.add("state.files", api.DoctorWarn, "state files were repaired at start: "+strings.Join(l, "; "), "check the .previous copies under the state directory")
	} else {
		c.add("state.files", api.DoctorOK, "state files are intact", "")
	}
	if probs, err := s.d.DB.IntegrityCheck(ctx); err != nil {
		c.add("db.integrity", api.DoctorFail, err.Error(), "")
	} else if len(probs) > 0 {
		c.add("db.integrity", api.DoctorFail, strings.Join(probs, "; "), "restore the database from the latest VACUUM INTO copy")
	} else {
		c.add("db.integrity", api.DoctorOK, "the operational database is healthy", "")
	}
	recs, err := s.journal.List(ctx)
	switch {
	case err != nil:
		c.add("operations.journal", api.DoctorFail, err.Error(), "")
	default:
		var bad []string
		for _, r := range recs {
			if r.State == plan.StateFailed {
				bad = append(bad, r.ID)
			}
		}
		// a run that the recovery at the start could not resolve keeps its record: it is not "in flight", it waits for
		// the operator
		stuck := map[string]string{}
		for _, o := range s.Recovered() {
			if o.Action == "needs-attention" {
				stuck[o.Run] = o.Detail
			}
		}
		var attention []string
		inflight := 0
		for _, r := range recs {
			if d, ok := stuck[r.ID]; ok {
				attention = append(attention, r.ID+" ("+d+")")
			} else if r.State != plan.StateFailed {
				inflight++
			}
		}
		if len(bad) > 0 {
			c.add("operations.journal", api.DoctorFail, "a rollback did not complete for: "+strings.Join(bad, ", "), "inspect the datasets of these jails, then remove the journal record")
		} else if len(attention) > 0 {
			c.add("operations.journal", api.DoctorFail, "the recovery after the last start could not resolve: "+strings.Join(attention, "; "), "look at what the run made (zfs list), clean it up, then remove the record from the journal directory")
		} else if inflight > 0 {
			c.add("operations.journal", api.DoctorOK, "operations are in flight", "")
		} else {
			c.add("operations.journal", api.DoctorOK, "no interrupted operations", "")
		}
	}
}

func (s *Service) runOK(ctx context.Context, name string, args ...string) (ok, available bool, out string) {
	if s.d.Run == nil {
		return false, false, ""
	}
	res, err := s.d.Run.Run(ctx, run.Cmd{Name: name, Args: args, Timeout: 10 * time.Second})
	if err == nil {
		return true, true, string(res.Stdout)
	}
	if _, isExit := run.IsExit(err); isExit {
		return false, true, ""
	}
	return false, false, err.Error()
}

func (s *Service) doctorKernel(ctx context.Context, c *checkSet) {
	needLinux := false
	s.mu.RLock()
	for _, e := range s.jails {
		if e.jail.Spec.OS == api.OSLinux {
			needLinux = true
		}
	}
	s.mu.RUnlock()
	mods := []struct {
		name     string
		required bool
	}{{"if_epair", true}, {"pf", true}, {"zfs", true}, {"linux64", needLinux}, {"linprocfs", needLinux}, {"linsysfs", needLinux}, {"fdescfs", needLinux}, {"dummynet", s.hasShaping()}}
	for _, m := range mods {
		ok, avail, _ := s.runOK(ctx, "kldstat", "-q", "-n", m.name)
		switch {
		case !avail:
			c.add("kernel.module."+m.name, api.DoctorUnknown, "cannot be checked here: kldstat is not available to the daemon", "")
		case ok:
			c.add("kernel.module."+m.name, api.DoctorOK, "loaded", "")
		case m.required:
			c.add("kernel.module."+m.name, api.DoctorFail, "not loaded", "kldload "+m.name+" and add it to /boot/loader.conf")
		default:
			c.add("kernel.module."+m.name, api.DoctorOK, "not loaded, not needed", "")
		}
	}
}

func (s *Service) doctorSysctl(ctx context.Context, c *checkSet) {
	nets, _ := s.netKind.list()
	var v4, v6 bool
	for _, n := range nets {
		if n.Spec.IPv4 != nil {
			v4 = true
		}
		if n.Spec.IPv6 != nil && n.Spec.IPv6.Mode != api.IPv6None {
			v6 = true
		}
	}
	racct := false
	s.mu.RLock()
	for _, e := range s.jails {
		r := e.jail.Spec.Resources
		if r.Memory != "" || r.PIDs > 0 || r.CPU > 0 {
			racct = true
		}
	}
	s.mu.RUnlock()
	check := func(name, want string, needed bool, why, hint string) {
		got, err := s.sysctl(ctx, name)
		switch {
		case err != nil:
			c.add("sysctl."+name, api.DoctorUnknown, err.Error(), "")
		case got == want:
			c.add("sysctl."+name, api.DoctorOK, name+"="+got, "")
		case needed:
			if hint == "" {
				hint = "sysctl " + name + "=" + want + " and add it to /etc/sysctl.conf"
			}
			if name == SysctlOnlinkNS { // recommended, not needed to work: a segment whose routers do not probe from off-link addresses is fine without it
				c.add("sysctl."+name, api.DoctorWarn, name+" is "+got+", JailOps recommends "+want+" ("+why+")", hint)
				break
			}
			c.add("sysctl."+name, api.DoctorFail, name+" is "+got+", JailOps needs "+want+" ("+why+")", hint)
		default:
			c.add("sysctl."+name, api.DoctorOK, name+"="+got+" (not needed now)", "")
		}
	}
	check("net.inet6.ip6.forwarding", "1", v6, "jails reach IPv6 through the host", "")
	check("net.inet.ip.forwarding", "1", v4, "jails reach IPv4 through the host", "")
	check("kern.racct.enable", "1", racct, "limits.cpu, limits.memory and limits.pids are enforced with rctl",
		"add kern.racct.enable=1 to /boot/loader.conf and reboot: the kernel reads it only at boot")
	if v6 { // present from FreeBSD 15.2; JailOps derives a jail's link-local address from its MAC address, which this setting changes
		const stable = "net.inet6.ip6.use_stableaddr"
		if got, err := s.sysctl(ctx, stable); err == nil {
			if got == "0" {
				c.add("sysctl."+stable, api.DoctorOK, stable+"="+got, "")
			} else {
				c.add("sysctl."+stable, api.DoctorFail, stable+" is "+got+": the kernel no longer forms a jail's link-local address from its MAC address, so the jail's IPv6 neighbour discovery is dropped by its own firewall",
					"sysctl "+stable+"=0 and take it out of /etc/sysctl.conf")
			}
		}
	}
	check(SysctlOnlinkNS, "1", s.hasProxyNetwork(), "the routers of a shared IPv6 segment probe the host from off-link addresses", onlinkNSHint)
}

func (s *Service) doctorZFS(ctx context.Context, c *checkSet) {
	if s.d.ZClient == nil {
		c.add("zfs.compat", api.DoctorUnknown, "no ZFS client", "")
		return
	}
	pools, err := s.d.ZClient.ListPools(ctx)
	if err != nil {
		c.add("zfs.pool", api.DoctorUnknown, err.Error(), "")
		return
	}
	for _, si := range s.storageList() {
		pn := poolOf(si.Root)
		if pn == s.d.Pool {
			continue
		}
		for _, p := range pools {
			if p.Name != pn {
				continue
			}
			if p.Health != "ONLINE" {
				c.add("zfs.pool."+pn, api.DoctorFail, "pool "+p.Name+" of storage "+si.Name+" is "+p.Health, "zpool status "+p.Name)
			} else {
				c.add("zfs.pool."+pn, api.DoctorOK, "pool "+p.Name+" of storage "+si.Name+" is ONLINE", "")
			}
		}
	}
	found := false
	for _, p := range pools {
		if p.Name != s.d.Pool {
			continue
		}
		found = true
		if p.Health != "ONLINE" {
			c.add("zfs.pool", api.DoctorFail, "pool "+p.Name+" is "+p.Health, "zpool status "+p.Name)
		} else {
			c.add("zfs.pool", api.DoctorOK, "pool "+p.Name+" is ONLINE", "")
		}
	}
	if !found {
		c.add("zfs.pool", api.DoctorFail, "pool "+s.d.Pool+" does not exist", "")
		return
	}
	active, err := s.d.ZClient.ActiveFeatures(ctx, s.d.Pool)
	if err != nil {
		c.add("zfs.compat", api.DoctorUnknown, err.Error(), "")
		return
	}
	content := ""
	if s.d.CompatFile != "" {
		dir := s.d.CompatDir
		if dir == "" {
			dir = zfs.DefaultCompatDir
		}
		content, _ = zfs.LoadCompat(dir, s.d.CompatFile)
	}
	res := zfs.CheckCompatDetail(active, content)
	switch res.Verdict {
	case zfs.Verified:
		c.add("zfs.compat", api.DoctorOK, "pool features fit "+s.d.CompatFile, "")
	case zfs.No:
		c.add("zfs.compat", api.DoctorFail, "active features not in "+s.d.CompatFile+": "+strings.Join(res.Blocking, ", "), "JailOps never runs zpool upgrade; replication to older hosts will fail")
	default:
		if s.d.CompatFile == "" {
			c.add("zfs.compat", api.DoctorOK, "no replication target configured; features of "+s.d.Pool+" are not compared with an older release", "")
		} else {
			c.add("zfs.compat", api.DoctorUnknown, "the compatibility file "+s.d.CompatFile+" was not found", "")
		}
	}
}

// doctorLeftovers names the datasets of the projects that no object accounts for: the container a replace-restore
// parked (it keeps the old jail until the operator has looked at the restored one) and a volume dataset that an
// interrupted creation left without its volume. Nothing is destroyed: they hold data.
func (s *Service) doctorLeftovers(ctx context.Context, c *checkSet) {
	z := s.d.ZClient
	if z == nil {
		return
	}
	vols, err := s.volKind.listAll()
	if err != nil {
		return
	}
	known := map[string]bool{}
	for _, o := range vols {
		known[o.Meta.Project+"/"+o.Meta.Name] = true
	}
	var parked, orphans []string
	for _, si := range s.storageList() {
		root := si.lifecycle().Root + "/projects/"
		list, err := z.List(ctx, zfs.ListOpts{Root: strings.TrimSuffix(root, "/"), Recursive: true, Props: []string{"used"}})
		if err != nil {
			continue
		}
		for _, d := range list {
			rel := strings.TrimPrefix(d.Name, root)
			parts := strings.Split(rel, "/")
			switch {
			case len(parts) == 3 && parts[1] == "jails" && strings.Contains(parts[2], ".replaced-"):
				parked = append(parked, fmt.Sprintf("%s (%s)", d.Name, sizeText(atoi64(d.Props["used"]))))
			case len(parts) == 3 && parts[1] == "volumes" && !known[parts[0]+"/"+parts[2]]:
				orphans = append(orphans, fmt.Sprintf("%s (%s)", d.Name, sizeText(atoi64(d.Props["used"]))))
			}
		}
	}
	switch {
	case len(orphans) > 0:
		c.add("storage.leftovers", api.DoctorWarn, "volume datasets without a volume: "+strings.Join(orphans, ", "),
			"an interrupted creation left them; look at them with 'zfs list -r', then destroy what you do not need with 'zfs destroy -r'")
	case len(parked) > 0:
		c.add("storage.leftovers", api.DoctorInfo, "datasets of jails that a restore replaced are kept: "+strings.Join(parked, ", "),
			"keep them until the restored jail is checked, then destroy each with 'zfs destroy -r NAME'; they count against the project's storage quota")
	default:
		c.add("storage.leftovers", api.DoctorOK, "no dataset is left that no object of a project accounts for", "")
	}
}

// doctorHostDirs looks at the volumes that are directories of the host: each must still be on its mount, which is what
// a jail needs to start and what a watch tells the operator about.
func (s *Service) doctorHostDirs(ctx context.Context, c *checkSet) {
	vols, err := s.volKind.listAll()
	if err != nil {
		return
	}
	var lost []string
	n := 0
	for _, o := range vols {
		if !o.Spec.IsHostDir() {
			continue
		}
		n++
		if state, detail := s.hostDirStateRead(ctx, o); state != api.VolumeStateOK {
			lost = append(lost, fmt.Sprintf("%s/%s (%s): %s", o.Meta.Project, o.Meta.Name, o.Spec.Path, detail))
		}
	}
	switch {
	case n == 0:
	case len(lost) > 0:
		c.add("volume.hostdirs", api.DoctorFail, "a volume's directory is not on its mount: "+strings.Join(lost, "; "), "mount it again; the jails that attach it do not start while it is lost")
	default:
		c.add("volume.hostdirs", api.DoctorOK, fmt.Sprintf("%d volume(s) of host directories, every directory is on its mount", n), "")
	}
}

// doctorVolumes compares the volumes with their datasets and with the jails that attach them: a volume without its
// dataset, a dataset that is not mounted where the jails reach it, and an attachment of a volume that does not exist.
func (s *Service) doctorVolumes(ctx context.Context, c *checkSet) {
	if s.d.ZClient == nil {
		return
	}
	vols, err := s.volKind.listAll()
	if err != nil {
		return
	}
	var bad, fixes []string
	known := map[string]bool{}
	for _, o := range vols {
		known[o.Meta.Project+"/"+o.Meta.Name] = true
		if o.Spec.IsHostDir() {
			continue // looked at by doctorHostDirs
		}
		si, ok := s.storage(o.Spec.Storage)
		if !ok {
			bad = append(bad, fmt.Sprintf("volume %s/%s is on storage %q, which does not exist", o.Meta.Project, o.Meta.Name, o.Spec.Storage))
			continue
		}
		ds := lifecycle.VolumeDS(si.lifecycle(), o.Meta.Project, o.Meta.Name)
		if ok, err := s.d.ZFS.Exists(ctx, ds); err != nil {
			continue
		} else if !ok {
			bad = append(bad, fmt.Sprintf("volume %s/%s has no dataset %s", o.Meta.Project, o.Meta.Name, ds))
			continue
		}
		if o.Spec.Encrypted {
			continue // mounted when it is unlocked
		}
		if v, _ := s.d.ZFS.Get(ctx, ds, "mounted"); v == "no" {
			fixes = append(fixes, "zfs mount "+ds)
		}
	}
	s.mu.RLock()
	for _, k := range sortedKeys(s.jails) {
		j := s.jails[k].jail
		for _, v := range j.Spec.Volumes {
			if !known[j.Metadata.Project+"/"+v.Name] {
				bad = append(bad, fmt.Sprintf("jail %s/%s attaches volume %q, which does not exist", j.Metadata.Project, j.Metadata.Name, v.Name))
			}
		}
	}
	s.mu.RUnlock()
	switch {
	case len(bad) > 0:
		c.add("jail.volumes", api.DoctorFail, strings.Join(bad, "; "), "jailops volume list; create the missing volume or detach it from the jail")
	case len(fixes) > 0:
		c.add("jail.volumes", api.DoctorWarn, fmt.Sprintf("%d volume dataset(s) are not mounted on the host, so the jails that attach them cannot reach them", len(fixes)), strings.Join(fixes, "; "))
	default:
		c.add("jail.volumes", api.DoctorOK, fmt.Sprintf("%d volume(s), every dataset is there and every attached volume exists", len(vols)), "")
	}
}

// doctorDelegation compares zfs_delegation of the jails with the jailed property of their delegated datasets: a jail
// that asks for the dataset needs it jailed to start, and a jailed dataset of a jail that does not ask for it is
// neither mounted on the host nor managed by anyone.
func (s *Service) doctorDelegation(ctx context.Context, c *checkSet) {
	s.mu.RLock()
	want := map[string]bool{}
	for k, e := range s.jails {
		want[k] = e.jail.Spec.Delegate
	}
	s.mu.RUnlock()
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var bad []string
	var fixes []string
	n := 0
	for _, k := range keys {
		ds := s.lcfg.DelegatedDS(k)
		ok, err := s.d.ZFS.Exists(ctx, ds)
		if err != nil {
			continue
		}
		jailed := false
		if ok {
			v, _ := s.d.ZFS.Get(ctx, ds, "jailed")
			jailed = v == "on"
		}
		switch {
		case want[k]:
			n++
			if !jailed {
				_, name := validate.SplitQualified(k)
				bad = append(bad, name)
				fixes = append(fixes, "jailops config set "+name+" zfs.delegation false; jailops config set "+name+" zfs.delegation true")
			}
		case jailed:
			bad = append(bad, ds)
			fixes = append(fixes, "zfs set jailed=off "+ds)
		}
	}
	if len(bad) == 0 {
		if n > 0 {
			c.add("jail.delegation", api.DoctorOK, fmt.Sprintf("%d jail(s) with a delegated dataset: jailed=on", n), "")
		}
		return
	}
	c.add("jail.delegation", api.DoctorFail, "the delegated dataset does not match zfs_delegation: "+strings.Join(bad, ", "), strings.Join(fixes, "; "))
}

func (s *Service) doctorPF(ctx context.Context, c *checkSet) {
	if s.d.Run == nil {
		c.add("pf.anchors", api.DoctorUnknown, "no command runner", "")
		return
	}
	_, ok, rules := s.runOK(ctx, "pfctl", "-s", "rules")
	if !ok {
		c.add("pf.anchors", api.DoctorUnknown, "pfctl is not available here", "")
		return
	}
	// pfctl -s rules still prints the loaded ruleset while pf is disabled: a disabled pf evaluates none of it, and the
	// jails would run without a firewall.
	if okInfo, _, info := s.runOK(ctx, "pfctl", "-s", "info"); okInfo {
		switch pfStatus(info) {
		case "Disabled":
			c.add("pf.enabled", api.DoctorFail, "pf is disabled: the anchors of the jails are loaded and nothing evaluates them, so the jails run without a firewall (a jail with a network link does not start while pf is off)",
				"enable pf: sysrc pf_enable=YES, then service pf start (or pfctl -e now); load the ruleset first with pfctl -f /etc/pf.conf if it is not loaded")
		case "Enabled":
			c.add("pf.enabled", api.DoctorOK, "pf is enabled", "")
		}
	}
	if strings.Contains(rules, `anchor "jailops/*"`) {
		c.add("pf.anchors", api.DoctorOK, "the jailops anchors are in the ruleset", "")
		if early := quickPassesBeforeAnchor(rules); len(early) > 0 {
			c.add("pf.order", api.DoctorWarn, "rules of pf.conf that come before the jailops anchor pass traffic for good (quick), so policies cannot filter it and the NAT and port forwards of the networks do not apply to it: "+strings.Join(early, "; "),
				`move anchor "jailops/*" above them, or accept that this traffic is not filtered by JailOps`)
		} else {
			c.add("pf.order", api.DoctorOK, "no quick pass rule comes before the jailops anchor", "")
		}
		if hasScrub(rules) {
			c.add("pf.scrub", api.DoctorOK, "pf.conf normalises packets (scrub)", "")
		} else {
			c.add("pf.scrub", api.DoctorWarn, "pf.conf has no scrub rule: fragments are not reassembled (a jail whose policy denies inbound traffic then loses fragmented packets, UDP above the path MTU among them) and TCP MSS is not clamped",
				"add `scrub in all fragment reassemble` (and `max-mss` for a tunnel or a smaller MTU) near the top of /etc/pf.conf; see docs/install.md")
		}
	} else {
		c.add("pf.anchors", api.DoctorFail, "the jailops anchor line is missing from pf.conf", "add to /etc/pf.conf, and reload it with pfctl -f /etc/pf.conf. The anchor holds the filter rules and the NAT and port forwards of the jails, so it belongs before any quick rule that should not decide first:\n"+render.AnchorLines())
	}
	s.doctorStatePolicy(ctx, c, rules)
}

// pfStatus is "Enabled" or "Disabled" from the output of pfctl -s info, "" when it does not say.
func pfStatus(info string) string {
	for _, ln := range strings.Split(info, "\n") {
		if f := strings.Fields(ln); len(f) >= 2 && f[0] == "Status:" {
			return f[1]
		}
	}
	return ""
}

var (
	reStatePolicy = regexp.MustCompile(`(?m)^\s*set\s+state-policy\s+if-bound\b`)
	rePFRules     = regexp.MustCompile(`^\s*pf_rules\s*=\s*(.*?)\s*$`)
)

// doctorStatePolicy fails a host whose pf.conf does not bind states to interfaces while jails exist. A jail's traffic is
// judged at every hop of the host (in on the sender's link, out on the receiver's or on the uplink), and pf's default,
// floating states let a connection that the first hop admitted pass the next hop without its rules looking at it, and
// make the host drop all but the first packet of a NATed flow. JailOps's own rules say if-bound themselves; the line
// makes the host's rules behave the same. pf does not print the state policy, so the pf.conf the system loads is read;
// includes are not followed.
func (s *Service) doctorStatePolicy(ctx context.Context, c *checkSet, rules string) {
	const name = "pf.state-policy"
	nets, _ := s.netKind.list()
	nat := false
	for _, n := range nets {
		nat = nat || n.Spec.IPv4 != nil && n.Spec.IPv4.NAT
	}
	s.mu.RLock()
	jails := len(s.jails)
	s.mu.RUnlock()
	if !nat && jails == 0 {
		c.add(name, api.DoctorOK, "no network has NAT and there is no jail yet", "")
		return
	}
	conf, err := s.pfConfPath()
	if err != nil {
		c.add(name, api.DoctorUnknown, "the pf.conf the system loads cannot be found: "+err.Error(), "")
		return
	}
	b, err := s.hostFile(conf)
	if errors.Is(err, fs.ErrPermission) && conf == "/etc/pf.conf" {
		// the helper (root) reads it for us
		if fw, ok := s.d.Host.(HostFirewallSystem); ok && s.d.Host != nil {
			if st, herr := fw.HostFirewallRead(ctx); herr == nil && st.StatePolicyIfBound != nil {
				s.statePolicyResult(c, name, conf, *st.StatePolicyIfBound)
				return
			}
		}
	}
	if errors.Is(err, fs.ErrPermission) {
		// pf.conf is root's (mode 0600 is common): not a fault of the host, only something the daemon cannot judge
		c.add(name, api.DoctorInfo, conf+" is readable by root only, so the daemon cannot check it; jails are routed through the host, which wants `set state-policy if-bound` in it",
			"check it as root: grep state-policy "+conf)
		return
	}
	if err != nil {
		c.add(name, api.DoctorUnknown, conf+" cannot be read by the daemon: "+err.Error(), "")
		return
	}
	s.statePolicyResult(c, name, conf, PFBindsStates(string(b)))
}

// statePolicyResult adds the verdict on conf: bound states pass, floating ones fail.
func (s *Service) statePolicyResult(c *checkSet, name, conf string, bound bool) {
	if bound {
		c.add(name, api.DoctorOK, conf+" binds states to interfaces (set state-policy if-bound)", "")
		return
	}
	c.add(name, api.DoctorFail, conf+" has no `set state-policy if-bound`: with pf's default (floating) states a connection that one hop of the host admitted passes the next without being judged, and jails behind NAT lose packets (only the first of a flow gets through)",
		"add the line `set state-policy if-bound` at the top of "+conf+" (with the other options), check and load it with `pfctl -nf "+conf+" && pfctl -f "+conf+"`; never `service pf restart` over ssh, it flushes the states and cuts the session")
}

// defaultBlock says whether the loaded ruleset (pfctl -s rules) has a block ... all rule that is not quick.
func defaultBlock(rules string) bool {
	for _, ln := range strings.Split(rules, "\n") {
		f := strings.Fields(ln)
		if len(f) > 1 && f[0] == "block" && f[len(f)-1] == "all" && !slices.Contains(f, "quick") {
			return true
		}
	}
	return false
}

// pfConfPath is the pf.conf the rc script loads: pf_rules of rc.conf (rc.conf.local wins), else /etc/pf.conf.
func (s *Service) pfConfPath() (string, error) {
	p := "/etc/pf.conf"
	for _, f := range []string{"/etc/rc.conf", "/etc/rc.conf.local"} {
		b, err := s.hostFile(f)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			m := rePFRules.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			v := m[1]
			if q := v[:min(1, len(v))]; q == `"` || q == "'" {
				v, _, _ = strings.Cut(v[1:], q)
			} else if f := strings.Fields(v); len(f) > 0 {
				v = f[0]
			}
			if strings.ContainsAny(v, "$`") || !strings.HasPrefix(v, "/") {
				return "", fmt.Errorf("pf_rules in %s is %q", f, m[1])
			}
			p = v
		}
	}
	return p, nil
}

// stripPFComments drops the comments of a pf.conf and joins its continued lines.
func stripPFComments(conf string) string {
	conf = strings.ReplaceAll(conf, "\\\n", " ")
	var out []string
	for _, ln := range strings.Split(conf, "\n") {
		if i := strings.IndexByte(ln, '#'); i >= 0 {
			ln = ln[:i]
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func (s *Service) doctorRuntime(ctx context.Context, c *checkSet) {
	// Rendered versus live, from the reconciler's last pass.
	if s.d.Reconciler != nil {
		rep := s.d.Reconciler.Last()
		switch {
		case rep.At.IsZero():
			c.add("reconcile", api.DoctorUnknown, "no reconcile pass has run yet", "")
		case rep.Err != nil:
			c.add("reconcile", api.DoctorFail, "the last pass failed: "+rep.Err.Error(), "")
		case len(rep.Drift) > 0 || len(rep.Failures) > 0:
			var l []string
			for k, v := range rep.Failures {
				l = append(l, k+": "+v)
			}
			for k, v := range rep.Drift {
				l = append(l, k+": "+strings.Join(v, "; "))
			}
			c.add("reconcile", api.DoctorWarn, strings.Join(l, " | "), "")
		default:
			c.add("reconcile", api.DoctorOK, "rendered and live state agree", "")
		}
	}
	// Stale epairs.
	if s.d.Net != nil {
		known := map[string]bool{}     // jail ids
		knownBase := map[string]bool{} // the jail part of epair names
		s.mu.RLock()
		for _, e := range s.jails {
			known[e.jail.Metadata.UUID] = true
			if h, _, err := ipam.EpairNames(e.jail.Metadata.UUID, 0); err == nil {
				knownBase[h[:len(h)-3]] = true
			}
		}
		s.mu.RUnlock()
		ifs, err := s.d.Net.List(ctx)
		if err != nil {
			c.add("network.epairs", api.DoctorUnknown, err.Error(), "")
		} else {
			var stale []string
			for _, i := range ifs {
				if !ipam.IsEpairName(i.Name) || !render.IsJailOpsDesc(i.Description) || strings.HasPrefix(i.Description, "jailops net=") {
					continue
				}
				if knownBase[i.Name[:len(i.Name)-3]] {
					continue
				}
				stale = append(stale, i.Name)
			}
			if len(stale) > 0 {
				c.add("network.epairs", api.DoctorWarn, "epairs without a jail: "+strings.Join(stale, ", "), "the reconciler removes them on its next pass")
			} else {
				c.add("network.epairs", api.DoctorOK, "no stale epairs", "")
			}
		}
	}
	// Degraded jails.
	var deg []string
	s.mu.RLock()
	for n, e := range s.jails {
		if len(e.problems) > 0 {
			deg = append(deg, n)
		}
	}
	s.mu.RUnlock()
	if len(deg) > 0 {
		c.add("jails.health", api.DoctorWarn, "jails with damaged datasets or records: "+strings.Join(deg, ", "), "")
	} else {
		c.add("jails.health", api.DoctorOK, "all jails are consistent", "")
	}
	if d, err := s.Desired(ctx); err == nil {
		var l []string
		for _, n := range d.Networks {
			if n.Problem != "" {
				l = append(l, "network "+n.Name+": "+n.Problem)
			}
		}
		for _, j := range d.Jails {
			if j.Problem != "" {
				l = append(l, "jail "+j.Name+": "+j.Problem)
			}
		}
		if len(l) > 0 {
			c.add("render", api.DoctorWarn, strings.Join(l, "; "), "")
		} else {
			c.add("render", api.DoctorOK, "all configuration renders", "")
		}
	}
	if o := s.Recovered(); len(o) > 0 {
		var l []string
		for _, r := range o {
			l = append(l, r.Run+": "+r.Action)
		}
		c.add("startup.recovery", api.DoctorWarn, "interrupted operations were handled at start: "+strings.Join(l, "; "), "")
	}
	if s.d.ConfDir != "" {
		if _, err := os.Stat(s.d.ConfDir); err != nil {
			c.add("conf.dir", api.DoctorWarn, err.Error(), "")
		}
	}
}

// quickPassesBeforeAnchor lists the `pass ... quick` rules, in the loaded ruleset, that stand before the jailops
// anchor and are not tied to an interface that is not a jail's: pf stops at a quick rule, so a jail policy after it
// never sees that traffic. Rules for one named interface (the uplink) are not a problem for traffic of the jails'
// own interfaces and are skipped.
func quickPassesBeforeAnchor(rules string) []string {
	var out []string
	for _, ln := range strings.Split(rules, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.Contains(ln, `anchor "jailops/*"`) {
			break
		}
		if !strings.HasPrefix(ln, "pass ") || !strings.Contains(ln, " quick ") {
			continue
		}
		if strings.Contains(ln, " on ") && !strings.Contains(ln, " on jo") {
			continue
		}
		out = append(out, ln)
		if len(out) == 5 {
			break
		}
	}
	return out
}

// doctorNDPProxy reports the networks in IPv6 proxy mode whose proxy is not answering: the upstream router then cannot
// find their jails, and nothing else says so. A proxy whose capture is still being opened (the reconcile loop started it
// a moment ago) is a warning, not a failure: it opens on its own.
func (s *Service) doctorNDPProxy(c *checkSet) {
	var bad, starting, flooded []string
	proxied := 0
	nets, _ := s.netKind.list()
	s.mu.RLock()
	for _, o := range nets {
		if o.Spec.IPv6 == nil || o.Spec.IPv6.Mode != api.IPv6Proxy {
			continue
		}
		proxied++
		answering := false
		reason, msg := "", "no status yet"
		for _, cd := range s.netStat[o.Meta.Name].Conditions {
			if cd.Type == "NDPProxy" {
				answering, reason, msg = cd.Status == api.ConditionTrue, cd.Reason, cd.Message
			}
			if cd.Type == "NDPFlood" && cd.Status != api.ConditionTrue {
				flooded = append(flooded, o.Meta.Name+": "+cd.Message)
			}
		}
		switch {
		case answering:
		case reason == "Starting":
			starting = append(starting, o.Meta.Name+": "+msg)
		default:
			bad = append(bad, o.Meta.Name+": "+msg)
		}
	}
	s.mu.RUnlock()
	switch {
	case proxied == 0:
		return
	case len(bad) > 0:
		c.add("network.ndproxy", api.DoctorFail, "the IPv6 proxy is not answering for "+strings.Join(append(bad, starting...), "; "),
			"read the network's NDPProxy condition (jailops network show): it says what the helper refused or what failed")
	case len(starting) > 0:
		c.add("network.ndproxy", api.DoctorWarn, "the IPv6 proxy is not answering yet for "+strings.Join(starting, "; ")+"; it opens within a few minutes after the daemon starts",
			"run jailops doctor again in a few minutes; see the network's NDPProxy condition")
	case len(flooded) > 0:
		c.add("network.ndproxy", api.DoctorWarn, "the IPv6 proxy dropped solicitations over its limits: "+strings.Join(flooded, "; "),
			"a neighbor on the uplink sends far more neighbor solicitations than a segment needs; find it with tcpdump on the uplink (icmp6 and ip6[40] == 135) and ask the provider or the switch's port security to stop it")
	default:
		c.add("network.ndproxy", api.DoctorOK, "the IPv6 proxy answers for every proxy-mode network", "")
	}
}

// minHostMajor and minHostMinor are the oldest FreeBSD release JailOps is built and tested for.
const minHostMajor, minHostMinor = 15, 1

// doctorRelease checks the running FreeBSD release. JailOps targets 15.1 and later: it relies on pkgbase, on the
// pf and VNET behaviour of 15.1, and nothing older is tested.
func (s *Service) doctorRelease(ctx context.Context, c *checkSet) {
	r, err := s.sysctl(ctx, "kern.osrelease")
	if err != nil || r == "" {
		c.add("host.release", api.DoctorUnknown, "the FreeBSD release cannot be read here", "")
		return
	}
	var major, minor int
	if _, err := fmt.Sscanf(r, "%d.%d", &major, &minor); err != nil {
		c.add("host.release", api.DoctorUnknown, "the release "+r+" is not one JailOps recognises", "")
		return
	}
	if major < minHostMajor || (major == minHostMajor && minor < minHostMinor) {
		c.add("host.release", api.DoctorFail, "FreeBSD "+r+" is older than the first release JailOps supports, 15.1",
			"upgrade the host to FreeBSD 15.1 or later")
		return
	}
	c.add("host.release", api.DoctorOK, "FreeBSD "+r, "")
}

// doctorAppsLocal checks the host's own app definitions (apps.local_dir)
// when the directory exists: the daemon must be able to read it, or the
// whole catalog listing fails.
func (s *Service) doctorAppsLocal(c *checkSet) {
	dir := s.appsLocalDir()
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return
	}
	es, err := apps.Load(dir)
	if err != nil {
		c.add("apps.local_dir", api.DoctorFail, fmt.Sprintf("%s cannot be read: %v", dir, err),
			"the daemon runs as the user jailops: chmod 0755 "+dir+" and 0644 its files")
		return
	}
	bad := 0
	for _, e := range es {
		if e.Err != nil {
			bad++
		}
	}
	if bad > 0 {
		c.add("apps.local_dir", api.DoctorWarn, fmt.Sprintf("%d of %d definition(s) in %s are invalid", bad, len(es), dir),
			"jailops app list --source local shows the reasons; jailops app validate "+dir+" checks them")
		return
	}
	c.add("apps.local_dir", api.DoctorOK, fmt.Sprintf("%d definition(s) in %s", len(es), dir), "")
}

// sizeText writes a number of bytes the way a person reads it (1.5 GiB).
func sizeText(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
