package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Host management, module identity (docs/appliance.md). Four operations: host.identity.read reads the host name,
// /etc/resolv.conf, the jailops block of /etc/ntp.conf and three /etc/rc.conf variables; host.identity.apply takes
// validated structured fields (never a file body), renders the files itself, keeps a copy of every file it changes
// and writes; host.snapshot.list and host.snapshot.restore list and put back those copies.
//
// Changing anything needs the admin assertion and the module in host-manage of priv.conf: the daemon's own
// configuration is not enough, because a daemon that is not trustworthy could ignore it. The copies and the record of
// what was applied live in host-dir, a directory of root that the daemon cannot write: a restore copies files back
// into /etc as root, so their content must be the helper's own.
//
// UNVERIFIED: the commands (hostname, sysrc -f, service ntpd restart|onestop, ntpq -pn) have run against fakes only;
// scripts/ci-freebsd-e2e.sh has a block for a real host (JAILOPS_E2E_HOST=1).

// DefaultHostDir holds the snapshots and the applied record of host management.
const DefaultHostDir = "/var/db/jailops-priv/host"

// Markers of the files the identity module renders.
const (
	HostResolvHeader = "# managed by jailops"
	HostNTPBegin     = "# jailops begin"
	HostNTPEnd       = "# jailops end"
)

// Fixed commands of host management. Nothing a caller sends names a program.
const (
	hostnameBin = "/bin/hostname"
	sysrcBin    = "/usr/sbin/sysrc"
	serviceBin  = "/usr/sbin/service"
	ntpqBin     = "/usr/bin/ntpq"
)

// MaxHostSnapshots is how many snapshots are kept; older ones are removed when a new one is taken.
const MaxHostSnapshots = 20

// maxHostFile bounds a host file the helper reads or keeps a copy of.
const maxHostFile = 1 << 20

// HostRCVars are the only /etc/rc.conf variables host management sets, each with the pattern of its value.
var HostRCVars = map[string]*regexp.Regexp{
	"hostname":           regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`),
	"ntpd_enable":        regexp.MustCompile(`^(YES|NO)$`),
	"ntpd_sync_on_start": regexp.MustCompile(`^(YES|NO)$`),
	// module firewall; pf_rules is only ever set to the pf.conf the module writes (sysrcSet checks it)
	"pf_enable": regexp.MustCompile(`^YES$`),
	"pf_rules":  regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,250}$`),
}

// hostModuleRCVars are the rc.conf variables each module owns. A snapshot records only these (not a copy of
// rc.conf), and a restore sets or removes only these: whatever else root changed in rc.conf since stays.
var hostModuleRCVars = map[string][]string{
	api.HostModuleIdentity: {"hostname", "ntpd_enable", "ntpd_sync_on_start"},
	api.HostModuleFirewall: {"pf_enable", "pf_rules"},
}

// reRCRestore is what a value put back from a snapshot may hold: the values host management writes and the plain
// values a host has for these variables; anything else is refused and left to the administrator.
var reRCRestore = regexp.MustCompile(`^[A-Za-z0-9._/:+-]{0,253}$`)

// hostIdentityFiles are the files of /etc the identity module touches, by name below the etc directory.
var hostIdentityFiles = []string{"resolv.conf", "ntp.conf", "rc.conf"}

type hostApplyArgs struct {
	Spec   api.HostIdentitySpec `json:"spec"`
	DryRun bool                 `json:"dry_run,omitempty"`
}

type hostRestoreArgs struct {
	Name   string `json:"name"`
	DryRun bool   `json:"dry_run,omitempty"`
}

type hostSnapshotsRes struct {
	V []api.HostSnapshot `json:"v"`
}

// hostApplied is the record of what the identity module applied last.
type hostApplied struct {
	Spec api.HostIdentitySpec `json:"spec"`
	Time time.Time            `json:"time"`
}

// hostSnapFile is one file of a snapshot.
type hostSnapFile struct {
	Name   string `json:"name"` // below the etc directory
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
}

// hostManifest describes a snapshot (snapshot.json in its directory).
type hostManifest struct {
	Module   string         `json:"module"`
	Time     time.Time      `json:"time"`
	Reason   string         `json:"reason"`
	Hostname string         `json:"hostname"` // the running host name before the change
	Files    []hostSnapFile `json:"files"`
	Applied  *hostApplied   `json:"applied,omitempty"`
	// Firewall is the record of the firewall module when the snapshot was taken, PFEnabled whether pf ran.
	Firewall  *hostFirewallRecord `json:"firewall,omitempty"`
	PFEnabled *bool               `json:"pf_enabled,omitempty"`
	// RC holds the module's rc.conf variables as they were (null: not set) when rc.conf is among the files; no copy
	// of rc.conf is kept. A snapshot of an earlier version has a copy instead, and only these variables are read
	// from it.
	RC map[string]*string `json:"rc,omitempty"`
}

// hostModuleFiles are the files of /etc each module touches; a manifest naming another file is refused.
var hostModuleFiles = map[string][]string{api.HostModuleIdentity: hostIdentityFiles, api.HostModuleFirewall: hostFirewallFiles}

// hostFile is a file of /etc as it is now.
type hostFile struct {
	name   string
	data   string
	exists bool
	mode   os.FileMode
	uid    int
	gid    int
}

// ---- configuration and access ----

func (c Config) checkHostManage() error {
	var seen []string
	for _, m := range c.HostManage {
		if !slices.Contains(api.HostModules, m) {
			return api.Errorf(api.CodeInvalid, "host-manage %q is not a module (known: %s)", m, strings.Join(api.HostModules, ", "))
		}
		if slices.Contains(seen, m) {
			return api.Errorf(api.CodeInvalid, "host-manage %q is listed twice", m)
		}
		seen = append(seen, m)
	}
	return nil
}

// hostAllowed checks what every change needs: the admin assertion and the module in priv.conf. The refusal of the
// module carries detail module=<name>, which the daemon turns into not_managed.
func (l *Local) hostAllowed(ctx context.Context, module string) error {
	if !isAdmin(ctx) {
		return forbidden("changing the host's %s needs the admin assertion", module)
	}
	if !slices.Contains(l.cfg.HostManage, module) {
		return api.Errorf(api.CodeForbidden, "host-manage of priv.conf does not list %s: the helper does not change it", module).
			WithHint("add `host-manage = "+module+"` to priv.conf and restart jailops-priv").WithDetail("module", module)
	}
	return nil
}

func (l *Local) etcDir() string {
	if l.d.Etc != "" {
		return l.d.Etc
	}
	return "/etc"
}

func (l *Local) etcPath(name string) string { return filepath.Join(l.etcDir(), name) }

func (l *Local) now() time.Time {
	if l.d.Now != nil {
		return l.d.Now()
	}
	return time.Now()
}

// readEtc reads one file of the etc directory. A symlink or anything but a regular file is refused: the helper
// never writes through a link.
func (l *Local) readEtc(name string) (hostFile, error) {
	f := hostFile{name: name}
	root, err := os.OpenRoot(l.etcDir())
	if err != nil {
		return f, mapFSErr(err)
	}
	defer root.Close()
	st, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, mapFSErr(err)
	}
	if !st.Mode().IsRegular() {
		return f, forbidden("%s is not a regular file; JailOps does not write through links", l.etcPath(name))
	}
	if st.Size() > maxHostFile {
		return f, invalid("%s is larger than %d bytes", l.etcPath(name), maxHostFile)
	}
	fh, err := root.Open(name)
	if err != nil {
		return f, mapFSErr(err)
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxHostFile+1))
	if err != nil {
		return f, mapFSErr(err)
	}
	f.data, f.exists, f.mode = string(b), true, st.Mode().Perm()
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		f.uid, f.gid = int(s.Uid), int(s.Gid)
	}
	return f, nil
}

// writeAtomic replaces dir/name with data: a temporary file in the same directory, synced, then renamed over it.
// The mode and owner are those given (the old file's).
func (l *Local) writeAtomic(dir, name string, data []byte, mode os.FileMode, uid, gid int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return mapFSErr(err)
	}
	defer root.Close()
	if st, err := root.Lstat(name); err == nil && !st.Mode().IsRegular() {
		return forbidden("%s is not a regular file", filepath.Join(dir, name))
	}
	tmp := tmpName(name)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return mapFSErr(err)
	}
	fail := func(err error) error { f.Close(); _ = root.Remove(tmp); return mapFSErr(err) }
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := f.Chown(uid, gid); err != nil && !l.noChown {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return mapFSErr(err)
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return mapFSErr(err)
	}
	if d, err := root.Open("."); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// hostDir opens the helper's own directory, creating it when missing. It must belong to root and be closed to
// everybody else: its content is copied into /etc by a restore.
func (l *Local) hostDir() (*os.Root, error) {
	dir := l.cfg.HostDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, mapFSErr(err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, mapFSErr(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, forbidden("%s is not a plain directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != l.hostDirUID || fi.Mode().Perm()&0o077 != 0 {
		return nil, forbidden("%s must belong to root with mode 0700", dir)
	}
	return os.OpenRoot(dir)
}

// hostRun runs one fixed command of host management.
func (l *Local) hostRun(ctx context.Context, name string, args ...string) (string, error) {
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: name, Args: args, Timeout: 60 * time.Second, MaxOutput: 64 << 10})
	return string(res.Stdout), err
}

// sysrcRestore puts back a variable of the module's own as a snapshot recorded it: set to its value, or removed
// (sysrc -x) when it was not set.
func (l *Local) sysrcRestore(ctx context.Context, name string, value *string) error {
	if HostRCVars[name] == nil {
		return forbidden("rc.conf variable %q is not one host management sets", name)
	}
	if value == nil {
		_, err := l.hostRun(ctx, sysrcBin, "-f", l.etcPath("rc.conf"), "-x", name)
		return err
	}
	if !reRCRestore.MatchString(*value) {
		return invalid("the snapshot's value of rc.conf %s is not one the helper writes back; set it by hand", name)
	}
	_, err := l.hostRun(ctx, sysrcBin, "-f", l.etcPath("rc.conf"), name+"="+*value)
	return err
}

// sysrcSet sets one allow-listed rc.conf variable through sysrc(8).
func (l *Local) sysrcSet(ctx context.Context, name, value string) error {
	re := HostRCVars[name]
	if re == nil {
		return forbidden("rc.conf variable %q is not one host management sets", name)
	}
	if !re.MatchString(value) {
		return invalid("invalid value %q for rc.conf %s", value, name)
	}
	if name == "pf_rules" && value != l.etcPath("pf.conf") {
		return forbidden("rc.conf pf_rules is only set to %s", l.etcPath("pf.conf"))
	}
	_, err := l.hostRun(ctx, sysrcBin, "-f", l.etcPath("rc.conf"), name+"="+value)
	return err
}

// ---- parsing and rendering (pure) ----

// parseResolv returns the nameservers and the search domains of resolv.conf and whether it carries the header.
func parseResolv(s string) (ns, search []string, managed bool) {
	lines := splitLines(s)
	managed = len(lines) > 0 && strings.TrimSpace(lines[0]) == HostResolvHeader
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || strings.HasPrefix(f[0], ";") {
			continue
		}
		switch f[0] {
		case "nameserver":
			ns = append(ns, f[1])
		case "search":
			search = append([]string(nil), f[1:]...)
		}
	}
	return ns, search, managed
}

// renderResolv renders the whole of resolv.conf.
func renderResolv(r api.HostResolvers) string {
	var b strings.Builder
	b.WriteString(HostResolvHeader + "\n")
	b.WriteString("# Set with `jailops host identity set`; a change made here is reported as drift.\n")
	if len(r.Search) > 0 {
		b.WriteString("search " + strings.Join(r.Search, " ") + "\n")
	}
	for _, n := range r.Nameservers {
		b.WriteString("nameserver " + n + "\n")
	}
	return b.String()
}

// ntpBlock finds the jailops block: the line numbers of its markers, -1 when there is none. Markers out of order,
// twice or alone are an error: the helper does not guess what someone meant.
func ntpBlock(lines []string) (begin, end int, err error) {
	begin, end = -1, -1
	for i, ln := range lines {
		switch strings.TrimSpace(ln) {
		case HostNTPBegin:
			if begin >= 0 {
				return 0, 0, api.Errorf(api.CodeConflict, "ntp.conf has %q twice", HostNTPBegin)
			}
			begin = i
		case HostNTPEnd:
			if begin < 0 || end >= 0 {
				return 0, 0, api.Errorf(api.CodeConflict, "ntp.conf has %q without a matching %q before it", HostNTPEnd, HostNTPBegin)
			}
			end = i
		}
	}
	if begin >= 0 && end < 0 {
		return 0, 0, api.Errorf(api.CodeConflict, "ntp.conf has %q without %q", HostNTPBegin, HostNTPEnd)
	}
	return begin, end, nil
}

// parseNTP returns the servers of the jailops block and whether the block is there.
func parseNTP(s string) ([]string, bool, error) {
	lines := splitLines(s)
	b, e, err := ntpBlock(lines)
	if err != nil || b < 0 {
		return nil, false, err
	}
	var out []string
	for _, ln := range lines[b+1 : e] {
		if f := strings.Fields(ln); len(f) >= 2 && (f[0] == "server" || f[0] == "pool") {
			out = append(out, f[1])
		}
	}
	return out, true, nil
}

// renderNTP replaces the jailops block of ntp.conf (or appends it); every other line stays as it is. No servers
// removes the block.
func renderNTP(s string, servers []string) (string, error) {
	lines := splitLines(s)
	b, e, err := ntpBlock(lines)
	if err != nil {
		return "", err
	}
	var block []string
	if len(servers) > 0 {
		block = append(block, HostNTPBegin)
		for _, v := range servers {
			block = append(block, "server "+v+" iburst")
		}
		block = append(block, HostNTPEnd)
	}
	var out []string
	if b >= 0 {
		out = append(append(append(out, lines[:b]...), block...), lines[e+1:]...)
	} else {
		out = append(append(out, lines...), block...)
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\n") + "\n", nil
}

// parseRC returns the value of each variable host management sets, from the plain assignments of rc.conf.
func parseRC(s string) map[string]string {
	out := map[string]string{}
	for _, ln := range splitLines(s) {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok || HostRCVars[k] == nil {
			continue
		}
		v = strings.TrimSpace(v)
		if v != "" && (v[0] == '"' || v[0] == '\'') {
			if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
				v = v[1 : end+1]
			}
		} else if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[k] = v
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

// parseNTPQ reads `ntpq -pn`: the line of the system peer starts with '*'.
func parseNTPQ(out string) api.HostNTPSync {
	for _, ln := range splitLines(out) {
		if strings.HasPrefix(ln, "*") {
			peer := strings.Fields(strings.TrimPrefix(ln, "*"))
			if len(peer) > 0 {
				return api.HostNTPSync{Synchronised: true, Peer: peer[0]}
			}
		}
	}
	return api.HostNTPSync{Detail: "no server is selected yet"}
}

// ---- read ----

type identityFiles struct {
	files    map[string]hostFile
	hostname string // running
}

func (l *Local) readIdentity(ctx context.Context) (identityFiles, error) {
	out := identityFiles{files: map[string]hostFile{}}
	for _, n := range hostIdentityFiles {
		f, err := l.readEtc(n)
		if err != nil {
			return out, err
		}
		out.files[n] = f
	}
	h, err := l.hostRun(ctx, hostnameBin)
	if err != nil {
		return out, err
	}
	out.hostname = strings.TrimSpace(h)
	return out, nil
}

// current is the identity the files and the running host name hold.
func (f identityFiles) current() (api.HostIdentitySpec, map[string]string, bool, bool, error) {
	ns, search, managed := parseResolv(f.files["resolv.conf"].data)
	servers, block, err := parseNTP(f.files["ntp.conf"].data)
	if err != nil {
		return api.HostIdentitySpec{}, nil, false, false, err
	}
	rc := parseRC(f.files["rc.conf"].data)
	cur := api.HostIdentitySpec{
		Hostname:  f.hostname,
		Resolvers: &api.HostResolvers{Nameservers: orEmpty(ns), Search: search},
		NTP:       &api.HostNTP{Servers: orEmpty(servers), Enable: strings.EqualFold(rc["ntpd_enable"], "YES")},
	}
	return cur, rc, managed, block, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// HostIdentityRead implements Host. It changes nothing and needs no assertion; file contents never leave the helper,
// only the values the module manages.
func (l *Local) HostIdentityRead(ctx context.Context) (service.HostIdentityState, error) {
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	f, err := l.readIdentity(ctx)
	if err != nil {
		return service.HostIdentityState{}, err
	}
	cur, rc, managed, block, err := f.current()
	if err != nil {
		return service.HostIdentityState{}, err
	}
	st := service.HostIdentityState{Current: cur, RCHostname: rc["hostname"], ResolvManaged: managed, NTPBlock: block,
		Modules: append([]string(nil), l.cfg.HostManage...)}
	if a, err := l.readApplied(); err == nil && a != nil {
		st.Applied, st.AppliedAt = &a.Spec, a.Time
	}
	// ntpq needs no privilege; a missing or silent ntpd leaves the state unknown or not synchronised.
	if out, err := l.hostRun(ctx, ntpqBin, "-pn"); err == nil {
		s := parseNTPQ(out)
		st.NTPSync = &s
	} else if _, ok := run.IsExit(err); ok && cur.NTP.Enable {
		st.NTPSync = &api.HostNTPSync{Detail: "ntpd does not answer ntpq"}
	}
	return st, nil
}

func (l *Local) readApplied() (*hostApplied, error) {
	if _, err := os.Lstat(l.cfg.HostDir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	root, err := l.hostDir()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	b, err := root.ReadFile("identity.json")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, mapFSErr(err)
	}
	var a hostApplied
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("%s/identity.json: %w", l.cfg.HostDir, err)
	}
	return &a, nil
}

func (l *Local) writeApplied(a *hostApplied) error {
	root, err := l.hostDir()
	if err != nil {
		return err
	}
	defer root.Close()
	if a == nil {
		if err := root.Remove("identity.json"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return mapFSErr(err)
		}
		return nil
	}
	b, _ := json.MarshalIndent(a, "", "  ")
	return l.writeAtomic(l.cfg.HostDir, "identity.json", append(b, '\n'), 0o600, 0, 0)
}

// ---- plan ----

// fileChange is one file to write (or remove).
type fileChange struct {
	cur  hostFile
	data string
	keep bool // false: remove the file (a restore of a file that did not exist)
}

// hostPlan is what an apply or a restore does, in order: files, rc.conf variables, the host name, ntpd.
type hostPlan struct {
	files []fileChange
	rc    [][2]string // name, value
	// rcBack are the variables a restore puts back (nil: remove), in order; checked by sysrcRestore
	rcBack   []rcValue
	hostname string // set the running host name; "" leaves it
	ntpd     string // "restart", "onestop" or ""
	diff     strings.Builder
	actions  []string
}

// rcValue is an rc.conf variable and its value; nil is not set.
type rcValue struct {
	name  string
	value *string
}

func (p *hostPlan) changed() bool {
	return len(p.files) > 0 || len(p.rc) > 0 || len(p.rcBack) > 0 || p.hostname != "" || p.ntpd != ""
}

func (p *hostPlan) touched() []string {
	var out []string
	for _, f := range p.files {
		out = append(out, f.cur.name)
	}
	if len(p.rc)+len(p.rcBack) > 0 && !slices.Contains(out, "rc.conf") {
		out = append(out, "rc.conf")
	}
	return out
}

func (l *Local) planFile(p *hostPlan, cur hostFile, data string, keep bool, what string) {
	if cur.exists == keep && cur.data == data {
		return
	}
	p.files = append(p.files, fileChange{cur: cur, data: data, keep: keep})
	p.diff.WriteString(unifiedDiff(l.etcPath(cur.name), cur.data, data, cur.exists, keep))
	if keep {
		p.actions = append(p.actions, "write "+l.etcPath(cur.name)+what)
	} else {
		p.actions = append(p.actions, "remove "+l.etcPath(cur.name))
	}
}

// planIdentity compares the spec with the host. It is pure apart from the paths it names.
func (l *Local) planIdentity(f identityFiles, spec api.HostIdentitySpec) (*hostPlan, error) {
	p := &hostPlan{}
	_, rc, _, _, err := f.current()
	if err != nil {
		return nil, err
	}
	if r := spec.Resolvers; r != nil {
		l.planFile(p, f.files["resolv.conf"], renderResolv(*r), true, "")
	}
	ntpRestart, ntpEnableChanged := false, false
	if n := spec.NTP; n != nil {
		cur := f.files["ntp.conf"]
		data, err := renderNTP(cur.data, n.Servers)
		if err != nil {
			return nil, err
		}
		before := len(p.files)
		l.planFile(p, cur, data, cur.exists || data != "", " (the jailops block)")
		ntpRestart = len(p.files) > before
	}
	var rcDiff []string
	setRC := func(name, value string) {
		old, ok := rc[name]
		if ok && old == value {
			return
		}
		p.rc = append(p.rc, [2]string{name, value})
		if ok {
			rcDiff = append(rcDiff, fmt.Sprintf("-%s=%q", name, old))
		}
		rcDiff = append(rcDiff, fmt.Sprintf("+%s=%q", name, value))
		was := " (not set)"
		if ok {
			was = fmt.Sprintf(" (was %q)", old)
		}
		p.actions = append(p.actions, fmt.Sprintf("sysrc -f %s %s=%s%s", l.etcPath("rc.conf"), name, value, was))
	}
	if spec.Hostname != "" {
		setRC("hostname", spec.Hostname)
	}
	if n := spec.NTP; n != nil {
		on := strings.EqualFold(rc["ntpd_enable"], "YES")
		ntpEnableChanged = on != n.Enable
		if ntpEnableChanged || !strings.EqualFold(rc["ntpd_enable"], yesNo(n.Enable)) {
			setRC("ntpd_enable", yesNo(n.Enable))
		}
		if n.Enable {
			setRC("ntpd_sync_on_start", "YES")
		}
		switch {
		case n.Enable && (ntpRestart || ntpEnableChanged):
			p.ntpd = "restart"
		case !n.Enable && ntpEnableChanged:
			p.ntpd = "onestop"
		}
	}
	if len(rcDiff) > 0 {
		fmt.Fprintf(&p.diff, "--- %s\n+++ %s (variables set with sysrc)\n%s\n", l.etcPath("rc.conf"), l.etcPath("rc.conf"), strings.Join(rcDiff, "\n"))
	}
	if spec.Hostname != "" && spec.Hostname != f.hostname {
		p.hostname = spec.Hostname
		p.actions = append(p.actions, fmt.Sprintf("hostname %s (was %s)", spec.Hostname, f.hostname))
	}
	if p.ntpd != "" {
		p.actions = append(p.actions, "service ntpd "+p.ntpd)
	}
	return p, nil
}

// execute does what the plan says. On an error it stops; the caller puts the snapshot back.
func (l *Local) execute(ctx context.Context, p *hostPlan) error {
	for _, f := range p.files {
		if !f.keep {
			if err := os.Remove(l.etcPath(f.cur.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return mapFSErr(err)
			}
			continue
		}
		mode, uid, gid := f.cur.mode, f.cur.uid, f.cur.gid
		if !f.cur.exists {
			mode, uid, gid = 0o644, 0, 0
		}
		if err := l.writeAtomic(l.etcDir(), f.cur.name, []byte(f.data), mode, uid, gid); err != nil {
			return err
		}
	}
	for _, kv := range p.rc {
		if err := l.sysrcSet(ctx, kv[0], kv[1]); err != nil {
			return err
		}
	}
	for _, v := range p.rcBack {
		if err := l.sysrcRestore(ctx, v.name, v.value); err != nil {
			return err
		}
	}
	if p.hostname != "" {
		if !api.ValidDNSName(p.hostname) {
			return invalid("invalid host name %q", p.hostname)
		}
		if _, err := l.hostRun(ctx, hostnameBin, p.hostname); err != nil {
			return err
		}
	}
	switch p.ntpd {
	case "restart":
		if _, err := l.hostRun(ctx, serviceBin, "ntpd", "restart"); err != nil {
			return err
		}
	case "onestop":
		// ntpd may not run at all; stopping it is all that is asked.
		if _, err := l.hostRun(ctx, serviceBin, "ntpd", "onestop"); err != nil {
			if _, ok := run.IsExit(err); !ok {
				return err
			}
		}
	}
	return nil
}

// ---- apply ----

// HostIdentityApply implements Host.
func (l *Local) HostIdentityApply(ctx context.Context, spec api.HostIdentitySpec, dryRun bool) (api.HostChange, error) {
	if err := l.hostAllowed(ctx, api.HostModuleIdentity); err != nil {
		return api.HostChange{}, err
	}
	if err := spec.Validate(); err != nil {
		return api.HostChange{}, err
	}
	spec = spec.Canonical()
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	if p, err := l.readPending(); err != nil {
		return api.HostChange{}, err
	} else if p != nil && !dryRun {
		return api.HostChange{}, l.busyPending(*p)
	}
	f, err := l.readIdentity(ctx)
	if err != nil {
		return api.HostChange{}, err
	}
	p, err := l.planIdentity(f, spec)
	if err != nil {
		return api.HostChange{}, err
	}
	res := api.HostChange{DryRun: dryRun, Changed: p.changed(), Diff: p.diff.String(), Actions: p.actions}
	if res.Actions == nil {
		res.Actions = []string{}
	}
	if dryRun || !p.changed() {
		if p.changed() {
			res.Actions = append([]string{"keep a copy of " + strings.Join(l.etcPaths(p.touched()), ", ") + " (snapshot)"}, res.Actions...)
		} else if !dryRun {
			// The host already has it: the record still says JailOps applied it, so drift is measured against it.
			if err := l.recordApplied(spec); err != nil {
				return res, err
			}
		}
		return res, nil
	}
	prev, err := l.readApplied()
	if err != nil {
		return res, err
	}
	snap, err := l.takeSnapshot(f, p.touched(), "apply", prev)
	if err != nil {
		return res, err
	}
	res.Snapshot = snap
	res.Actions = append([]string{"keep a copy of " + strings.Join(l.etcPaths(p.touched()), ", ") + " in snapshot " + snap}, res.Actions...)
	if err := l.execute(ctx, p); err != nil {
		return res, l.undo(ctx, snap, err)
	}
	if err := l.recordApplied(spec); err != nil {
		return res, err
	}
	return res, nil
}

func (l *Local) etcPaths(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = l.etcPath(n)
	}
	return out
}

// recordApplied merges the parts of spec into the record of what was applied.
func (l *Local) recordApplied(spec api.HostIdentitySpec) error {
	prev, err := l.readApplied()
	if err != nil {
		return err
	}
	a := hostApplied{Time: l.now().UTC()}
	if prev != nil {
		a.Spec = prev.Spec
	}
	if spec.Hostname != "" {
		a.Spec.Hostname = spec.Hostname
	}
	if spec.Resolvers != nil {
		a.Spec.Resolvers = spec.Resolvers
	}
	if spec.NTP != nil {
		a.Spec.NTP = spec.NTP
	}
	return l.writeApplied(&a)
}

// undo puts the snapshot back after a failed change and says what happened.
func (l *Local) undo(ctx context.Context, snap string, cause error) error {
	var ae *api.Error
	code := api.CodeInternal
	if errors.As(cause, &ae) {
		code = ae.Code
	}
	if _, err := l.restore(ctx, snap, false, false); err != nil {
		return api.Errorf(code, "%v; putting snapshot %s back failed too: %v", cause, snap, err).
			WithHint("the copies are in "+filepath.Join(l.cfg.HostDir, "snapshots", snap)+"; restore them by hand as root").WithDetail("snapshot", snap)
	}
	return api.Errorf(code, "%v; the files of snapshot %s were put back", cause, snap).WithDetail("snapshot", snap)
}

// ---- snapshots ----

var reSnapDir = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z(-[0-9]{1,3})?$`)

// takeSnapshot keeps a copy of the named files of f (only those) with the record of what was applied.
func (l *Local) takeSnapshot(f identityFiles, names []string, reason string, applied *hostApplied) (string, error) {
	return l.keepSnapshot(hostManifest{Module: api.HostModuleIdentity, Reason: reason, Hostname: f.hostname, Applied: applied}, f.files, names)
}

func snapFilePath(snap, name string) string { return filepath.Join("snapshots", snap, name) }

// keepSnapshot keeps a copy of the named files (only those) with the manifest m; it sets the time and the list.
func (l *Local) keepSnapshot(m hostManifest, files map[string]hostFile, names []string) (string, error) {
	root, err := l.hostDir()
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.MkdirAll("snapshots", 0o700); err != nil {
		return "", mapFSErr(err)
	}
	now := l.now().UTC()
	base := now.Format("20060102T150405Z")
	name := base
	for i := 1; ; i++ {
		err := root.Mkdir(filepath.Join("snapshots", name), 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i > 999 {
			return "", mapFSErr(err)
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	dir := filepath.Join(l.cfg.HostDir, "snapshots", name)
	m.Time, m.Files = now, nil
	for _, n := range names {
		hf := files[n]
		sf := hostSnapFile{Name: n, Exists: hf.exists}
		if n == "rc.conf" {
			// the module's variables only: rc.conf is root's file, the rest of it is not the module's to put back
			m.RC = map[string]*string{}
			cur := parseRC(hf.data)
			for _, v := range hostModuleRCVars[m.Module] {
				if val, ok := cur[v]; ok {
					m.RC[v] = &val
				} else {
					m.RC[v] = nil
				}
			}
			m.Files = append(m.Files, sf)
			continue
		}
		if hf.exists {
			sf.Mode, sf.UID, sf.GID = uint32(hf.mode), hf.uid, hf.gid
			if err := l.writeAtomic(dir, n, []byte(hf.data), 0o600, 0, 0); err != nil {
				return "", err
			}
		}
		m.Files = append(m.Files, sf)
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := l.writeAtomic(dir, "snapshot.json", append(b, '\n'), 0o600, 0, 0); err != nil {
		return "", err
	}
	l.pruneSnapshots(root)
	return name, nil
}

// pruneSnapshots removes the oldest snapshots beyond MaxHostSnapshots.
func (l *Local) pruneSnapshots(root *os.Root) {
	names, err := l.snapshotNames(root)
	if err != nil || len(names) <= MaxHostSnapshots {
		return
	}
	for _, n := range names[MaxHostSnapshots:] {
		_ = root.RemoveAll(filepath.Join("snapshots", n))
	}
}

// snapshotNames lists the snapshot directories, newest first.
func (l *Local) snapshotNames(root *os.Root) ([]string, error) {
	d, err := root.Open("snapshots")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer d.Close()
	ents, err := d.ReadDir(-1)
	if err != nil {
		return nil, mapFSErr(err)
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() && reSnapDir.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool { return snapLess(names[j], names[i]) })
	return names, nil
}

// snapLess orders snapshot names by time, then by their suffix as a number.
func snapLess(a, b string) bool {
	ab, as, _ := strings.Cut(a, "-")
	bb, bs, _ := strings.Cut(b, "-")
	if ab != bb {
		return ab < bb
	}
	if len(as) != len(bs) {
		return len(as) < len(bs)
	}
	return as < bs
}

func (l *Local) readManifest(root *os.Root, name string) (hostManifest, error) {
	var m hostManifest
	b, err := root.ReadFile(filepath.Join("snapshots", name, "snapshot.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return m, api.Errorf(api.CodeNotFound, "host snapshot %q not found", name)
	}
	if err != nil {
		return m, mapFSErr(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("snapshot %s: %w", name, err)
	}
	allowed, ok := hostModuleFiles[m.Module]
	if !ok {
		return m, forbidden("snapshot %s is of module %q, which the helper does not know", name, m.Module)
	}
	for _, f := range m.Files {
		if !slices.Contains(allowed, f.Name) {
			return m, forbidden("snapshot %s names %q, which the %s module does not touch", name, f.Name, m.Module)
		}
	}
	return m, nil
}

// HostSnapshots implements Host.
func (l *Local) HostSnapshots(ctx context.Context) ([]api.HostSnapshot, error) {
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	if _, err := os.Lstat(l.cfg.HostDir); errors.Is(err, fs.ErrNotExist) {
		return []api.HostSnapshot{}, nil
	}
	root, err := l.hostDir()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	names, err := l.snapshotNames(root)
	if err != nil {
		return nil, err
	}
	out := []api.HostSnapshot{}
	for _, n := range names {
		m, err := l.readManifest(root, n)
		if err != nil {
			continue
		}
		s := api.HostSnapshot{Name: n, Module: m.Module, Time: m.Time, Reason: m.Reason, Files: []string{}}
		for _, f := range m.Files {
			s.Files = append(s.Files, l.etcPath(f.Name))
		}
		out = append(out, s)
	}
	return out, nil
}

// HostSnapshotRestore implements Host.
// The module of the snapshot decides which entry of host-manage the restore needs.
func (l *Local) HostSnapshotRestore(ctx context.Context, name string, dryRun bool) (api.HostChange, error) {
	if !isAdmin(ctx) {
		return api.HostChange{}, forbidden("restoring host files needs the admin assertion")
	}
	if err := api.ValidHostSnapshotName(name); err != nil {
		return api.HostChange{}, err
	}
	l.hostMu.Lock()
	defer l.hostMu.Unlock()
	module := api.HostModuleIdentity
	if _, err := os.Lstat(l.cfg.HostDir); err == nil {
		root, err := l.hostDir()
		if err != nil {
			return api.HostChange{}, err
		}
		if n, err := l.resolveSnapshot(root, name); err == nil {
			if m, err := l.readManifest(root, n); err == nil {
				module = m.Module
			}
		}
		root.Close()
	}
	if err := l.hostAllowed(ctx, module); err != nil {
		return api.HostChange{}, err
	}
	if p, err := l.readPending(); err != nil {
		return api.HostChange{}, err
	} else if p != nil && !dryRun {
		return api.HostChange{}, l.busyPending(*p)
	}
	return l.restoreSnapshot(ctx, name, dryRun, true, true, false)
}

// resolveSnapshot turns "latest" into the newest snapshot's name.
func (l *Local) resolveSnapshot(root *os.Root, name string) (string, error) {
	if name != api.HostSnapshotLatest {
		return name, nil
	}
	names, err := l.snapshotNames(root)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", api.Errorf(api.CodeNotFound, "there is no host snapshot")
	}
	return names[0], nil
}

// restore puts the files of a snapshot back and makes them take effect. With keep it first takes a snapshot of
// what it replaces, so a restore can be undone too; the undo of a failed apply does not.
func (l *Local) restore(ctx context.Context, name string, dryRun, keep bool) (api.HostChange, error) {
	return l.restoreSnapshot(ctx, name, dryRun, keep, true, true)
}

// restoreSnapshot puts a snapshot of any module back. effective makes the files take effect (ntpd, the host name,
// pfctl); without it only the files go back (at boot). force makes a firewall restore reload pf even when no file
// differs.
func (l *Local) restoreSnapshot(ctx context.Context, name string, dryRun, keep, effective, force bool) (api.HostChange, error) {
	root, err := l.hostDir()
	if err != nil {
		return api.HostChange{}, err
	}
	defer root.Close()
	if name, err = l.resolveSnapshot(root, name); err != nil {
		return api.HostChange{}, err
	}
	m, err := l.readManifest(root, name)
	if err != nil {
		return api.HostChange{}, err
	}
	if m.Module == api.HostModuleFirewall {
		return l.restoreFirewall(ctx, root, name, m, dryRun, keep, effective, force)
	}
	f, err := l.readIdentity(ctx)
	if err != nil {
		return api.HostChange{}, err
	}
	p := &hostPlan{}
	rcAfter := parseRC(f.files["rc.conf"].data)
	for _, sf := range m.Files {
		cur := f.files[sf.Name]
		switch sf.Name {
		case "rc.conf":
			if rcAfter, err = l.planRestoreRC(p, root, name, m, sf, cur); err != nil {
				return api.HostChange{}, err
			}
			continue
		case "ntp.conf":
			// only the jailops block goes back; every other line stays as it is now
			snapData, err := readSnapCopy(root, name, sf)
			if err != nil {
				return api.HostChange{}, err
			}
			data, err := spliceNTPBlock(cur.data, snapData)
			if err != nil {
				return api.HostChange{}, err
			}
			keep := cur.exists || data != ""
			if !sf.Exists && data == "" {
				keep = false
			}
			before := len(p.files)
			l.planFile(p, cur, data, keep, " (the jailops block)")
			if len(p.files) > before && !cur.exists {
				last := &p.files[len(p.files)-1]
				last.cur.mode, last.cur.uid, last.cur.gid = os.FileMode(sf.Mode).Perm(), sf.UID, sf.GID
			}
			continue
		}
		data, err := readSnapCopy(root, name, sf)
		if err != nil {
			return api.HostChange{}, err
		}
		before := len(p.files)
		l.planFile(p, cur, data, sf.Exists, "")
		if len(p.files) > before && sf.Exists {
			// the copy carries the mode and owner the file had
			p.files[len(p.files)-1].cur.mode, p.files[len(p.files)-1].cur.uid, p.files[len(p.files)-1].cur.gid = os.FileMode(sf.Mode).Perm(), sf.UID, sf.GID
			if !cur.exists {
				p.files[len(p.files)-1].cur.exists = true
			}
		}
	}
	if m.Hostname != "" && m.Hostname != f.hostname && api.ValidDNSName(m.Hostname) {
		p.hostname = m.Hostname
		p.actions = append(p.actions, fmt.Sprintf("hostname %s (was %s)", m.Hostname, f.hostname))
	}
	ntpTouched := len(p.rcBack) > 0
	for _, fc := range p.files {
		ntpTouched = ntpTouched || fc.cur.name == "ntp.conf"
	}
	if ntpTouched {
		was, now := strings.EqualFold(parseRC(f.files["rc.conf"].data)["ntpd_enable"], "YES"), strings.EqualFold(rcAfter["ntpd_enable"], "YES")
		switch {
		case now:
			p.ntpd = "restart"
		case was:
			p.ntpd = "onestop"
		}
		if p.ntpd != "" {
			p.actions = append(p.actions, "service ntpd "+p.ntpd)
		}
	}
	res := api.HostChange{DryRun: dryRun, Changed: p.changed(), Diff: p.diff.String(), Actions: p.actions}
	if res.Actions == nil {
		res.Actions = []string{}
	}
	if dryRun || !p.changed() {
		return res, nil
	}
	if keep {
		prev, err := l.readApplied()
		if err != nil {
			return res, err
		}
		var names []string
		for _, sf := range m.Files {
			names = append(names, sf.Name)
		}
		snap, err := l.takeSnapshot(f, names, "restore", prev)
		if err != nil {
			return res, err
		}
		res.Snapshot = snap
		res.Actions = append([]string{"keep a copy of " + strings.Join(l.etcPaths(names), ", ") + " in snapshot " + snap}, res.Actions...)
	}
	if err := l.execute(ctx, p); err != nil {
		return res, err
	}
	return res, l.writeApplied(m.Applied)
}

// readSnapCopy reads the copy of a file in a snapshot; "" for a file that did not exist.
func readSnapCopy(root *os.Root, name string, sf hostSnapFile) (string, error) {
	if !sf.Exists {
		return "", nil
	}
	b, err := root.ReadFile(snapFilePath(name, sf.Name))
	if err != nil {
		return "", mapFSErr(err)
	}
	return string(b), nil
}

// planRestoreRC plans putting the module's rc.conf variables back as the snapshot recorded them (set, or removed
// when they were not set), and nothing else of rc.conf. It returns the variables as they will be afterwards. A
// snapshot of an earlier version holds a copy of rc.conf: only the module's variables are read from it.
func (l *Local) planRestoreRC(p *hostPlan, root *os.Root, name string, m hostManifest, sf hostSnapFile, cur hostFile) (map[string]string, error) {
	owned := hostModuleRCVars[m.Module]
	want := m.RC
	if want == nil {
		data, err := readSnapCopy(root, name, sf)
		if err != nil {
			return nil, err
		}
		old := parseRC(data)
		want = map[string]*string{}
		for _, v := range owned {
			if val, ok := old[v]; ok {
				want[v] = &val
			} else {
				want[v] = nil
			}
		}
	}
	have := parseRC(cur.data)
	after := maps.Clone(have)
	var diff []string
	for _, v := range owned {
		w, recorded := want[v]
		if !recorded {
			continue
		}
		h, set := have[v]
		if (w == nil && !set) || (w != nil && set && *w == h) {
			continue
		}
		if w != nil && !reRCRestore.MatchString(*w) {
			return nil, invalid("the snapshot's value of rc.conf %s is not one the helper writes back; set it by hand", v)
		}
		p.rcBack = append(p.rcBack, rcValue{name: v, value: w})
		was := " (not set)"
		if set {
			diff = append(diff, fmt.Sprintf("-%s=%q", v, h))
			was = fmt.Sprintf(" (was %q)", h)
		}
		if w == nil {
			delete(after, v)
			p.actions = append(p.actions, fmt.Sprintf("sysrc -f %s -x %s%s", l.etcPath("rc.conf"), v, was))
			continue
		}
		after[v] = *w
		diff = append(diff, fmt.Sprintf("+%s=%q", v, *w))
		p.actions = append(p.actions, fmt.Sprintf("sysrc -f %s %s=%s%s", l.etcPath("rc.conf"), v, *w, was))
	}
	if len(diff) > 0 {
		fmt.Fprintf(&p.diff, "--- %s\n+++ %s (variables set with sysrc)\n%s\n", l.etcPath("rc.conf"), l.etcPath("rc.conf"), strings.Join(diff, "\n"))
	}
	return after, nil
}

// spliceNTPBlock puts the jailops block of snap (none, when snap has none) in place of the block of cur, or at its
// end; every other line of cur stays as it is.
func spliceNTPBlock(cur, snap string) (string, error) {
	sl := splitLines(snap)
	sb, se, err := ntpBlock(sl)
	if err != nil {
		return "", err
	}
	var block []string
	if sb >= 0 {
		block = sl[sb : se+1]
	}
	lines := splitLines(cur)
	b, e, err := ntpBlock(lines)
	if err != nil {
		return "", err
	}
	var out []string
	if b >= 0 {
		if slices.Equal(lines[b:e+1], block) {
			return cur, nil
		}
		out = append(append(append(out, lines[:b]...), block...), lines[e+1:]...)
	} else {
		if block == nil {
			return cur, nil
		}
		out = append(append(out, lines...), block...)
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, "\n") + "\n", nil
}

// ---- wire ----

func init() {
	register(OpHostIdentityRead, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		return h.HostIdentityRead(ctx)
	})
	register(OpHostIdentityApply, false, func(ctx context.Context, h Host, a hostApplyArgs, _ *callIO) (any, error) {
		return h.HostIdentityApply(ctx, a.Spec, a.DryRun)
	})
	register(OpHostSnapshotList, false, func(ctx context.Context, h Host, _ empty, _ *callIO) (any, error) {
		v, err := h.HostSnapshots(ctx)
		return hostSnapshotsRes{v}, err
	})
	register(OpHostSnapshotRestore, false, func(ctx context.Context, h Host, a hostRestoreArgs, _ *callIO) (any, error) {
		return h.HostSnapshotRestore(ctx, a.Name, a.DryRun)
	})
}

// HostIdentityRead implements Host.
func (c *Client) HostIdentityRead(ctx context.Context) (service.HostIdentityState, error) {
	return callJSON[service.HostIdentityState](ctx, c, OpHostIdentityRead, empty{}, callOpts{})
}

// HostIdentityApply implements Host.
func (c *Client) HostIdentityApply(ctx context.Context, spec api.HostIdentitySpec, dryRun bool) (api.HostChange, error) {
	return callJSON[api.HostChange](ctx, c, OpHostIdentityApply, hostApplyArgs{Spec: spec, DryRun: dryRun}, callOpts{})
}

// HostSnapshots implements Host.
func (c *Client) HostSnapshots(ctx context.Context) ([]api.HostSnapshot, error) {
	r, err := callJSON[hostSnapshotsRes](ctx, c, OpHostSnapshotList, empty{}, callOpts{})
	return r.V, err
}

// HostSnapshotRestore implements Host.
func (c *Client) HostSnapshotRestore(ctx context.Context, name string, dryRun bool) (api.HostChange, error) {
	return callJSON[api.HostChange](ctx, c, OpHostSnapshotRestore, hostRestoreArgs{Name: name, DryRun: dryRun}, callOpts{})
}
