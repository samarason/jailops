package apps

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// Drafting a definition from a running jail ('jailops app export',
// GET /api/v1/jails/<name>/app-draft). The daemon runs the commands below,
// as data like the installer's, and hands their output to BuildDraft, which
// is pure. Nothing reads the content of a configuration file: configuration
// and log files are listed by name only.

// PkgLeavesFormat is what PkgLeavesArgv asks pkg for, one line per package.
const PkgLeavesFormat = "%n %v %R %w"

// PkgLeavesQuery selects the packages installed on purpose, not as dependencies.
const PkgLeavesQuery = "%a = 0"

// PkgLeavesArgv is the host command that lists the packages of a running jail
// that were installed on purpose: name, version, repository, homepage.
func PkgLeavesArgv(jail string) []string {
	return PkgJailArgv(jail, "query", "-e", PkgLeavesQuery, PkgLeavesFormat)
}

// SockstatArgv is the in-jail command that lists the listening IPv4 and IPv6 sockets, without a header.
func SockstatArgv() []string { return []string{"/usr/bin/sockstat", "-4", "-6", "-l", "-q"} }

// PkgDBPath is pkg's database in a jail; files newer than it changed after the last package operation.
const PkgDBPath = "/var/db/pkg/local.sqlite"

// FindNewerArgv is the in-jail command that lists the regular files below dir changed after the last package operation.
func FindNewerArgv(dir string) []string {
	return []string{"/usr/bin/find", dir, "-type", "f", "-newer", PkgDBPath}
}

// StatOwnerArgv is the in-jail command that prints "user:group path" for each path.
func StatOwnerArgv(paths []string) []string {
	return append([]string{"/usr/bin/stat", "-f", "%Su:%Sg %N"}, paths...)
}

// ExportHeader is the comment a drafted file starts with: where it comes
// from and what the jail showed.
func ExportHeader(d api.AppDraft) []string {
	h := []string{"Drafted from the jail " + d.Jail + " with 'jailops app export'. What the jail showed:"}
	for _, f := range d.Findings {
		h = append(h, "- "+f)
	}
	return h
}

// DraftFacts is what the daemon read from a jail. A step that failed has
// its error in Errs, by step name, and its output empty.
type DraftFacts struct {
	Jail string
	// Packages is the output of PkgLeavesArgv.
	Packages []byte
	// RcConf is the jail's /etc/rc.conf.
	RcConf []byte
	// Sockets is the output of SockstatArgv.
	Sockets []byte
	// Volumes are the mount paths of the jail's volumes.
	Volumes []string
	// Configs and Logs are the outputs of FindNewerArgv for /usr/local/etc and /var/log.
	Configs, Logs []byte
	// Owners is the output of StatOwnerArgv for OwnerPaths.
	Owners  []byte
	SysVIPC bool
	// Scripts maps a service as rc.conf spells it (web_worker) to the name of
	// its rc.d script when that differs (web-worker).
	Scripts map[string]string
	// Resources are the jail's limits.
	Resources api.Resources
	Errs      map[string]string
}

// draftMax bounds what a draft lists of each kind.
const draftMax = 16

// baseServices are rc.d services of the base system: not the app's.
var baseServices = []string{"sshd", "sendmail", "sendmail_submit", "sendmail_outbound", "sendmail_msp_queue", "syslogd", "cron",
	"ntpd", "ntpdate", "rpcbind", "inetd", "devd", "moused", "powerd", "zfs", "dumpdev", "clear_tmp", "linux", "local_unbound",
	"dmesg", "virecover", "update_motd", "newsyslog", "blacklistd", "blocklistd", "pf", "pflog", "ipfw", "jail", "nfs_client",
	"nfs_server", "mountd", "rpc_lockd", "rpc_statd", "gateway", "ipv6_gateway", "dma", "tmpmfs", "varmfs", "mixer", "ftpd"}

// baseDaemons are programs of the base system whose sockets are not the app's.
var baseDaemons = []string{"sshd", "syslogd", "sendmail", "ntpd", "rpcbind", "inetd", "dma", "local-unbound", "unbound", "ftpd", "blacklistd", "blocklistd"}

// baseLogs are the log files of the base system.
var baseLogs = []string{"messages", "auth.log", "cron", "daemon.log", "debug.log", "maillog", "security", "utx.log", "utx.lastlogin",
	"lpd-errs", "xferlog", "ppp.log", "userlog", "devd.log", "all.log", "console.log", "sendmail.st", "mount.today", "mount.yesterday",
	"setuid.today", "setuid.yesterday", "dmesg.today", "dmesg.yesterday", "pf.today", "bsdinstall_log", "ntp.log", "wtmp", "lastlog"}

var (
	secretRE  = regexp.MustCompile(`(?i)(pass|secret|token|key|cred)`)
	rotatedRE = regexp.MustCompile(`\.([0-9]+|bz2|gz|xz|zst)$|\.[0-9]+\.`)
	ownerRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}:[A-Za-z_][A-Za-z0-9_.-]{0,31}$`)
	protoRE   = regexp.MustCompile(`^(tcp|udp)(4|6|46)?$`)
)

// RcSetting is one assignment of rc.conf.
type RcSetting struct{ Name, Value string }

// ParseRcConf reads the simple assignments of an rc.conf (name=value,
// name="value", name='value'), in order; the last one of a name wins.
// Anything else (shell code, a value with an expansion) is skipped.
func ParseRcConf(data []byte) []RcSetting {
	var out []RcSetting
	index := map[string]int{}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		name, rest, ok := strings.Cut(l, "=")
		if !ok || !rcKeyRE.MatchString(name) {
			continue
		}
		var val string
		switch {
		case strings.HasPrefix(rest, `"`):
			var b strings.Builder
			closed := false
			for i := 1; i < len(rest); i++ {
				c := rest[i]
				if c == '\\' && i+1 < len(rest) {
					i++
					b.WriteByte(rest[i])
					continue
				}
				if c == '"' {
					closed = true
					break
				}
				b.WriteByte(c)
			}
			// an expansion is the shell's to evaluate, and the installer writes values without one
			if !closed || strings.ContainsAny(b.String(), "$`") {
				continue
			}
			val = b.String()
		case strings.HasPrefix(rest, "'"):
			end := strings.IndexByte(rest[1:], '\'')
			if end < 0 {
				continue
			}
			val = rest[1 : 1+end]
		default:
			val, _, _ = strings.Cut(rest, " ")
			val, _, _ = strings.Cut(val, "\t")
			if strings.ContainsAny(val, "\"'$`#;") {
				continue
			}
		}
		if i, ok := index[name]; ok {
			out[i].Value = val
			continue
		}
		index[name] = len(out)
		out = append(out, RcSetting{Name: name, Value: val})
	}
	return out
}

// Listener is one listening socket, as sockstat reports it.
type Listener struct {
	Command  string
	Proto    string // tcp or udp
	Port     int
	Loopback bool
}

// ParseSockstat reads the lines of SockstatArgv: USER COMMAND PID FD PROTO
// LOCAL FOREIGN. A line it cannot read is skipped.
// UNVERIFIED on FreeBSD: the column layout of sockstat in 15.1.
func ParseSockstat(out []byte) []Listener {
	var ls []Listener
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 6 || !protoRE.MatchString(f[4]) {
			continue
		}
		local := f[5]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		host := strings.Trim(local[:i], "[]")
		if j := strings.IndexByte(host, '%'); j >= 0 {
			host = host[:j]
		}
		lo := host == "::1" || host == "localhost" || strings.HasPrefix(host, "127.")
		ls = append(ls, Listener{Command: f[1], Proto: f[4][:3], Port: port, Loopback: lo})
	}
	return ls
}

// OwnerPaths are the directories whose owners a draft reads: the data
// volumes, the directories of the logs (other than /var/log itself) and
// /var/run/<script> of each service, by its rc.d script name.
func OwnerPaths(volumes []string, logs, services []string) []string {
	var out []string
	add := func(p string) {
		if !slices.Contains(out, p) && len(out) < 3*draftMax {
			out = append(out, p)
		}
	}
	for _, v := range volumes {
		add(v)
	}
	for _, l := range logs {
		if d := path.Dir(l); d != "/var/log" && strings.HasPrefix(d, "/var/log/") {
			add(d)
		}
	}
	for _, s := range services {
		add("/var/run/" + s)
	}
	return out
}

// DraftServices returns the services a draft will name, from rc.conf:
// those enabled there that are not part of the base system, as rc.conf
// spells them ("-" and "." of an rc.d script name are "_" there).
func DraftServices(rc []RcSetting) []string {
	var out []string
	for _, s := range rc {
		n, ok := strings.CutSuffix(s.Name, "_enable")
		if !ok || !yes(s.Value) || slices.Contains(baseServices, n) || !rcNameRE.MatchString(n) || slices.Contains(out, n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) > draftMax {
		out = out[:draftMax]
	}
	return out
}

// DraftLogs returns the log files a draft will name, from the output of FindNewerArgv("/var/log").
func DraftLogs(out []byte) []string {
	var l []string
	for _, p := range lines(out) {
		if !strings.HasPrefix(p, "/var/log/") || slices.Contains(baseLogs, strings.TrimPrefix(p, "/var/log/")) ||
			rotatedRE.MatchString(path.Base(p)) || strings.HasPrefix(path.Base(p), ".") || appPath("logs", p, logParents) != nil {
			continue
		}
		l = append(l, p)
	}
	sort.Strings(l)
	if len(l) > draftMax {
		l = l[:draftMax]
	}
	return l
}

func yes(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// lines splits command output into clean, distinct absolute paths.
func lines(out []byte) []string {
	var l []string
	for _, s := range strings.Split(string(out), "\n") {
		s = strings.TrimSpace(s)
		if s == "" || !strings.HasPrefix(s, "/") || path.Clean(s) != s || slices.Contains(l, s) {
			continue
		}
		l = append(l, s)
	}
	return l
}

// slug turns a program or file name into a port or log name.
func slug(s string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	n := strings.Trim(b.String(), "-")
	if len(n) > 32 {
		n = strings.TrimRight(n[:32], "-")
	}
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		n = "p" + n
		if len(n) > 32 {
			n = n[:32]
		}
	}
	return n
}

// BuildDraft turns what was read from a jail into a draft definition: valid
// as it is, with TODO markers (in Todo and in some values) for what cannot
// be read from a jail.
func BuildDraft(f DraftFacts) api.AppDraft {
	d := api.AppDraft{Jail: f.Jail, Todo: map[string]string{}, Findings: []string{}}
	find := func(format string, args ...any) { d.Findings = append(d.Findings, fmt.Sprintf(format, args...)) }
	for _, step := range sortedKeys(f.Errs) {
		find("%s: could not be read: %s", step, oneLine(f.Errs[step]))
	}
	name := f.Jail
	if validate.Name("name", name) != nil {
		name = "app"
		d.Todo["name"] = "the app name; the jail's name is not one"
	}
	a := api.App{
		Version: 1, Name: name, Title: name,
		Summary:     TodoMarker + ": what it is and what it is for, in one line.",
		Description: TodoMarker + ": a few short paragraphs of plain text: what the software does, what this\ndefinition sets up and what is left to the operator.\n",
		Category:    api.AppOther,
		License:     TodoMarker,
		Image:       api.AppImage{OS: "freebsd", ReleaseMin: "15.1"},
		SysVIPC:     f.SysVIPC,
		Notes:       TodoMarker + ": what to do after the installation: the first-run steps, how to connect.\n",
	}
	d.Todo["category"] = "choose the category"

	// packages
	var pkgNames []string
	for _, l := range strings.Split(string(f.Packages), "\n") {
		p := strings.Split(strings.TrimSpace(l), " ")
		if len(p) < 2 || !pkgRE.MatchString(p[0]) || strings.HasPrefix(p[0], "FreeBSD-") || p[0] == "pkg" || slices.Contains(pkgNames, p[0]) {
			continue
		}
		pk := api.AppPackage{Name: p[0], Repo: "ports"}
		if versionRE.MatchString(p[1]) {
			pk.Version = p[1]
		}
		if len(p) > 2 && p[2] == JailopsRepo {
			pk.Repo = JailopsRepo
		}
		if len(p) > 3 && a.Homepage == "" {
			if u, err := url.Parse(p[3]); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(p[3]) <= 256 {
				a.Homepage = p[3]
			}
		}
		pkgNames = append(pkgNames, p[0])
		a.Packages = append(a.Packages, pk)
	}
	if len(a.Packages) > draftMax {
		find("packages: only the first %d of %d were kept", draftMax, len(a.Packages))
		a.Packages = a.Packages[:draftMax]
	}
	// ports first, jailops after: the order the installer uses
	sort.SliceStable(a.Packages, func(i, j int) bool { return a.Packages[i].Repo == "ports" && a.Packages[j].Repo != "ports" })
	if len(a.Packages) == 0 {
		a.Packages = []api.AppPackage{{Name: TodoMarker, Repo: "ports"}}
		d.Todo["packages"] = "no package installed on purpose was found; name the packages"
	} else {
		var l []string
		for _, p := range a.Packages {
			l = append(l, p.Name)
		}
		find("packages: %s (installed on purpose; their dependencies come with them)", strings.Join(l, ", "))
	}
	if a.Homepage == "" {
		d.Todo["homepage"] = "the software's https homepage"
	}

	// services and their knobs
	rc := ParseRcConf(f.RcConf)
	services := DraftServices(rc)
	t := true
	var left, secret []string
	for _, s := range services {
		n := s
		if sc := f.Scripts[s]; sc != "" && rcNameRE.MatchString(sc) && rcName(sc) == s {
			n = sc
		}
		a.Services = append(a.Services, api.AppService{Name: n, Start: &t})
	}
	for _, s := range rc {
		if n, ok := strings.CutSuffix(s.Name, "_enable"); ok && slices.Contains(services, n) {
			continue
		}
		owner := -1
		for i, svc := range services {
			if strings.HasPrefix(s.Name, rcName(svc)+"_") && (owner < 0 || len(svc) > len(services[owner])) {
				owner = i
			}
		}
		if owner < 0 {
			// an rc.d service switched on or off is not a setting of the app
			if n, ok := strings.CutSuffix(s.Name, "_enable"); !ok || !(yes(s.Value) || strings.EqualFold(s.Value, "no")) || n == "" {
				left = append(left, s.Name)
			}
			continue
		}
		v := s.Value
		if secretRE.MatchString(s.Name) {
			secret = append(secret, s.Name)
			v = TodoMarker
		}
		if len(v) > maxRCValue || strings.IndexFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			left = append(left, s.Name)
			continue
		}
		if a.Services[owner].RC == nil {
			a.Services[owner].RC = map[string]string{}
		}
		a.Services[owner].RC[s.Name] = v
	}
	if len(services) > 0 {
		find("services: %s (enabled in /etc/rc.conf)", strings.Join(services, ", "))
	} else {
		d.Todo["services"] = "no service of a package is enabled in /etc/rc.conf; name the rc.d scripts, or [] for none"
	}
	if len(secret) > 0 {
		find("rc.conf: the values of %s look like secrets and were left out", strings.Join(secret, ", "))
		d.Todo["services"] = "set the knobs whose value was left out, or remove them: a definition holds no secret"
	}
	if len(left) > 0 {
		find("rc.conf: not knobs of an enabled service, left out: %s", strings.Join(left, ", "))
	}

	// ports
	type portKey struct {
		port  int
		proto string
	}
	seen := map[portKey]int{}
	var skipped []string
	for _, l := range ParseSockstat(f.Sockets) {
		if slices.Contains(baseDaemons, l.Command) {
			s := fmt.Sprintf("%d/%s of %s", l.Port, l.Proto, l.Command)
			if !slices.Contains(skipped, s) {
				skipped = append(skipped, s)
			}
			continue
		}
		k := portKey{l.Port, l.Proto}
		if i, ok := seen[k]; ok {
			if !l.Loopback && strings.HasSuffix(a.Ports[i].Description, " on localhost only.") {
				a.Ports[i].Description = strings.TrimSuffix(a.Ports[i].Description, " on localhost only.") + "."
			}
			continue
		}
		desc := "Listened on by " + l.Command
		if l.Loopback {
			desc += " on localhost only."
		} else {
			desc += "."
		}
		if len(desc) > maxShort || strings.IndexFunc(desc, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			desc = ""
		}
		seen[k] = len(a.Ports)
		a.Ports = append(a.Ports, api.AppPort{Name: slug(l.Command), Port: l.Port, Proto: l.Proto, Description: desc})
	}
	sort.SliceStable(a.Ports, func(i, j int) bool {
		if a.Ports[i].Port != a.Ports[j].Port {
			return a.Ports[i].Port < a.Ports[j].Port
		}
		return a.Ports[i].Proto < a.Ports[j].Proto
	})
	if len(a.Ports) > draftMax {
		a.Ports = a.Ports[:draftMax]
	}
	names := map[string]bool{}
	for i := range a.Ports {
		p := &a.Ports[i]
		if names[p.Name] {
			p.Name = trimSlug(p.Name, strconv.Itoa(p.Port))
			if names[p.Name] {
				p.Name = trimSlug(p.Name, p.Proto)
			}
		}
		names[p.Name] = true
	}
	if len(a.Ports) > 0 {
		var l []string
		for _, p := range a.Ports {
			l = append(l, fmt.Sprintf("%d/%s", p.Port, p.Proto))
		}
		find("ports: %s (listening now)", strings.Join(l, ", "))
	} else {
		d.Todo["ports"] = "nothing of the app listens now; name the ports it listens on, or [] for none"
	}
	if len(skipped) > 0 {
		find("ports of the base system left out: %s", strings.Join(skipped, ", "))
	}

	// health: a tcp connection to the first port that is not on localhost
	for _, p := range a.Ports {
		if p.Proto == "tcp" && !strings.HasSuffix(p.Description, "on localhost only.") {
			a.Health = &api.AppHealth{TCP: p.Port, WaitSeconds: 60}
			break
		}
	}
	if a.Health != nil {
		d.Todo["health"] = "check that this test fits: a tcp connection says only that something listens; http or exec can say more"
	} else {
		d.Todo["health"] = "add a check that the app answers: tcp, http or exec"
	}

	// data: the jail's volumes
	for _, v := range f.Volumes {
		if len(a.Data) == draftMax {
			break
		}
		next := append(slices.Clone(a.Data), api.AppPath{Path: v})
		if err := validateData(next); err != nil {
			find("volume %s left out: %s", v, reason(err))
			continue
		}
		if err := CheckPersistent(api.App{Data: next}, PersistentPaths); err != nil {
			find("volume %s left out: %s", v, reason(err))
			continue
		}
		a.Data = next
	}
	if len(a.Data) > 0 {
		var l []string
		for _, p := range a.Data {
			l = append(l, p.Path)
		}
		find("data: %s (the jail's volumes)", strings.Join(l, ", "))
	}
	d.Todo["data"] = "every directory that holds state needs a data path: only the jail's volumes were found"

	// configuration files, by name
	for _, p := range lines(f.Configs) {
		b := path.Base(p)
		if !strings.HasPrefix(p, "/usr/local/etc/") || strings.HasPrefix(p, "/usr/local/etc/rc.d/") || strings.HasPrefix(p, "/usr/local/etc/pkg/") ||
			strings.HasSuffix(b, ".sample") || strings.HasPrefix(b, ".") || appPath("config", p, dataParents) != nil || len(a.Config) == draftMax {
			continue
		}
		c := api.AppConfig{Path: p}
		for i, s := range services {
			if strings.Contains(p, s) || strings.Contains(p, a.Services[i].Name) || len(services) == 1 {
				c.Restart = a.Services[i].Name
				break
			}
		}
		a.Config = append(a.Config, c)
	}
	sort.Slice(a.Config, func(i, j int) bool { return a.Config[i].Path < a.Config[j].Path })
	if len(a.Config) > 0 {
		find("config: %d file(s) below /usr/local/etc changed after the packages were installed (names only, never read)", len(a.Config))
	}
	d.Todo["config"] = "keep the files a person edits, with the service each one restarts"

	// log files, by name
	logNames := map[string]bool{}
	logs := DraftLogs(f.Logs)
	for _, p := range logs {
		n := slug(strings.TrimSuffix(path.Base(p), ".log"))
		for i := 2; logNames[n]; i++ {
			n = trimSlug(slug(strings.TrimSuffix(path.Base(p), ".log")), strconv.Itoa(i))
		}
		logNames[n] = true
		a.Logs = append(a.Logs, api.AppLog{Name: n, Path: p})
	}
	if len(a.Logs) > 0 {
		find("logs: %d file(s) below /var/log written after the packages were installed", len(a.Logs))
	} else {
		d.Todo["logs"] = "no log file of the app was found; name where it logs (many log to /var/log/messages), or [] for none"
	}

	// setup: the owners of the directories that are not root's
	byOwner := map[string][]string{}
	var mkdir []string
	isData := func(p string) bool {
		return slices.ContainsFunc(a.Data, func(x api.AppPath) bool { return x.Path == p })
	}
	var scripts []string
	for _, sv := range a.Services {
		scripts = append(scripts, sv.Name)
	}
	asked := OwnerPaths(f.Volumes, logs, scripts)
	for _, l := range strings.Split(string(f.Owners), "\n") {
		owner, p, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok || !slices.Contains(asked, p) || owner == "root:wheel" {
			continue
		}
		if !ownerRE.MatchString(owner) {
			find("%s is owned by %s, which is not a user and group name; left out of setup", p, oneLine(owner))
			continue
		}
		if !isData(p) && !slices.Contains(mkdir, p) {
			mkdir = append(mkdir, p)
		}
		byOwner[owner] = append(byOwner[owner], p)
	}
	if len(mkdir) > 0 {
		a.Setup = append(a.Setup, append([]string{"/bin/mkdir", "-p"}, mkdir...))
	}
	for _, o := range sortedKeys2(byOwner) {
		a.Setup = append(a.Setup, append([]string{"/usr/sbin/chown", o}, byOwner[o]...))
	}
	if len(a.Setup) > 0 {
		find("setup: the owners were read from the jail (pkg -r leaves the directories of a package's user to root)")
	}
	d.Todo["setup"] = "check the owners and add what else must happen once before the first start"

	// resources: the jail's limits, else modest hints
	a.Resources = api.AppResources{Memory: "256M", Disk: "2G", CPU: "1"}
	if f.Resources.Memory != "" {
		a.Resources.Memory = f.Resources.Memory
	}
	if f.Resources.Disk != "" {
		a.Resources.Disk = f.Resources.Disk
	}
	if f.Resources.CPU > 0 {
		a.Resources.CPU = strconv.Itoa(f.Resources.CPU)
	}

	if err := Validate(&a); err != nil {
		find("the draft does not validate yet: %s", reason(err))
	}
	d.Definition = a
	return d
}

func sortedKeys2(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// oneLine shortens a message to one printable line.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, s)), " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
