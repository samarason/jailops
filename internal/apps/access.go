package apps

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Who may connect to an installed app (docs/apps.md, "Who may connect"), as
// pure functions: the source grammar, the firewall rule names, the managed
// block of pg_hba.conf, the SQL and the password. The service runs what these
// build; the tests of the privileged helper check the same argument vectors.

// validateAccess checks the optional access block against the rest of the
// definition: a port, a service and a configuration file of its own.
func validateAccess(app *api.App) error {
	a := app.Access
	if a == nil {
		return nil
	}
	if a.Type != api.AppAccessTypePostgreSQL {
		return invalid("access.type", "%q is not a type this daemon knows (postgresql)", a.Type)
	}
	if !slices.ContainsFunc(app.Ports, func(p api.AppPort) bool { return p.Name == a.Port && p.Proto == "tcp" }) {
		return invalid("access.port", "%q is not the name of a tcp port of ports", a.Port)
	}
	if !slices.ContainsFunc(app.Services, func(s api.AppService) bool { return s.Name == a.Service }) {
		return invalid("access.service", "%q is not one of the services", a.Service)
	}
	if !slices.ContainsFunc(app.Config, func(c api.AppConfig) bool { return c.Path == a.HBAFile }) {
		return invalid("access.hba_file", "%q is not one of the config paths", a.HBAFile)
	}
	return nil
}

// Source is a parsed source of an allow.
type Source struct {
	// Kind is api.AccessSourceJail, AccessSourceSet, AccessSourceCIDR or AccessSourceHost; Name is the jail or the
	// address set.
	Kind   string
	Name   string
	Prefix netip.Prefix
}

var ()

// ParseSource reads the source of an allow or a deny: jail:NAME (a jail of the project), set:NAME (an address set of
// the project), an address or a prefix, or host.
func ParseSource(s string) (Source, error) {
	switch {
	case s == "host":
		return Source{Kind: api.AccessSourceHost}, nil
	case strings.HasPrefix(s, "@"):
		n := s[1:]
		return Source{}, fmt.Errorf("source %q: @ is not used: write jail:%s or set:%s", s, n, n)
	case strings.HasPrefix(s, "jail:"):
		if !api.IsName(s[5:], 29) {
			return Source{}, fmt.Errorf("source %q: jail: is followed by the name of a jail of the project", s)
		}
		return Source{Kind: api.AccessSourceJail, Name: s[5:]}, nil
	case strings.HasPrefix(s, "set:"):
		if !api.IsName(s[4:], 29) {
			return Source{}, fmt.Errorf("source %q: set: is followed by the name of an address set of the project", s)
		}
		return Source{Kind: api.AccessSourceSet, Name: s[4:]}, nil
	case s == "" || s == "any" || strings.HasPrefix(s, "tag:"):
		return Source{}, fmt.Errorf("source %q: name a jail (jail:web), an address set (set:office), an address or a prefix, or host", s)
	}
	var pf netip.Prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Source{}, fmt.Errorf("source %q is not an address or a prefix", s)
		}
		pf = p.Masked()
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Source{}, fmt.Errorf("source %q is not an address, a prefix, jail:NAME, set:NAME or host", s)
		}
		if a.Zone() != "" {
			return Source{}, fmt.Errorf("source %q: zones are not allowed", s)
		}
		pf = netip.PrefixFrom(a, a.BitLen())
	}
	if pf.Addr().Zone() != "" || pf.Addr().Is4In6() {
		return Source{}, fmt.Errorf("source %q: zones and IPv4-mapped addresses are not allowed", s)
	}
	return Source{Kind: api.AccessSourceCIDR, Prefix: pf}, nil
}

// Canonical is the form a grant is stored and found under.
func (s Source) Canonical() string {
	switch s.Kind {
	case api.AccessSourceHost:
		return "host"
	case api.AccessSourceCIDR:
		if s.Prefix.Bits() == s.Prefix.Addr().BitLen() {
			return s.Prefix.Addr().String()
		}
		return s.Prefix.String()
	}
	if s.Kind == api.AccessSourceSet {
		return "set:" + s.Name
	}
	return "jail:" + s.Name
}

// HostPrefix is the prefix of one address: /32 or /128.
func HostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

// PortSpec is a port and a protocol.
type PortSpec struct {
	Port  int
	Proto string
}

func (p PortSpec) String() string { return strconv.Itoa(p.Port) + "/" + p.Proto }

// ParsePorts reads "N" or "N/proto" values, sorted and without repeats.
func ParsePorts(in []string) ([]PortSpec, error) {
	seen := map[PortSpec]bool{}
	var out []PortSpec
	for _, s := range in {
		p, err := ParsePort(s)
		if err != nil {
			return nil, err
		}
		ps := PortSpec{p.Port, p.Proto}
		if !seen[ps] {
			seen[ps] = true
			out = append(out, ps)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

// DefaultPorts are the ports a grant opens when none are named: the access
// block's port for an app that has one, every port of the definition otherwise.
func DefaultPorts(app api.App) []string {
	var out []string
	for _, p := range app.Ports {
		if app.Access != nil && p.Name != app.Access.Port {
			continue
		}
		out = append(out, strconv.Itoa(p.Port)+"/"+p.Proto)
	}
	return out
}

// AccessPolicyName is the managed firewall policy of a jail.
func AccessPolicyName(jail string) string { return "app-" + jail }

// AccessRuleName is the name of the firewall rule of a grant for one protocol.
// Rule names allow letters, digits, space, dot, underscore and dash, at most 64.
func AccessRuleName(canonical, proto string) string {
	r := strings.NewReplacer("/", ".", ":", " ")
	name := "access " + r.Replace(canonical)
	if canonical == "host" {
		name = "access host"
	}
	if proto != "tcp" {
		name += " " + proto
	}
	if len(name) > 64 {
		h := sha256.Sum256([]byte(canonical + " " + proto))
		name = name[:64-9] + " " + hex.EncodeToString(h[:4])
	}
	return name
}

// RuleText is a typed rule the way a person reads it.
func RuleText(r api.FirewallRule) string {
	var b strings.Builder
	b.WriteString(r.Action + " " + r.Direction)
	if r.Proto != "" {
		b.WriteString(" " + r.Proto)
	}
	if len(r.From) > 0 {
		b.WriteString(" from " + strings.Join(r.From, ","))
	}
	if len(r.To) > 0 {
		b.WriteString(" to " + strings.Join(r.To, ","))
	}
	if len(r.Ports) > 0 {
		if len(r.To) == 0 {
			b.WriteString(" to")
		}
		b.WriteString(" port " + strings.Join(r.Ports, ","))
	}
	return b.String()
}

// ---- the database ----

var dbNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// CheckDatabaseName refuses anything but ^[a-z][a-z0-9_]{0,62}$ and the names
// PostgreSQL reserves: no quoting is ever needed, nothing can be injected.
func CheckDatabaseName(n string) error {
	if !dbNameRE.MatchString(n) {
		return fmt.Errorf("database name %q must match ^[a-z][a-z0-9_]{0,62}$", n)
	}
	if n == "postgres" || n == "public" || n == "template0" || n == "template1" || strings.HasPrefix(n, "pg_") {
		return fmt.Errorf("database name %q is reserved by PostgreSQL", n)
	}
	return nil
}

// DefaultDatabase is the database of a jail source: its name with "-" turned into "_".
func DefaultDatabase(jail string) string { return strings.ReplaceAll(jail, "-", "_") }

// quoteIdent quotes an SQL identifier. The names that reach it are checked by
// CheckDatabaseName already; the quoting is the second line.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// quoteLiteral quotes an SQL string literal (standard_conforming_strings, the default).
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// PsqlPath is the client the access statements run with, as postgres in the jail.
const PsqlPath = "/usr/local/bin/psql"

// PsqlUser is the jail user psql runs as.
const PsqlUser = "postgres"

// PsqlArgv runs the statements read from standard input against one database:
// no ~/.psqlrc, quiet, unaligned output without headers, stop at the first error.
func PsqlArgv(db string) []string {
	return []string{PsqlPath, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", db}
}

// ProbeSQL asks whether a role and a database exist and what the server
// listens on; ParseProbe reads the answer.
func ProbeSQL(role, db string) string {
	return "SELECT 'role=' || count(*) FROM pg_roles WHERE rolname = " + quoteLiteral(role) + ";\n" +
		"SELECT 'database=' || count(*) FROM pg_database WHERE datname = " + quoteLiteral(db) + ";\n" +
		"SELECT 'listen=' || current_setting('listen_addresses');\n"
}

// Probe is the answer of ProbeSQL.
type Probe struct {
	Role, Database bool
	Listen         string
}

// ParseProbe reads the output of ProbeSQL.
func ParseProbe(out []byte) (Probe, error) {
	var p Probe
	seen := 0
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		switch k {
		case "role":
			p.Role, seen = v != "0", seen|1
		case "database":
			p.Database, seen = v != "0", seen|2
		case "listen":
			p.Listen, seen = v, seen|4
		}
	}
	if seen != 7 {
		return p, fmt.Errorf("psql answered %q, not the three lines asked for", strings.TrimSpace(string(out)))
	}
	return p, nil
}

// Statement is one SQL statement with its text for people: the password is
// left out of Shown.
type Statement struct {
	SQL, Shown string
}

const redacted = "'<generated, shown once>'"

// CreateRole makes a login role with a SCRAM verifier (the server never sees the password).
func CreateRole(role, verifier string) Statement {
	pre := "CREATE ROLE " + quoteIdent(role) + " LOGIN PASSWORD "
	return Statement{pre + quoteLiteral(verifier) + ";", pre + redacted + ";"}
}

// SetPassword gives an existing role JailOps made its login and a new password.
func SetPassword(role, verifier string) Statement {
	pre := "ALTER ROLE " + quoteIdent(role) + " LOGIN PASSWORD "
	return Statement{pre + quoteLiteral(verifier) + ";", pre + redacted + ";"}
}

// CreateDatabase makes the database, owned by the role.
func CreateDatabase(db, role string) Statement {
	s := "CREATE DATABASE " + quoteIdent(db) + " OWNER " + quoteIdent(role) + ";"
	return Statement{s, s}
}

// OwnDatabase gives a database JailOps made back to the role.
func OwnDatabase(db, role string) Statement {
	s := "ALTER DATABASE " + quoteIdent(db) + " OWNER TO " + quoteIdent(role) + ";"
	return Statement{s, s}
}

// SetListen sets listen_addresses; it takes effect at the next restart.
func SetListen(value string) Statement {
	s := "ALTER SYSTEM SET listen_addresses TO " + quoteLiteral(value) + ";"
	return Statement{s, s}
}

// Reload makes the server read pg_hba.conf again.
func Reload() Statement {
	s := "SELECT pg_reload_conf();"
	return Statement{s, s}
}

// DisableRole takes a role's login and password away and ends its sessions.
func DisableRole(role string) []Statement {
	a := "ALTER ROLE " + quoteIdent(role) + " NOLOGIN PASSWORD NULL;"
	b := "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = " + quoteLiteral(role) + ";"
	return []Statement{{a, a}, {b, b}}
}

// ReassignOwned gives what a role owns in the current database (and the
// databases it owns) to postgres, then drops its privileges there.
func ReassignOwned(role string) []Statement {
	a := "REASSIGN OWNED BY " + quoteIdent(role) + " TO postgres;"
	b := "DROP OWNED BY " + quoteIdent(role) + ";"
	return []Statement{{a, a}, {b, b}}
}

// DropRole drops a role that owns nothing any more.
func DropRole(role string) Statement {
	s := "DROP ROLE IF EXISTS " + quoteIdent(role) + ";"
	return Statement{s, s}
}

// Script joins statements into what psql reads on standard input.
func Script(st []Statement) string {
	var b strings.Builder
	for _, s := range st {
		b.WriteString(s.SQL)
		b.WriteString("\n")
	}
	return b.String()
}

// Shown is the text of statements for people.
func Shown(st []Statement) []string {
	out := make([]string, 0, len(st))
	for _, s := range st {
		out = append(out, s.Shown)
	}
	return out
}

// ListenValue is listen_addresses with the jail's addresses added, and
// whether it changed. "*" already covers everything.
func ListenValue(current string, addrs []netip.Addr) (string, bool) {
	var have []string
	for _, f := range strings.Split(current, ",") {
		if f = strings.TrimSpace(f); f != "" {
			have = append(have, f)
		}
	}
	if slices.Contains(have, "*") {
		return current, false
	}
	if len(have) == 0 {
		have = []string{"localhost"}
	}
	changed := false
	for _, a := range addrs {
		if !slices.Contains(have, a.String()) {
			have, changed = append(have, a.String()), true
		}
	}
	return strings.Join(have, ","), changed
}

// ---- pg_hba.conf ----

// The markers of the managed block of pg_hba.conf.
const (
	HBABegin = "# jailops access begin: written by jailops app allow and deny; edits inside are replaced"
	HBAEnd   = "# jailops access end"
)

// HBALines are the lines of one grant: one per source prefix, scram-sha-256.
func HBALines(db, role string, prefixes []netip.Prefix) []string {
	var out []string
	for _, p := range prefixes {
		out = append(out, "host "+db+" "+role+" "+p.Masked().String()+" scram-sha-256")
	}
	return out
}

// errHBAMarkers is a block whose markers are not one begin before one end.
var errHBAMarkers = errors.New("the jailops access markers are not one begin line followed by one end line; fix the file by hand")

// HBABlock returns the lines between the markers and whether the block exists.
func HBABlock(content string) ([]string, bool, error) {
	lines := strings.Split(content, "\n")
	b, e := -1, -1
	for i, l := range lines {
		switch strings.TrimSpace(l) {
		case HBABegin:
			if b >= 0 {
				return nil, false, errHBAMarkers
			}
			b = i
		case HBAEnd:
			if e >= 0 {
				return nil, false, errHBAMarkers
			}
			e = i
		}
	}
	if b < 0 && e < 0 {
		return nil, false, nil
	}
	if b < 0 || e < b {
		return nil, false, errHBAMarkers
	}
	var out []string
	for _, l := range lines[b+1 : e] {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out, true, nil
}

// SetHBABlock replaces the managed block of pg_hba.conf with lines (sorted,
// without repeats), or appends one at the end when there is none. Every
// other line stays as it is. With no lines the block is removed.
func SetHBABlock(content string, lines []string) (string, error) {
	if _, _, err := HBABlock(content); err != nil {
		return "", err
	}
	want := slices.Clone(lines)
	sort.Strings(want)
	want = slices.Compact(want)
	for _, l := range want {
		if strings.ContainsAny(l, "\n\r") {
			return "", fmt.Errorf("a pg_hba line holds a line break")
		}
	}
	var block []string
	if len(want) > 0 {
		block = append(append([]string{HBABegin}, want...), HBAEnd)
	}
	src := strings.Split(content, "\n")
	var out []string
	inside, placed := false, false
	for _, l := range src {
		switch strings.TrimSpace(l) {
		case HBABegin:
			inside = true
			continue
		case HBAEnd:
			inside = false
			out = append(out, block...)
			placed = true
			continue
		}
		if !inside {
			out = append(out, l)
		}
	}
	res := strings.Join(out, "\n")
	if !placed && len(block) > 0 {
		res = strings.TrimRight(res, "\n")
		if res != "" {
			res += "\n\n"
		}
		res += strings.Join(block, "\n") + "\n"
	}
	return res, nil
}

// ---- secrets ----

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// PasswordLength is the length of a generated password.
const PasswordLength = 32

// NewPassword reads 32 characters of [A-Za-z0-9] from r, without bias
// (bytes from 248 up are thrown away): about 190 bits.
func NewPassword(r io.Reader) (string, error) {
	out := make([]byte, 0, PasswordLength)
	buf := make([]byte, 64)
	for len(out) < PasswordLength {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("reading random bytes: %w", err)
		}
		for _, b := range buf {
			if b >= 248 { // 248 = 4 * 62
				continue
			}
			out = append(out, passwordAlphabet[int(b)%len(passwordAlphabet)])
			if len(out) == PasswordLength {
				break
			}
		}
	}
	return string(out), nil
}

// ScramIterations is the iteration count of a verifier (PostgreSQL's default).
const ScramIterations = 4096

// ScramVerifier is the SCRAM-SHA-256 verifier PostgreSQL stores for a
// password (RFC 5802, RFC 7677): the server gets this, never the password.
// A password of [A-Za-z0-9] is unchanged by SASLprep.
func ScramVerifier(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	clientKey := mac(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	server := mac(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iterations, b64(salt), b64(stored[:]), b64(server)), nil
}

// ConnectionString is the URL a client connects with.
func ConnectionString(role, password string, host netip.Addr, port int, db string) string {
	return "postgres://" + role + ":" + password + "@" + net.JoinHostPort(host.String(), strconv.Itoa(port)) + "/" + db + "?sslmode=disable"
}

// ---- services ----

// ServiceRestartScript is ServiceStartScript for a restart: the rc script's
// output goes to a file in the jail, so a daemon it starts does not hold the
// pipes of the in-jail exec.
const ServiceRestartScript = `out=$(/usr/bin/mktemp -t jailops) || exit 1; /usr/sbin/service "$1" restart </dev/null >"$out" 2>&1; rc=$?; [ $rc -eq 0 ] || /bin/cat "$out"; /bin/rm -f "$out"; exit $rc`

// ServiceRestartName is $0 of ServiceRestartScript.
const ServiceRestartName = "jailops-restart"

// ServiceRestartArgv is the in-jail command that restarts an rc.d service with
// its output detached from the caller.
func ServiceRestartArgv(service string) ([]string, error) {
	if !serviceNameRE.MatchString(service) {
		return nil, fmt.Errorf("%q is not an rc.d service name", service)
	}
	return []string{"/bin/sh", "-c", ServiceRestartScript, ServiceRestartName, service}, nil
}

// HBAOwnerArgv and HBAModeArgv give pg_hba.conf back to postgres after the
// helper wrote it (the helper writes files as root).
func HBAOwnerArgv(path string) []string {
	return []string{"/usr/sbin/chown", "postgres:postgres", path}
}

// HBAModeArgv sets the mode initdb gives the file.
func HBAModeArgv(path string) []string { return []string{"/bin/chmod", "0600", path} }
