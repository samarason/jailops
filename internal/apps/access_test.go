package apps

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestParseSource(t *testing.T) {
	for _, c := range []struct {
		in, kind, name, prefix, canonical string
	}{
		{"host", api.AccessSourceHost, "", "", "host"},
		{"jail:web", api.AccessSourceJail, "web", "", "jail:web"},
		{"jail:web-1", api.AccessSourceJail, "web-1", "", "jail:web-1"},
		{"set:office-net", api.AccessSourceSet, "office-net", "", "set:office-net"},
		{"192.0.2.7", api.AccessSourceCIDR, "", "192.0.2.7/32", "192.0.2.7"},
		{"192.0.2.9/24", api.AccessSourceCIDR, "", "192.0.2.0/24", "192.0.2.0/24"},
		{"2001:db8::1", api.AccessSourceCIDR, "", "2001:db8::1/128", "2001:db8::1"},
		{"2001:db8::/48", api.AccessSourceCIDR, "", "2001:db8::/48", "2001:db8::/48"},
		{"0.0.0.0/0", api.AccessSourceCIDR, "", "0.0.0.0/0", "0.0.0.0/0"},
	} {
		s, err := ParseSource(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if s.Kind != c.kind || s.Name != c.name {
			t.Errorf("%q: %+v", c.in, s)
		}
		if c.prefix != "" && s.Prefix.String() != c.prefix {
			t.Errorf("%q: prefix %s", c.in, s.Prefix)
		}
		if got := s.Canonical(); got != c.canonical {
			t.Errorf("%q: canonical %q, want %q", c.in, got, c.canonical)
		}
	}
	for _, bad := range []string{"", "any", "@", "@web", "@Web", "jail:", "jail:Web", "jail:web;id", "jail:a/b", "jail:shop/web", "jail:web-", "set:web_1", "set:web-",
		"set:" + strings.Repeat("a", 30), "jail:" + strings.Repeat("a", 30), "tag:web", "web", "192.0.2.300", "192.0.2.0/33",
		"fe80::1%em0", "::ffff:192.0.2.1", "host ", "$(id)", "jail:web\n"} {
		if s, err := ParseSource(bad); err == nil {
			t.Errorf("%q accepted: %+v", bad, s)
		}
	}
}

func TestParsePortsAndDefaults(t *testing.T) {
	got, err := ParsePorts([]string{"5432", "53/udp", "5432/tcp", "80"})
	if err != nil {
		t.Fatal(err)
	}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if strings.Join(s, " ") != "80/tcp 5432/tcp 53/udp" {
		t.Fatalf("%v", s)
	}
	for _, bad := range []string{"0", "65536", "x", "80/sctp", "-1"} {
		if _, err := ParsePorts([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	pg := api.App{Ports: []api.AppPort{{Name: "postgres", Port: 5432, Proto: "tcp"}, {Name: "metrics", Port: 9187, Proto: "tcp"}},
		Access: &api.AppAccessDef{Type: "postgresql", Port: "postgres"}}
	if d := DefaultPorts(pg); !slices.Equal(d, []string{"5432/tcp"}) {
		t.Fatalf("%v", d)
	}
	pg.Access = nil
	if d := DefaultPorts(pg); !slices.Equal(d, []string{"5432/tcp", "9187/tcp"}) {
		t.Fatalf("%v", d)
	}
}

var ruleNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// Rule names are valid firewall rule names for every source form, unique per
// source and protocol, and stable.
func TestAccessRuleNames(t *testing.T) {
	seen := map[string]string{}
	for _, src := range []string{"jail:web", "set:web", "set:office", "192.0.2.7", "192.0.2.0/24", "2001:db8::/48", "host",
		"jail:" + strings.Repeat("a", 29), "jail:" + strings.Repeat("a", 28) + "b", "set:" + strings.Repeat("j", 23) + "x"} {
		for _, proto := range []string{"tcp", "udp"} {
			n := AccessRuleName(src, proto)
			if !ruleNameRE.MatchString(n) {
				t.Errorf("%s %s: %q is not a rule name", src, proto, n)
			}
			if o, ok := seen[n]; ok {
				t.Errorf("%q names both %s and %s %s", n, o, src, proto)
			}
			seen[n] = src + " " + proto
		}
	}
	if AccessRuleName("jail:web", "tcp") != "access jail web" || AccessRuleName("jail:web", "udp") != "access jail web udp" {
		t.Fatal(AccessRuleName("jail:web", "tcp"), AccessRuleName("jail:web", "udp"))
	}
	r := api.FirewallRule{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"192.0.2.7", "2001:db8::7"}, Ports: []string{"5432"}}
	if got := RuleText(r); got != "allow in tcp from 192.0.2.7,2001:db8::7 to port 5432" {
		t.Fatal(got)
	}
}

// Database names are the whole defence of the SQL: nothing outside
// ^[a-z][a-z0-9_]{0,62}$ and nothing PostgreSQL reserves gets through.
func TestDatabaseNames(t *testing.T) {
	for _, ok := range []string{"web", "shop_api", "a", "x" + strings.Repeat("1", 62)} {
		if err := CheckDatabaseName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Web", "1web", "_web", "web-api", `web"; DROP ROLE postgres; --`, "web'", "we b", "x" + strings.Repeat("1", 63),
		"postgres", "public", "template0", "template1", "pg_monitor", "pg_", "wéb", "web\n"} {
		if err := CheckDatabaseName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if DefaultDatabase("web-api-1") != "web_api_1" {
		t.Fatal(DefaultDatabase("web-api-1"))
	}
}

func TestSQL(t *testing.T) {
	v := "SCRAM-SHA-256$4096:c2FsdA==$a:b"
	st := []Statement{CreateRole("shop", v), CreateDatabase("shop", "shop"), SetListen("localhost,192.0.2.10")}
	want := `CREATE ROLE "shop" LOGIN PASSWORD 'SCRAM-SHA-256$4096:c2FsdA==$a:b';
CREATE DATABASE "shop" OWNER "shop";
ALTER SYSTEM SET listen_addresses TO 'localhost,192.0.2.10';
`
	if got := Script(st); got != want {
		t.Fatalf("%s", got)
	}
	shown := Shown(st)
	if strings.Contains(strings.Join(shown, "\n"), "SCRAM") || shown[0] != `CREATE ROLE "shop" LOGIN PASSWORD '<generated, shown once>';` {
		t.Fatalf("%v", shown)
	}
	if s := SetPassword("shop", v); strings.Contains(s.Shown, "SCRAM") || !strings.HasPrefix(s.SQL, `ALTER ROLE "shop" LOGIN PASSWORD 'SCRAM`) {
		t.Fatalf("%+v", s)
	}
	// quoting is the second line of defence: a name that slipped past the check stays one identifier or one literal
	if q := quoteIdent(`a"b`); q != `"a""b"` {
		t.Fatal(q)
	}
	if q := quoteLiteral(`a'b`); q != `'a''b'` {
		t.Fatal(q)
	}
	if got := Script(DisableRole("shop")); got != "ALTER ROLE \"shop\" NOLOGIN PASSWORD NULL;\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'shop';\n" {
		t.Fatal(got)
	}
	if got := Script(append(ReassignOwned("shop"), DropRole("shop"))); got != "REASSIGN OWNED BY \"shop\" TO postgres;\nDROP OWNED BY \"shop\";\nDROP ROLE IF EXISTS \"shop\";\n" {
		t.Fatal(got)
	}
	if !strings.Contains(ProbeSQL("shop", "shop"), "rolname = 'shop'") {
		t.Fatal(ProbeSQL("shop", "shop"))
	}
	p, err := ParseProbe([]byte("role=1\ndatabase=0\nlisten=localhost\n"))
	if err != nil || !p.Role || p.Database || p.Listen != "localhost" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParseProbe([]byte("role=1\n")); err == nil {
		t.Fatal("a short answer was accepted")
	}
	argv := PsqlArgv("shop")
	if argv[0] != "/usr/local/bin/psql" || argv[len(argv)-1] != "shop" || !slices.Contains(argv, "ON_ERROR_STOP=1") {
		t.Fatal(argv)
	}
}

func TestListenValue(t *testing.T) {
	a := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	for _, c := range []struct {
		cur, want string
		changed   bool
	}{
		{"localhost", "localhost,192.0.2.10,2001:db8::10", true},
		{"", "localhost,192.0.2.10,2001:db8::10", true},
		{"*", "*", false},
		{"localhost,192.0.2.10,2001:db8::10", "localhost,192.0.2.10,2001:db8::10", false},
		{"localhost, 192.0.2.10", "localhost,192.0.2.10,2001:db8::10", true},
	} {
		got, ch := ListenValue(c.cur, a)
		if got != c.want || ch != c.changed {
			t.Errorf("%q: %q %v", c.cur, got, ch)
		}
	}
}

const stockHBA = `# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
`

// The managed block is appended once, replaced in place afterwards, and every
// other line stays as it was, byte for byte.
func TestHBABlock(t *testing.T) {
	l1 := HBALines("shop", "shop", []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("2001:db8::7/128")})
	if !slices.Equal(l1, []string{"host shop shop 192.0.2.7/32 scram-sha-256", "host shop shop 2001:db8::7/128 scram-sha-256"}) {
		t.Fatal(l1)
	}
	one, err := SetHBABlock(stockHBA, l1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(one, stockHBA) || !strings.Contains(one, HBABegin+"\nhost shop shop 192.0.2.7/32") || !strings.HasSuffix(one, HBAEnd+"\n") {
		t.Fatalf("%s", one)
	}
	again, _ := SetHBABlock(one, l1)
	if again != one {
		t.Fatalf("not idempotent:\n%s", again)
	}
	// a person's line after the block stays where it is
	edited := one + "host    all             all             198.51.100.0/24         reject\n"
	l2 := append(slices.Clone(l1), "host api api 192.0.2.8/32 scram-sha-256")
	two, err := SetHBABlock(edited, l2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(two, HBAEnd+"\nhost    all             all             198.51.100.0/24         reject\n") || !strings.HasPrefix(two, stockHBA) {
		t.Fatalf("%s", two)
	}
	lines, ok, err := HBABlock(two)
	if err != nil || !ok || len(lines) != 3 || lines[0] != "host api api 192.0.2.8/32 scram-sha-256" {
		t.Fatalf("%v %v %v", lines, ok, err)
	}
	// removing every line removes the block; the rest is as before
	none, _ := SetHBABlock(two, nil)
	if strings.Contains(none, "jailops") || !strings.Contains(none, "198.51.100.0/24") || !strings.HasPrefix(none, stockHBA) {
		t.Fatalf("%s", none)
	}
	if _, ok, _ := HBABlock(stockHBA); ok {
		t.Fatal("a stock file has a block")
	}
	// broken markers are refused, never guessed
	for _, bad := range []string{stockHBA + HBABegin + "\n", stockHBA + HBAEnd + "\n", HBAEnd + "\n" + HBABegin + "\n", HBABegin + "\n" + HBABegin + "\n" + HBAEnd + "\n"} {
		if _, err := SetHBABlock(bad, l1); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
	if _, err := SetHBABlock(stockHBA, []string{"host a a 192.0.2.1/32 trust\nlocal all all trust"}); err == nil {
		t.Fatal("a line break got into the file")
	}
}

func TestNewPassword(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
	seen := map[string]bool{}
	for range 50 {
		p, err := NewPassword(rand.Reader)
		if err != nil || !re.MatchString(p) || seen[p] {
			t.Fatalf("%q %v", p, err)
		}
		seen[p] = true
	}
	// bytes from 248 up are thrown away: all of them gives nothing, so it fails rather than biasing
	if _, err := NewPassword(bytes.NewReader(bytes.Repeat([]byte{255}, 4096))); err == nil {
		t.Fatal("a password from rejected bytes")
	}
	// deterministic for a given stream: 0..61 map to the alphabet in order
	in := make([]byte, 64)
	for i := range in {
		in[i] = byte(i % 62)
	}
	p, _ := NewPassword(bytes.NewReader(in))
	if p != passwordAlphabet[:32] {
		t.Fatal(p)
	}
}

// The verifier is the one PostgreSQL computes (RFC 7677 test vector shape):
// checked by recomputing the client proof check the server does.
func TestScramVerifier(t *testing.T) {
	salt := []byte("0123456789abcdef")
	v, err := ScramVerifier("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^SCRAM-SHA-256\$4096:([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$`)
	m := re.FindStringSubmatch(v)
	if m == nil {
		t.Fatal(v)
	}
	if s, _ := base64.StdEncoding.DecodeString(m[1]); string(s) != string(salt) {
		t.Fatal("salt")
	}
	// RFC 7677 section 3: password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ== , 4096 iterations
	rs, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	v2, _ := ScramVerifier("pencil", rs, 4096)
	m2 := re.FindStringSubmatch(v2)
	// the server signature of the RFC's exchange is HMAC(ServerKey, AuthMessage)
	server, _ := base64.StdEncoding.DecodeString(m2[3])
	auth := "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	h := hmac.New(sha256.New, server)
	h.Write([]byte(auth))
	if got := base64.StdEncoding.EncodeToString(h.Sum(nil)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("server signature %s does not match RFC 7677", got)
	}
	// and the client's proof of the RFC checks against the stored key, as the server checks it
	stored, _ := base64.StdEncoding.DecodeString(m2[2])
	proof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	cs := hmac.New(sha256.New, stored)
	cs.Write([]byte(auth))
	key := cs.Sum(nil)
	for i := range key {
		key[i] ^= proof[i]
	}
	if sum := sha256.Sum256(key); !bytes.Equal(sum[:], stored) {
		t.Fatal("the RFC 7677 client proof does not match the stored key")
	}
	if got := ConnectionString("shop", "pw", netip.MustParseAddr("2001:db8::10"), 5432, "shop"); got != "postgres://shop:pw@[2001:db8::10]:5432/shop?sslmode=disable" {
		t.Fatal(got)
	}
}

func TestAccessBlockValidation(t *testing.T) {
	a := good()
	a.Ports = []api.AppPort{{Name: "postgres", Port: 5432}, {Name: "dns", Port: 53, Proto: "udp"}}
	a.Services = []api.AppService{{Name: "postgresql"}}
	a.Config = []api.AppConfig{{Path: "/var/db/postgres/data18/pg_hba.conf"}}
	a.Access = &api.AppAccessDef{Type: "postgresql", Port: "postgres", Service: "postgresql", HBAFile: "/var/db/postgres/data18/pg_hba.conf"}
	if err := Validate(&a); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mut  func(*api.AppAccessDef)
		want string
	}{
		{func(d *api.AppAccessDef) { d.Type = "mysql" }, "access.type"},
		{func(d *api.AppAccessDef) { d.Port = "dns" }, "access.port"},
		{func(d *api.AppAccessDef) { d.Port = "nope" }, "access.port"},
		{func(d *api.AppAccessDef) { d.Service = "nginx" }, "access.service"},
		{func(d *api.AppAccessDef) { d.HBAFile = "/etc/passwd" }, "access.hba_file"},
	} {
		b := a
		d := *a.Access
		c.mut(&d)
		b.Access = &d
		if err := Validate(&b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", d, err)
		}
	}
	// an unknown key in the block is refused like every other unknown key
	src := string(mustYAML(t, a)) + ""
	src = strings.Replace(src, "hba_file:", "trust: all\n  hba_file:", 1)
	if _, err := Parse(a.Name, []byte(src)); err == nil || !strings.Contains(err.Error(), "trust") {
		t.Fatalf("%v", err)
	}
}

func mustYAML(t *testing.T, a api.App) []byte {
	t.Helper()
	return Draft{App: a}.YAML()
}
