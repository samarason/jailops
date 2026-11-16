package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func host(name, extra string) string {
	return "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: " + name + "\n" + extra + "spec:\n  socket: /var/run/" + name + ".sock\n"
}

func group(name, spec string) string {
	return "apiVersion: jailops/v1\nkind: HostGroup\nmetadata:\n  name: " + name + "\nspec:\n" + spec
}

// project writes projects/<name>.yaml spanning the given hosts.
func project(t *testing.T, d, name, hosts, extra string) {
	t.Helper()
	write(t, d, "projects/"+name+".yaml", "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: "+name+"\nspec:\n  hosts: "+hosts+"\n"+extra)
}

func base(t *testing.T) string {
	d := t.TempDir()
	write(t, d, "fleet.yaml", "id: f\n")
	for _, h := range []string{"a", "b", "c"} {
		write(t, d, "hosts/"+h+"/host.yaml", host(h, "  labels: {role: "+map[string]string{"a": "web", "b": "web", "c": "db"}[h]+"}\n"))
	}
	return d
}

func TestAliasCycleHasFullPath(t *testing.T) {
	d := base(t)
	write(t, d, "groups/x.yaml", group("x", "  members: [\"@y\"]\n"))
	write(t, d, "groups/y.yaml", group("y", "  members: [\"@z\"]\n"))
	write(t, d, "groups/z.yaml", group("z", "  members: [a, \"@x\"]\n"))
	_, err := Load(d)
	if err == nil || !strings.Contains(err.Error(), "group cycle: @x -> @y -> @z -> @x") {
		t.Fatalf("got %v", err)
	}
}

func TestSelfReferenceAndUnknownMembers(t *testing.T) {
	d := base(t)
	write(t, d, "groups/self.yaml", group("self", "  members: [\"@self\"]\n"))
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "group cycle: @self -> @self") {
		t.Fatalf("got %v", err)
	}
	d = base(t)
	write(t, d, "groups/g.yaml", group("g", "  members: [ghost]\n"))
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), `unknown host "ghost"`) {
		t.Fatalf("got %v", err)
	}
	d = base(t)
	write(t, d, "groups/g.yaml", group("g", "  members: [\"@ghost\"]\n"))
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "unknown group @ghost") {
		t.Fatalf("got %v", err)
	}
}

func TestGroupExpansionByMembersAndLabels(t *testing.T) {
	d := base(t)
	write(t, d, "groups/web.yaml", group("web", "  selector: {role: web}\n"))
	write(t, d, "groups/more.yaml", group("more", "  members: [\"@web\", c]\n"))
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	for refs, want := range map[string]string{"@web": "a,b", "@more": "a,b,c", "c": "c"} {
		got, err := f.ExpandHosts([]string{refs})
		if err != nil || strings.Join(got, ",") != want {
			t.Fatalf("%s: %v %v, want %s", refs, got, err, want)
		}
	}
	got, _ := f.ExpandHosts([]string{"a", "@web", "c", "a"})
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("not de-duplicated and sorted: %v", got)
	}
}

func net(name string) string {
	return "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: " + name + "\nspec:\n  ipv4: {subnet: 10.0.0.0/24, gateway: 10.0.0.1, range: 10.0.0.2-10.0.0.9}\n"
}

func TestFilenameEqualsName(t *testing.T) {
	d := base(t)
	write(t, d, "shared/networks/lan.yaml", net("wan"))
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), `metadata.name "wan" does not match the file name "lan"`) {
		t.Fatalf("got %v", err)
	}
}

func TestDuplicatesAcrossScopesAreErrors(t *testing.T) {
	d := base(t)
	write(t, d, "shared/networks/lan.yaml", net("lan"))
	write(t, d, "hosts/a/networks/lan.yaml", net("lan"))
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "duplicate Network") {
		t.Fatalf("got %v", err)
	}
	// Restricting the shared object to other hosts removes the clash.
	write(t, d, "shared/networks/lan.yaml", strings.Replace(net("lan"), "metadata:", "hosts: [b, c]\nmetadata:", 1))
	if _, err := Load(d); err != nil {
		t.Fatal(err)
	}
}

func TestLayoutRules(t *testing.T) {
	cases := map[string]struct{ rel, content, want string }{
		"jails cannot be shared": {"shared/jails/j.yaml", net("j"), "never shared"},
		"unknown top dir":        {"stuff/x.yaml", "a: b", "unexpected entry"},
		"wrong kind for dir":     {"shared/networks/x.yaml", strings.Replace(net("x"), "Network", "Image", 1), `kind is "Image"`},
		"server-owned field":     {"shared/networks/x.yaml", strings.Replace(net("x"), "name: x", "name: x\n  uuid: abc", 1), "may only hold name, project and labels"},
		"reserved label":         {"shared/networks/x.yaml", strings.Replace(net("x"), "name: x", "name: x\n  labels: {sync.jailops.net/hash: x}", 1), "reserved"},
		"two documents":          {"shared/networks/x.yaml", net("x") + "---\n" + net("x"), "exactly one document"},
		"bad apiVersion":         {"shared/networks/x.yaml", strings.Replace(net("x"), "jailops/v1", "v2", 1), "apiVersion"},
		"hosts in host dir":      {"hosts/a/networks/x.yaml", strings.Replace(net("x"), "metadata:", "hosts: [b]\nmetadata:", 1), "only allowed under shared"},
		"jail field on network":  {"shared/networks/x.yaml", strings.Replace(net("x"), "metadata:", "start: true\nmetadata:", 1), "jails only"},
		"upper case name":        {"shared/networks/Lan.yaml", net("Lan"), "lowercase"},
		"wrong extension":        {"shared/networks/x.yml", net("x"), "end in .yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := base(t)
			write(t, d, c.rel, c.content)
			if _, err := Load(d); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestSymlinksAreRefused(t *testing.T) {
	d := base(t)
	write(t, d, "shared/networks/real.yaml", net("real"))
	if err := os.Symlink("real.yaml", filepath.Join(d, "shared/networks/link.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "symlinks") {
		t.Fatalf("got %v", err)
	}
}

func TestTemplateMergeOrderAndHooks(t *testing.T) {
	d := base(t)
	project(t, d, "w", "[a]", "")
	write(t, d, "templates/one/manifest.yaml", "apiVersion: jailops/v1\nkind: JailTemplate\nmetadata:\n  name: one\nspec:\n  jail:\n    image: img@stable\n    resources: {memory: 1G, cpu: 1}\n    env: {A: one, B: one}\n  after: [{action: start}]\n")
	write(t, d, "templates/two/manifest.yaml", "apiVersion: jailops/v1\nkind: JailTemplate\nmetadata:\n  name: two\nspec:\n  jail:\n    resources: {memory: 2G}\n    env: {B: two}\n  after: [{action: snapshot, name: s1}]\n")
	write(t, d, "projects/w/jails/j.yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: j\ntemplates: [one, two]\nafter: [{action: restart}]\nspec:\n  env: {C: own, A: null}\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	var j *Object
	for _, o := range f.Objects {
		if o.Name == "j" {
			j = o
		}
	}
	out, _ := f.Render("a")
	s := string(out)
	for _, w := range []string{"memory: 2G", "cpu: 1", "B: two", "C: own", "image: img@stable"} {
		if !strings.Contains(s, w) {
			t.Fatalf("render lacks %q:\n%s", w, s)
		}
	}
	if strings.Contains(s, "A: one") {
		t.Fatal("null did not delete the key")
	}
	var acts []string
	for _, h := range j.After {
		acts = append(acts, h.Action)
	}
	if strings.Join(acts, ",") != "start,snapshot,restart" {
		t.Fatalf("hook order: %v", acts)
	}
}

func TestHooksAreTypedData(t *testing.T) {
	for name, tc := range map[string]struct{ hook, want string }{
		"unknown action": {"{action: sh}", "unknown hook action"},
		"exec no argv":   {"{action: exec}", "non-empty argv"},
		"start with arg": {"{action: start, argv: [x]}", "takes no name or argv"},
		"shell string":   {"{action: exec, command: ls}", "field command"},
	} {
		t.Run(name, func(t *testing.T) {
			d := base(t)
			project(t, d, "w", "[a]", "")
			write(t, d, "projects/w/jails/j.yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: j\nafter: ["+tc.hook+"]\nspec: {image: i}\n")
			if _, err := Load(d); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCheckFindsAddressSetCycleAndBadValues(t *testing.T) {
	d := base(t)
	project(t, d, "w", "[a, b, c]", "")
	write(t, d, "projects/w/address-sets/p.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: p\nspec:\n  addresses: [{address: \"set:q\"}]\n")
	write(t, d, "projects/w/address-sets/q.yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: q\nspec:\n  addresses: [{address: \"set:p\"}, {address: not-an-ip}]\n")
	write(t, d, "shared/networks/n.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: n\nspec:\n  ipv4: {subnet: 10.0.0.0/24, gateway: 10.9.9.9, range: 10.0.0.9-10.0.0.2}\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Check()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, w := range []string{"address set cycle: p -> q -> p", `"not-an-ip" is neither`, "ipv4.gateway", "ipv4.range"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

// set:NAME as a member of a set is a set of the project: one that is not declared is an error, and sets that reach each
// other through members are a cycle. jail:NAME that is not declared is a warning: the jail may be made later.
func TestCheckFollowsSetMembersThatNameSetsAndJails(t *testing.T) {
	d := base(t)
	project(t, d, "w", "[a, b, c]", "")
	set := func(name, members string) {
		write(t, d, "projects/w/address-sets/"+name+".yaml", "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: "+name+"\nspec:\n  addresses: ["+members+"]\n")
	}
	set("x", "{address: \"set:y\", comment: the other set}")
	set("y", "{address: \"set:x\"}")
	set("z", "{address: \"set:ghost\", comment: nobody}")
	write(t, d, "projects/w/firewall-policies/p.yaml", "apiVersion: jailops/v1\nkind: FirewallPolicy\nmetadata:\n  name: p\nspec:\n  default_in: deny\n  default_out: allow\n  rules:\n    - {action: allow, direction: in, from: [\"jail:ghost2\"]}\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Check()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, w := range []string{"address set cycle: x -> y -> x", "set:ghost, which is not an address set declared"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
	if strings.Contains(err.Error(), "ghost2") || !strings.Contains(strings.Join(f.Warnings, "\n"), "jail:ghost2, which is not a jail declared") {
		t.Errorf("a jail that is not declared is a warning, not an error: %v / %v", err, f.Warnings)
	}
}

func TestFleetIDAndHubRules(t *testing.T) {
	d := t.TempDir()
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "fleet.yaml is missing") {
		t.Fatalf("got %v", err)
	}
	write(t, d, "fleet.yaml", "id: Bad_ID\n")
	if _, err := Load(d); err == nil {
		t.Fatal("bad id accepted")
	}
	write(t, d, "fleet.yaml", "id: ok\n")
	write(t, d, "hosts/h/host.yaml", "apiVersion: jailops/v1\nkind: Host\nmetadata:\n  name: h\nspec:\n  via_hub: true\n")
	if _, err := Load(d); err == nil || !strings.Contains(err.Error(), "needs a hub") {
		t.Fatalf("got %v", err)
	}
	write(t, d, "fleet.yaml", "id: ok\nhub: {url: https://hub.example.test}\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if f.ManagedBy() != "sync:ok" {
		t.Fatal(f.ManagedBy())
	}
}

func TestProfilesMergeDevicesByName(t *testing.T) {
	d := base(t)
	project(t, d, "w", "[a]", "")
	write(t, d, "profiles/p1.yaml", "apiVersion: jailops/v1\nkind: Profile\nmetadata:\n  name: p1\nspec:\n  resources: {memory: 1G}\n  network: [{network: n, mtu: 1500, ipv4: auto}]\n  proxy: [{name: web, listen: \":80\", jail_port: 80}]\n")
	write(t, d, "profiles/p2.yaml", "apiVersion: jailops/v1\nkind: Profile\nmetadata:\n  name: p2\nspec:\n  resources: {memory: 2G, cpu: 2}\n  network: [{name: eth0, mtu: 9000}]\n  proxy: [{name: web, jail_port: 8080}, {name: tls, listen: \":443\", jail_port: 443}]\n")
	write(t, d, "projects/w/jails/j.yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: j\nspec:\n  image: i\n  profiles: [p1, p2]\n  resources: {cpu: 4}\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	var j *Object
	for _, o := range f.Objects {
		if o.Name == "j" {
			j = o
		}
	}
	if j.Project != "w" || len(j.Profiles) != 2 {
		t.Fatalf("%q %v", j.Project, j.Profiles)
	}
	out, _ := f.Render("a")
	s := string(out)
	for _, w := range []string{"memory: 2G", "cpu: 4", "mtu: 9000", `network: "n"`, "jail_port: 8080", "listen: :80", "name: tls", "profile p2", "the jail"} {
		if !strings.Contains(s, w) {
			t.Fatalf("render lacks %q:\n%s", w, s)
		}
	}
	if strings.Contains(s, "profiles:\n") && strings.Contains(s, "- p1") {
		t.Fatal("profiles key must not be sent")
	}
}

func TestProjectLayoutRules(t *testing.T) {
	proj := func(extra string) string {
		return "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: web\nspec:\n" + extra
	}
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"hosts required":              {map[string]string{"projects/web.yaml": proj("  comment: x\n")}, "spec.hosts is required"},
		"unknown host":                {map[string]string{"projects/web.yaml": proj("  hosts: [zz]\n")}, `unknown host "zz"`},
		"default is an ordinary name": {map[string]string{"projects/default.yaml": strings.Replace(proj("  hosts: [a]\n"), "web", "default", 1)}, ""},
		"object without a project":    {map[string]string{"hosts/a/address-sets/s.yaml": "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\nspec:\n  addresses: [{address: 1.1.1.1}]\n"}, "belongs to a project"},
		"jail outside a project":      {map[string]string{"hosts/a/jails/j.yaml": "apiVersion: jailops/v1\nkind: Jail\nmetadata:\n  name: j\nspec:\n  image: i\n"}, "put it under projects/<project>/jails/"},
		"dir w/o project":             {map[string]string{"projects/web/jails/j.yaml": "x"}, "no projects/web.yaml"},
		"undefined project":           {map[string]string{"shared/address-sets/s.yaml": "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\n  project: ghost\nspec:\n  addresses: [{address: 1.1.1.1}]\n"}, `project "ghost" is not defined`},
		"host not in project": {map[string]string{
			"projects/web.yaml":           proj("  hosts: [a]\n"),
			"hosts/b/address-sets/s.yaml": "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\n  project: web\nspec:\n  addresses: [{address: 1.1.1.1}]\n"}, "not one of project web's hosts"},
		"jail on two hosts": {map[string]string{
			"projects/web.yaml":         proj("  hosts: [a, b]\n"),
			"projects/web/jails/j.yaml": "apiVersion: jailops/v1\nkind: Jail\nmetadata:\n  name: j\nspec:\n  image: i\n"}, "exactly one named host"},
		"project on host-level kind": {map[string]string{"shared/networks/x.yaml": strings.Replace(net("x"), "name: x", "name: x\n  project: web", 1)}, "host-level kind"},
		"unknown profile": {map[string]string{
			"projects/web.yaml":         proj("  hosts: [a]\n"),
			"projects/web/jails/j.yaml": "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: j\nspec:\n  image: i\n  profiles: [nope]\n"}, `unknown profile "nope"`},
		"same name two projects ok": {map[string]string{
			"projects/web.yaml":                proj("  hosts: [a]\n"),
			"projects/db.yaml":                 strings.Replace(proj("  hosts: [a]\n"), "web", "db", 1),
			"projects/db/address-sets/s.yaml":  "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\nspec:\n  addresses: [{address: 1.1.1.1}]\n",
			"projects/web/address-sets/s.yaml": "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\nspec:\n  addresses: [{address: 2.2.2.2}]\n"}, ""},
		"duplicate in one project": {map[string]string{
			"projects/web.yaml":                proj("  hosts: [a]\n"),
			"hosts/a/address-sets/s.yaml":      "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\n  project: web\nspec:\n  addresses: [{address: 1.1.1.1}]\n",
			"projects/web/address-sets/s.yaml": "apiVersion: jailops/v1\nkind: AddressSet\nmetadata:\n  name: s\nspec:\n  addresses: [{address: 2.2.2.2}]\n"}, "duplicate AddressSet"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := base(t)
			for p, content := range c.files {
				write(t, d, p, content)
			}
			_, err := Load(d)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

func TestCheckEnforcesProjectGrants(t *testing.T) {
	d := base(t)
	write(t, d, "projects/web.yaml", "apiVersion: jailops/v1\nkind: Project\nmetadata:\n  name: web\nspec:\n  hosts: [a]\n  networks: [{network: ok}]\n  storage: [{storage: default}]\n  images: [img]\n  firewall_policies: [base]\n")
	write(t, d, "shared/networks/ok.yaml", net("ok"))
	write(t, d, "shared/networks/other.yaml", net("other"))
	write(t, d, "shared/images/img.yaml", "apiVersion: jailops/v1\nkind: Image\nmetadata:\n  name: img\nspec: {os: freebsd, release: r, arch: amd64, source: {type: pkgbase}}\n")
	write(t, d, "shared/images/bad.yaml", "apiVersion: jailops/v1\nkind: Image\nmetadata:\n  name: bad\nspec: {os: freebsd, release: r, arch: amd64, source: {type: pkgbase}}\n")
	write(t, d, "projects/web/jails/j.yaml", "apiVersion: jailops/v1\nkind: Jail\nmetadata:\n  name: j\nhosts: [a]\nspec:\n  image: bad\n  storage: other\n  network: [{network: other}]\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Check()
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, w := range []string{`network "other" is not granted`, `image "bad" is not in project web's image allow-list`, `mandatory firewall policy "base" is not declared`, `unknown Storage "other"`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

func TestAJailNeedsANetworkAndAStorage(t *testing.T) {
	d := base(t)
	project(t, d, "web", "[a]", "  networks: [{network: lan}]\n  storage: [{storage: default}]\n")
	write(t, d, "shared/networks/lan.yaml", net("lan"))
	write(t, d, "projects/web/jails/bare.yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: bare\nspec:\n  image: i\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Check()
	if err == nil || !strings.Contains(err.Error(), "a jail needs a network") || !strings.Contains(err.Error(), "a jail needs a storage") {
		t.Fatalf("got %v", err)
	}
	// a profile may supply both
	write(t, d, "profiles/lan.yaml", "apiVersion: jailops/v1\nkind: Profile\nmetadata:\n  name: lan\nspec:\n  network: [{network: lan}]\n  storage: default\n")
	write(t, d, "projects/web/jails/bare.yaml", "apiVersion: jailops/v1\nkind: Jail\nhosts: [a]\nmetadata:\n  name: bare\nspec:\n  image: i\n  profiles: [lan]\n")
	f, err = Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err != nil && (strings.Contains(err.Error(), "needs a network") || strings.Contains(err.Error(), "needs a storage")) {
		t.Fatalf("a profile that supplies them was refused: %v", err)
	}
}

func TestANetworkBelongsToOneProject(t *testing.T) {
	d := base(t)
	project(t, d, "web", "[a, b]", "  networks: [{network: lan}]\n")
	project(t, d, "db", "[b]", "  networks: [{network: lan}]\n")
	write(t, d, "shared/networks/lan.yaml", net("lan"))
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Check()
	if err == nil || !strings.Contains(err.Error(), `network "lan" is already granted to project`) || !strings.Contains(err.Error(), "on host b") {
		t.Fatalf("got %v", err)
	}
	// projects on different hosts may use the same name: they are different objects
	d = base(t)
	project(t, d, "web", "[a]", "  networks: [{network: lan}]\n")
	project(t, d, "db", "[b]", "  networks: [{network: lan}]\n")
	write(t, d, "shared/networks/lan.yaml", net("lan"))
	f, err = Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err != nil && strings.Contains(err.Error(), "already granted") {
		t.Fatalf("disjoint hosts were refused: %v", err)
	}
	// "every network" is not a grant
	d = base(t)
	project(t, d, "web", "[a]", "  networks: [{network: \"*\"}]\n")
	f, err = Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err == nil || !strings.Contains(err.Error(), "one by one") {
		t.Fatalf("got %v", err)
	}
}

func TestARolloutNamesItsProject(t *testing.T) {
	d := base(t)
	write(t, d, "rollouts/r.yaml", "apiVersion: jailops/v1\nkind: Rollout\nmetadata:\n  name: r\nspec:\n  selector: {role: web}\n  action: upgrade\n")
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err == nil || !strings.Contains(err.Error(), "names the project") {
		t.Fatalf("got %v", err)
	}
}

// Apps and their grants belong to a project and one host, and an app is its
// own jail: a Jail of the same name is an error.
func TestAppDocuments(t *testing.T) {
	appDoc := func(kind, name, hosts, spec string) string {
		return "apiVersion: jailops/v1\nkind: " + kind + "\nmetadata:\n  name: " + name + "\nhosts: " + hosts + "\nspec:\n" + spec
	}
	d := base(t)
	project(t, d, "shop", "[a, b]", "  networks: [{network: lan}]\n  storage: [{storage: default}]\n")
	write(t, d, "shared/networks/lan.yaml", "apiVersion: jailops/v1\nkind: Network\nmetadata:\n  name: lan\nspec:\n  ipv4: {subnet: 10.70.0.0/24, gateway: 10.70.0.1, range: 10.70.0.10-10.70.0.250}\n")
	write(t, d, "projects/shop/apps/db.yaml", appDoc("App", "db", "[a]", "  app: postgresql\n  network: lan\n"))
	write(t, d, "projects/shop/app-access/db.yaml", appDoc("AppAccess", "db", "[a]", "  grants:\n    - {source: \"jail:web\", database: shop}\n"))
	f, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.Warnings, "\n"), "source jail:web is neither a jail") {
		t.Fatalf("warnings %v", f.Warnings)
	}
	if objs := f.ObjectsFor("a"); objs[len(objs)-1].Kind != "AppAccess" {
		t.Fatalf("an AppAccess is not ordered last: %v", objs[len(objs)-1].Kind)
	}

	for name, c := range map[string]struct{ rel, doc, want string }{
		"two hosts":   {"projects/shop/apps/db.yaml", appDoc("App", "db", "[a, b]", "  app: postgresql\n"), "exactly one named host"},
		"bad source":  {"projects/shop/app-access/db.yaml", appDoc("AppAccess", "db", "[a]", "  grants:\n    - {source: everyone}\n"), "is not an address"},
		"unknown key": {"projects/shop/apps/db.yaml", appDoc("App", "db", "[a]", "  app: postgresql\n  rotate: true\n"), "unknown field"},
	} {
		t.Run(name, func(t *testing.T) {
			d := base(t)
			project(t, d, "shop", "[a, b]", "")
			write(t, d, c.rel, c.doc)
			if _, err := Load(d); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
	// outside a project
	d2 := base(t)
	write(t, d2, "hosts/a/apps/db.yaml", appDoc("App", "db", "[a]", "  app: postgresql\n"))
	if _, err := Load(d2); err == nil || !strings.Contains(err.Error(), "belongs to a project") {
		t.Fatalf("%v", err)
	}
	// an App and a Jail of the same name
	write(t, d, "projects/shop/jails/db.yaml", "apiVersion: jailops/v1\nkind: Jail\nmetadata:\n  name: db\nhosts: [a]\nspec:\n  image: x\n  storage: default\n  network: [{network: lan}]\n")
	f, err = Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Check(); err == nil || !strings.Contains(err.Error(), "an app is installed as its own jail") {
		t.Fatalf("%v", err)
	}
}
