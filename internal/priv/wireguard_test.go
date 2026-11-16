package priv

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

const wgBin = "/usr/local/bin/wg"

// wgHost is a stand-in for the kernel and the wg program: interfaces made with "ifconfig wg create", their
// descriptions and addresses, and the configuration `wg syncconf` read from its file. It checks, at the moment the
// file is read, that it is mode 0600 and inside the helper's directory.
type wgHost struct {
	mu      sync.Mutex
	t       *testing.T
	dir     string
	n       int
	ifs     map[string]*wgIf
	routes  []string
	gateway string // what route -n get -inet default answers ("" none)
	syncs   int
	secrets []string // every key the stand-in made
}

type wgIf struct {
	desc  string
	addrs []string
	up    bool
	wg    bool
	conf  string
}

func (h *wgHost) key() string {
	h.n++
	s := sha256.Sum256([]byte(fmt.Sprintf("wg-test-%d", h.n)))
	k := base64.StdEncoding.EncodeToString(s[:])
	h.secrets = append(h.secrets, k)
	return k
}

// get returns a copy of an interface (nil when there is none); set changes the stand-in under its lock.
func (h *wgHost) get(n string) *wgIf {
	h.mu.Lock()
	defer h.mu.Unlock()
	if i := h.ifs[n]; i != nil {
		c := *i
		return &c
	}
	return nil
}

func (h *wgHost) set(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn()
}

func (h *wgHost) keys() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.secrets)
}

func pubOf(priv string) string {
	s := sha256.Sum256([]byte("pub:" + priv))
	return base64.StdEncoding.EncodeToString(s[:])
}

func (h *wgHost) install(r *run.Fake) {
	r.Add(run.Rule{Name: wgBin, Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		out := func(s string) (run.Result, error) { return run.Result{Stdout: []byte(s)}, nil }
		fail := func(s string) (run.Result, error) {
			return run.Result{ExitCode: 1, Stderr: []byte(s)}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: s}
		}
		switch {
		case len(c.Args) == 1 && (c.Args[0] == "genkey" || c.Args[0] == "genpsk"):
			return out(h.key() + "\n")
		case len(c.Args) == 1 && c.Args[0] == "pubkey":
			b := make([]byte, 100)
			n, _ := c.Stdin.Read(b)
			return out(pubOf(strings.TrimSpace(string(b[:n]))) + "\n")
		case len(c.Args) == 3 && c.Args[0] == "syncconf":
			i := h.ifs[c.Args[1]]
			if i == nil {
				return fail("Unable to modify interface: No such device")
			}
			fi, err := os.Lstat(c.Args[2])
			if err != nil || fi.Mode().Perm() != 0o600 || !strings.HasPrefix(c.Args[2], h.dir+"/") {
				h.t.Errorf("syncconf read %s (mode %v, %v): not a 0600 file of the helper's directory", c.Args[2], fi.Mode(), err)
			}
			b, _ := os.ReadFile(c.Args[2])
			i.conf = string(b)
			h.syncs++
			return out("")
		case len(c.Args) == 3 && c.Args[0] == "show" && c.Args[2] == "dump":
			i := h.ifs[c.Args[1]]
			if i == nil {
				return fail("Unable to access interface: No such device")
			}
			return out(dumpOf(i.conf))
		}
		return fail("unexpected wg " + strings.Join(c.Args, " "))
	}})
	r.Add(run.Rule{Name: "ifconfig", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		a := c.Args
		fail := func(s string) (run.Result, error) {
			return run.Result{ExitCode: 1, Stderr: []byte(s)}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: s}
		}
		switch {
		case len(a) == 1 && a[0] == "-a":
			var b strings.Builder
			names := make([]string, 0, len(h.ifs))
			for n := range h.ifs {
				names = append(names, n)
			}
			slices.Sort(names)
			for _, n := range names {
				i := h.ifs[n]
				fl := "POINTOPOINT,RUNNING,MULTICAST"
				if i.up {
					fl = "UP," + fl
				}
				fmt.Fprintf(&b, "%s: flags=8051<%s> metric 0 mtu 1420\n", n, fl)
				if i.desc != "" {
					fmt.Fprintf(&b, "\tdescription: %s\n", i.desc)
				}
				for _, ad := range i.addrs {
					p := netip.MustParsePrefix(ad)
					if p.Addr().Is4() {
						fmt.Fprintf(&b, "\tinet %s netmask 0x%08x\n", p.Addr(), ^uint32(0)<<(32-p.Bits()))
					} else {
						fmt.Fprintf(&b, "\tinet6 %s prefixlen %d\n", p.Addr(), p.Bits())
					}
				}
				if i.wg {
					b.WriteString("\tgroups: wg\n")
				}
			}
			return run.Result{Stdout: []byte(b.String())}, nil
		case len(a) == 2 && a[0] == "wg" && a[1] == "create":
			n := fmt.Sprintf("wg%d", len(h.ifs))
			h.ifs[n] = &wgIf{wg: true}
			return run.Result{Stdout: []byte(n + "\n")}, nil
		case len(a) == 3 && a[1] == "name":
			i := h.ifs[a[0]]
			if i == nil || h.ifs[a[2]] != nil {
				return fail("ifconfig: SIOCSIFNAME: File exists")
			}
			delete(h.ifs, a[0])
			h.ifs[a[2]] = i
		case len(a) == 2 && a[1] == "destroy":
			if h.ifs[a[0]] == nil {
				return fail("ifconfig: interface " + a[0] + " does not exist")
			}
			delete(h.ifs, a[0])
		case len(a) == 3 && a[1] == "description":
			h.ifs[a[0]].desc = a[2]
		case len(a) == 2 && a[1] == "up":
			h.ifs[a[0]].up = true
		case len(a) >= 4 && (a[1] == "inet" || a[1] == "inet6"):
			i := h.ifs[a[0]]
			ad := a[2]
			if a[1] == "inet6" {
				ad += "/" + a[4]
			}
			if a[len(a)-1] == "-alias" {
				i.addrs = slices.DeleteFunc(i.addrs, func(x string) bool { return x == ad })
			} else {
				i.addrs = append(i.addrs, ad)
			}
		default:
			return fail("unexpected ifconfig " + strings.Join(a, " "))
		}
		return run.Result{}, nil
	}})
	r.Add(run.Rule{Name: "route", Args: []string{run.RestArgs}, Fn: func(c run.Cmd) (run.Result, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if len(c.Args) == 4 && c.Args[1] == "get" {
			if c.Args[2] != "-inet" || h.gateway == "" {
				return run.Result{ExitCode: 1}, &run.ExitError{Name: c.Name, Args: c.Args, Code: 1, Stderr: "route: route has not been found"}
			}
			return run.Result{Stdout: []byte("   route to: default\ndestination: default\n       mask: default\n    gateway: " + h.gateway + "\n  interface: em0\n")}, nil
		}
		h.routes = append(h.routes, strings.Join(c.Args, " "))
		return run.Result{}, nil
	}})
	r.Add(run.Rule{Name: "kldstat", Args: []string{"-q", "-n", "if_wg"}})
}

// dumpOf answers `wg show <if> dump` from the configuration the interface holds, secrets included, as wg does.
func dumpOf(conf string) string {
	var priv, port string
	type peer struct{ pub, psk, allowed, endpoint, ka string }
	var peers []peer
	var cur *peer
	for _, l := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(l, " = ")
		if !ok {
			if l == "[Peer]" {
				peers = append(peers, peer{psk: "(none)", endpoint: "(none)", ka: "off"})
				cur = &peers[len(peers)-1]
			}
			continue
		}
		switch {
		case k == "PrivateKey":
			priv = v
		case k == "ListenPort":
			port = v
		case cur != nil && k == "PublicKey":
			cur.pub = v
		case cur != nil && k == "PresharedKey":
			cur.psk = v
		case cur != nil && k == "AllowedIPs":
			cur.allowed = strings.ReplaceAll(v, ", ", ",")
		case cur != nil && k == "Endpoint":
			cur.endpoint = v
		case cur != nil && k == "PersistentKeepalive":
			cur.ka = v
		}
	}
	if port == "" {
		port = "40001"
	}
	out := priv + "\t" + pubOf(priv) + "\t" + port + "\toff\n"
	for _, p := range peers {
		out += strings.Join([]string{p.pub, p.psk, p.endpoint, p.allowed, "1761800000", "1024", "2048", p.ka}, "\t") + "\n"
	}
	return out
}

func newWGFixture(t *testing.T) (*fixture, *wgHost) {
	t.Helper()
	var h *wgHost
	f := newFixtureWith(t, func(e *env) {
		dir := filepath.Join(e.base, "wgroot", "wireguard")
		h = &wgHost{t: t, dir: dir, ifs: map[string]*wgIf{}}
		h.install(e.runner)
		cfg := e.cfg
		cfg.WireGuardDir = dir
		// Etc: the host's resolv.conf the route guard reads (a test writes it; none by default)
		l, err := NewLocal(cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner, Jexec: e.jexec,
			WGLocate: func() string { return wgBin }, Etc: filepath.Join(e.base, "etc-wg")}, WithoutChown())
		if err != nil {
			t.Fatal(err)
		}
		e.local, e.cfg = l, l.Config()
	})
	return f, h
}

var adminCtx = WithAdmin(context.Background(), "alice")

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// leaks fails when any secret appears in s.
func leaks(t *testing.T, where, s string, secrets []string) {
	t.Helper()
	for _, k := range secrets {
		if k != "" && strings.Contains(s, k) {
			t.Errorf("a secret reached %s", where)
		}
	}
}

func argvOf(r *run.Fake) string {
	var b strings.Builder
	for _, c := range r.Calls() {
		b.WriteString(c.Cmd.Name + " " + strings.Join(c.Cmd.Args, " ") + "\n")
	}
	return b.String()
}

func TestWireGuardKeysAndPeersOverTheWire(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	k, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"})
	if err != nil || !wireguard.ValidKey(k.PublicKey) {
		t.Fatalf("%+v %v", k, err)
	}
	dir := filepath.Join(h.dir, "office")
	if m := mode(t, h.dir); m != 0o700 {
		t.Errorf("wireguard dir mode %v", m)
	}
	if m := mode(t, dir); m != 0o700 {
		t.Errorf("object dir mode %v", m)
	}
	if m := mode(t, filepath.Join(dir, "private.key")); m != 0o600 {
		t.Errorf("private key mode %v", m)
	}
	again, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"})
	if err != nil || again.PublicKey != k.PublicKey {
		t.Fatalf("a second call made another key: %+v %v", again, err)
	}
	rot, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office", Rotate: true})
	if err != nil || rot.PublicKey == k.PublicKey {
		t.Fatalf("rotate: %+v %v", rot, err)
	}
	p, err := c.WGPeerKeys(adminCtx, wireguard.PeerKeysReq{Name: "office"})
	if err != nil || !wireguard.ValidKey(p.PrivateKey) || !wireguard.ValidKey(p.PresharedKey) || p.PublicKey != pubOf(p.PrivateKey) {
		t.Fatalf("%+v %v", p, err)
	}
	psk := filepath.Join(dir, pskFile(p.PublicKey))
	if m := mode(t, psk); m != 0o600 {
		t.Errorf("psk mode %v", m)
	}
	if b, _ := os.ReadFile(psk); strings.TrimSpace(string(b)) != p.PresharedKey {
		t.Error("the preshared key was not stored for the peer's public key")
	}
	if _, err := c.WGPeerKeys(adminCtx, wireguard.PeerKeysReq{Name: "ghost"}); !api.IsCode(err, api.CodeNotFound) {
		t.Errorf("peer of an object without keys: %v", err)
	}
	// keys never travel on a command line, and the audit log names objects only
	leaks(t, "the argv of a command", argvOf(f.runner), h.keys())
	leaks(t, "the audit log", f.audit.String(), h.keys())
	if !strings.Contains(f.audit.String(), `"op":"wg.peer_keys"`) || !strings.Contains(f.audit.String(), `"name":"office"`) {
		t.Errorf("audit: %s", f.audit.String())
	}
	// pubkey got the private key on standard input
	for _, call := range f.runner.Calls() {
		if call.Cmd.Name == wgBin && call.Cmd.Args[0] == "pubkey" && !slices.Contains(h.keys(), strings.TrimSpace(string(call.StdinData))) {
			t.Error("wg pubkey read no key on standard input")
		}
	}
}

func TestWireGuardNeedsTheAdminAssertion(t *testing.T) {
	f, _ := newWGFixture(t)
	c, ctx := f.client, context.Background()
	if _, err := c.WGKeys(ctx, wireguard.KeysReq{Name: "office"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("keys: %v", err)
	}
	if _, err := c.WGPeerKeys(ctx, wireguard.PeerKeysReq{Name: "office"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("peer keys: %v", err)
	}
	if _, err := c.WGImport(ctx, wireguard.ImportReq{Name: "office"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("import: %v", err)
	}
	if _, err := c.WGApply(ctx, wireguard.ApplyReq{Name: "office"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("apply: %v", err)
	}
	if err := c.WGRemove(ctx, wireguard.RemoveReq{Name: "office"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("remove: %v", err)
	}
	if err := c.WGRename(ctx, wireguard.RenameReq{From: "office", To: "hq"}); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("rename: %v", err)
	}
	// reading the state needs no assertion
	if _, err := c.WGShow(ctx, wireguard.ShowReq{Name: "office", Iface: "wg-office"}); err != nil {
		t.Errorf("show: %v", err)
	}
	if tl, err := c.WGTools(ctx); err != nil || tl.Path != wgBin || !tl.Module {
		t.Errorf("tools: %+v %v", tl, err)
	}
}

func serverApply(pub string) wireguard.ApplyReq {
	return wireguard.ApplyReq{Name: "office", Iface: "wg-office", ListenPort: 51820,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.99.0.1/24"), netip.MustParsePrefix("fd99::1/64")},
		Peers:     []wireguard.PeerConf{{PublicKey: pub, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}}}}
}

func TestWireGuardApplyShowRemove(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	p, err := c.WGPeerKeys(adminCtx, wireguard.PeerKeysReq{Name: "office"})
	if err != nil {
		t.Fatal(err)
	}
	req := serverApply(p.PublicKey)
	res, err := c.WGApply(adminCtx, req)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.Changed, "created wg-office") || !slices.Contains(res.Changed, "configuration") {
		t.Errorf("changed %v", res.Changed)
	}
	i := h.get("wg-office")
	if i == nil || i.desc != "jailops wireguard=office" || !i.up || len(i.addrs) != 2 {
		t.Fatalf("interface %+v", i)
	}
	if !strings.Contains(i.conf, "PrivateKey = ") || !strings.Contains(i.conf, "PresharedKey = "+p.PresharedKey) || !strings.Contains(i.conf, "ListenPort = 51820") {
		t.Errorf("configuration:\n%s", i.conf)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "office", wgConfFile)); !os.IsNotExist(err) {
		t.Error("the configuration file was left behind")
	}
	// idempotent: nothing differs, nothing is done
	res, err = c.WGApply(adminCtx, req)
	var syncs int
	h.set(func() { syncs = h.syncs })
	if err != nil || len(res.Changed) != 0 || syncs != 1 {
		t.Errorf("second apply changed %v (syncs %d) %v", res.Changed, syncs, err)
	}
	// a description changed by hand is put back
	h.set(func() { h.ifs["wg-office"].desc = "someone" })
	if res, err = c.WGApply(adminCtx, req); err != nil || !slices.Equal(res.Changed, []string{"description"}) {
		t.Errorf("repair %v %v", res.Changed, err)
	}
	sh, err := c.WGShow(context.Background(), wireguard.ShowReq{Name: "office", Iface: "wg-office"})
	if err != nil || !sh.Exists || !sh.Up || sh.ListenPort != 51820 || len(sh.Peers) != 1 || !sh.Peers[0].PresharedKey || sh.Peers[0].LatestHandshake == 0 {
		t.Fatalf("%+v %v", sh, err)
	}
	b, _ := json.Marshal(sh)
	leaks(t, "the answer of wg.show", string(b), h.keys())
	// the peer goes: its preshared key goes too
	req.Peers = nil
	if _, err := c.WGApply(adminCtx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "office", pskFile(p.PublicKey))); !os.IsNotExist(err) {
		t.Error("the preshared key of a removed peer stayed")
	}
	leaks(t, "the argv of a command", argvOf(f.runner), h.keys())
	leaks(t, "the audit log", f.audit.String(), h.keys())
	if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: "office", Iface: "wg-office"}); err != nil {
		t.Fatal(err)
	}
	if h.get("wg-office") != nil {
		t.Error("the interface is still there")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "office", "private.key")); err != nil {
		t.Error("down removed the keys")
	}
	if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: "office", Iface: "wg-office", Purge: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "office")); !os.IsNotExist(err) {
		t.Error("purge left the key directory")
	}
}

func TestWireGuardLeavesForeignInterfacesAlone(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	h.set(func() { h.ifs["wg-office"] = &wgIf{wg: true, desc: "the administrator's own tunnel", up: true} })
	if _, err := c.WGApply(adminCtx, serverApply(pubOf("x"))); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("apply on a foreign interface: %v", err)
	}
	if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: "office", Iface: "wg-office", Purge: true}); err != nil {
		t.Fatal(err)
	}
	if i := h.get("wg-office"); i == nil || i.desc != "the administrator's own tunnel" {
		t.Fatalf("the foreign interface was touched: %+v", i)
	}
	if sh, err := c.WGShow(adminCtx, wireguard.ShowReq{Name: "office", Iface: "wg-office"}); err != nil || sh.Exists {
		t.Errorf("show reports a foreign interface: %+v %v", sh, err)
	}
}

func TestWireGuardImport(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	priv, psk, srv := wireguard.FakeKey(1), wireguard.FakeKey(2), wireguard.FakeKey(3)
	k, err := c.WGImport(adminCtx, wireguard.ImportReq{Name: "home", PrivateKey: priv, PeerPublicKey: srv, PresharedKey: psk})
	if err != nil || k.PublicKey != pubOf(priv) {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := c.WGImport(adminCtx, wireguard.ImportReq{Name: "home", PrivateKey: priv, PeerPublicKey: srv}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Errorf("second import: %v", err)
	}
	req := wireguard.ApplyReq{Name: "home", Iface: "wg-home", Addresses: []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("10.20.0.0/24")},
		Peers: []wireguard.PeerConf{{PublicKey: srv, Endpoint: "203.0.113.10:51820", Keepalive: 25,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("10.20.0.0/24")}}}}
	if _, err := c.WGApply(adminCtx, req); err != nil {
		t.Fatal(err)
	}
	conf := h.get("wg-home").conf
	if !strings.Contains(conf, "PrivateKey = "+priv) || !strings.Contains(conf, "PresharedKey = "+psk) || strings.Contains(conf, "ListenPort") {
		t.Errorf("client configuration:\n%s", conf)
	}
	var routes []string
	h.set(func() { routes = slices.Clone(h.routes) })
	if !slices.Contains(routes, "-n add -inet 10.99.0.0/24 -interface wg-home") || !slices.Contains(routes, "-n add -inet 10.20.0.0/24 -interface wg-home") {
		t.Errorf("routes %v", routes)
	}
	leaks(t, "the argv of a command", argvOf(f.runner), []string{priv, psk})
	leaks(t, "the audit log", f.audit.String(), []string{priv, psk})
}

// Every field the helper takes is checked, and a refused key is never repeated in the error.
func TestWireGuardRefusals(t *testing.T) {
	f, _ := newWGFixture(t)
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	pub := pubOf("x")
	good := func() wireguard.ApplyReq { return serverApply(pub) }
	bad := []struct {
		what string
		req  func(*wireguard.ApplyReq)
	}{
		{"name with a path", func(q *wireguard.ApplyReq) { q.Name = "../office" }},
		{"name upper case", func(q *wireguard.ApplyReq) { q.Name = "Office" }},
		{"empty name", func(q *wireguard.ApplyReq) { q.Name = "" }},
		{"foreign interface name", func(q *wireguard.ApplyReq) { q.Iface = "em0" }},
		{"interface of JailOps networks", func(q *wireguard.ApplyReq) { q.Iface = "jo0" }},
		{"interface with a slash", func(q *wireguard.ApplyReq) { q.Iface = "wg/../x" }},
		{"interface too long", func(q *wireguard.ApplyReq) { q.Iface = "wg-0123456789abcd" }},
		{"interface with a space", func(q *wireguard.ApplyReq) { q.Iface = "wg office" }},
		{"no address", func(q *wireguard.ApplyReq) { q.Addresses = nil }},
		{"three addresses", func(q *wireguard.ApplyReq) {
			q.Addresses = append(q.Addresses, netip.MustParsePrefix("10.98.0.1/24"))
		}},
		{"loopback address", func(q *wireguard.ApplyReq) { q.Addresses = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")} }},
		{"link-local address", func(q *wireguard.ApplyReq) { q.Addresses = []netip.Prefix{netip.MustParsePrefix("fe80::1/64")} }},
		{"listen port too large", func(q *wireguard.ApplyReq) { q.ListenPort = 70000 }},
		{"default route", func(q *wireguard.ApplyReq) { q.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }},
		{"route with host bits", func(q *wireguard.ApplyReq) { q.Routes = []netip.Prefix{netip.MustParsePrefix("10.20.0.1/24")} }},
		{"peer key not base64", func(q *wireguard.ApplyReq) { q.Peers[0].PublicKey = "not a key" }},
		{"peer key of 31 bytes", func(q *wireguard.ApplyReq) {
			q.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31))
		}},
		{"peer twice", func(q *wireguard.ApplyReq) { q.Peers = append(q.Peers, q.Peers[0]) }},
		{"peer takes the default route", func(q *wireguard.ApplyReq) {
			q.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("::/0")}
		}},
		{"peer endpoint without a port", func(q *wireguard.ApplyReq) { q.Peers[0].Endpoint = "203.0.113.10" }},
		{"peer endpoint with a newline", func(q *wireguard.ApplyReq) { q.Peers[0].Endpoint = "a\nb:1" }},
		{"peer endpoint port 0", func(q *wireguard.ApplyReq) { q.Peers[0].Endpoint = "203.0.113.10:0" }},
		{"negative keepalive", func(q *wireguard.ApplyReq) { q.Peers[0].Keepalive = -1 }},
		{"too many peers", func(q *wireguard.ApplyReq) {
			for i := 0; i <= wireguard.MaxPeers; i++ {
				q.Peers = append(q.Peers, wireguard.PeerConf{PublicKey: wireguard.FakeKey(i + 10)})
			}
		}},
	}
	for _, b := range bad {
		q := good()
		b.req(&q)
		if _, err := c.WGApply(adminCtx, q); err == nil || !api.IsCode(err, api.CodeInvalid) && !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v", b.what, err)
		}
	}
	secret := wireguard.FakeKey(99)
	for _, q := range []wireguard.ImportReq{
		{Name: "x", PrivateKey: secret[:43], PeerPublicKey: pub},
		{Name: "x", PrivateKey: secret, PeerPublicKey: secret + "x"},
		{Name: "x", PrivateKey: secret, PeerPublicKey: pub, PresharedKey: secret[1:] + "=="},
		{Name: "../x", PrivateKey: secret, PeerPublicKey: pub},
		{Name: "x/y", PrivateKey: secret, PeerPublicKey: pub},
	} {
		_, err := c.WGImport(adminCtx, q)
		if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("import %q: %v", q.Name, err)
		}
		if err != nil && strings.Contains(err.Error(), secret[:20]) {
			t.Errorf("the error repeats a key: %v", err)
		}
	}
	for _, n := range []string{"..", "a/b", "A", "", strings.Repeat("a", 64)} {
		if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: n}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("keys %q: %v", n, err)
		}
		if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: n, Purge: true}); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("remove %q: %v", n, err)
		}
	}
	if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: "office", Iface: "em0"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("remove of em0: %v", err)
	}
	if _, err := c.WGShow(adminCtx, wireguard.ShowReq{Name: "office", Iface: "lo0"}); !api.IsCode(err, api.CodeInvalid) {
		t.Errorf("show of lo0: %v", err)
	}
	if strings.Contains(f.audit.String(), secret) {
		t.Error("a refused key reached the audit log")
	}
}

// The helper writes only below its own directory: a key directory that is a link out of it is refused, and so is
// a WireGuard directory that is a link.
func TestWireGuardWritesOnlyBelowItsDirectory(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(h.dir, "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "evil"}); err == nil {
		t.Fatal("keys were written through a link")
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("something was written outside: %v", ents)
	}
	if err := c.WGRemove(adminCtx, wireguard.RemoveReq{Name: "evil", Purge: true}); err != nil {
		t.Logf("remove of a link: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("purge followed the link")
	}
	// a link as the whole directory
	real := filepath.Join(f.base, "elsewhere")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.base, "wglink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg := f.cfg
	cfg.WireGuardDir = link
	if err := cfg.checkWGDir(link); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a linked directory: %v", err)
	}
}

func TestWireGuardDirConfig(t *testing.T) {
	base := Config{StateDir: "/var/db/jailops/state", ConfDir: "/usr/local/etc/jailops/jails", WorkDir: "/var/tmp/jailops"}
	if c, err := base.Normalize(); err != nil || c.WireGuardDir != DefaultWireGuardDir {
		t.Fatalf("default %q %v", c.WireGuardDir, err)
	}
	for _, d := range []string{"relative/wg", "/wg", "/var/db/jailops/state/wg", "/var/db/../wg", "/var/tmp/jailops/wg", "/usr/local/etc/jailops/jails/x"} {
		c := base
		c.WireGuardDir = d
		if _, err := c.Normalize(); err == nil {
			t.Errorf("accepted %q", d)
		}
	}
}

// Operations on several objects at once, and on one object from several callers, keep every key where it belongs.
func TestWireGuardConcurrent(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	var wg sync.WaitGroup
	names := []string{"a", "b", "c", "d"}
	for _, n := range names {
		if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	peers := make(chan wireguard.PeerKeysRes, 64)
	sem := make(chan struct{}, 3) // a connection carries at most 8 requests at once (two per goroutine here)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			n := names[i%len(names)]
			p, err := c.WGPeerKeys(adminCtx, wireguard.PeerKeysReq{Name: n})
			if err != nil {
				t.Error(err)
				return
			}
			peers <- p
			if _, err := c.WGShow(adminCtx, wireguard.ShowReq{Name: n, Iface: "wg-" + n}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	close(peers)
	seen := map[string]bool{}
	for p := range peers {
		if seen[p.PresharedKey] || seen[p.PrivateKey] {
			t.Fatal("a key was handed out twice")
		}
		seen[p.PresharedKey], seen[p.PrivateKey] = true, true
	}
	if len(seen) != 64 {
		t.Fatalf("%d keys", len(seen))
	}
	leaks(t, "the argv of a command", argvOf(f.runner), h.keys())
}

// A tunnel's routes stay with the networks behind it: inside a peer's allowed IPs, and, unless priv.conf allows it
// (admin-routes, wireguard-routes), not wide enough or placed to take over the host's own traffic.
func TestWireGuardRouteGuard(t *testing.T) {
	f, h := newWGFixture(t)
	mustWrite(t, filepath.Join(f.base, "etc-wg", "resolv.conf"), "nameserver 198.51.100.53\nnameserver 2001:db8:53::53\n")
	h.set(func() {
		h.gateway = "192.0.2.1"
		h.ifs["em0"] = &wgIf{addrs: []string{"192.0.2.10/24", "2001:db8:1::10/64"}, up: true}
	})
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	req := func(routes, allowed []netip.Prefix) wireguard.ApplyReq {
		q := serverApply(pubOf("x"))
		q.Routes, q.Peers[0].AllowedIPs = routes, allowed
		return q
	}
	for _, b := range []struct {
		what            string
		routes, allowed []netip.Prefix
	}{
		{"the lower half of IPv4", pfx("0.0.0.0/1"), pfx("0.0.0.0/1")},
		{"the upper half of IPv4", pfx("128.0.0.0/1"), pfx("128.0.0.0/1")},
		{"half of IPv6", pfx("::/1"), pfx("::/1")},
		{"a /7", pfx("10.0.0.0/7"), pfx("10.0.0.0/7")},
		{"a /12 of IPv6", pfx("2000::/12"), pfx("2000::/12")},
		{"a resolver", pfx("198.51.100.53/32"), pfx("198.51.100.53/32")},
		{"an IPv6 resolver", pfx("2001:db8:53::/48"), pfx("2001:db8:53::/48")},
		{"the default gateway", pfx("192.0.2.0/28"), pfx("192.0.2.0/28")},
		{"an address of the host", pfx("2001:db8:1::/64"), pfx("2001:db8:1::/64")},
		{"loopback", pfx("127.0.0.0/8"), pfx("127.0.0.0/8")},
		{"IPv6 loopback", pfx("::1/128"), pfx("::1/128")},
		{"link-local", pfx("169.254.0.0/16"), pfx("169.254.0.0/16")},
		{"IPv6 link-local", pfx("fe80::/64"), pfx("fe80::/64")},
		{"multicast", pfx("239.0.0.0/8"), pfx("239.0.0.0/8")},
		{"not inside an allowed IP", pfx("10.20.0.0/24"), pfx("10.99.0.2/32")},
		{"wider than the allowed IP", pfx("10.20.0.0/16"), pfx("10.20.0.0/24")},
	} {
		_, err := c.WGApply(adminCtx, req(b.routes, b.allowed))
		if !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("%s: %v, want forbidden", b.what, err)
		}
	}
	var routes []string
	h.set(func() { routes = slices.Clone(h.routes) })
	if len(routes) != 0 {
		t.Fatalf("a refused route was added: %v", routes)
	}
	// a tunnel network and the network of the far side, covered by the peer
	if _, err := c.WGApply(adminCtx, req(pfx("10.99.0.0/24", "10.20.0.0/16"), pfx("10.99.0.0/24", "10.20.0.0/16"))); err != nil {
		t.Fatalf("a normal tunnel: %v", err)
	}
	h.set(func() { routes = slices.Clone(h.routes) })
	if !slices.Contains(routes, "-n add -inet 10.20.0.0/16 -interface wg-office") {
		t.Errorf("routes %v", routes)
	}
}

// What priv.conf allows: wireguard-routes for listed networks, admin-routes for every route (with the admin
// assertion); coverage by the peers is needed either way.
func TestWireGuardRouteGuardAllowances(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config)
		ok   []string
		bad  []string
	}{
		{"wireguard-routes", func(c *Config) { c.WireGuardRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")} }, []string{"0.0.0.0/1", "10.0.0.0/7"}, []string{"128.0.0.0/1"}},
		{"admin-routes", func(c *Config) { c.Admin.Routes = true }, []string{"0.0.0.0/1", "128.0.0.0/1"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newWGFixture(t)
			cfg := f.local.cfg
			tc.set(&cfg)
			l, err := NewLocal(cfg, f.local.d, WithoutChown())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
				t.Fatal(err)
			}
			for _, r := range tc.ok {
				q := serverApply(pubOf("x"))
				q.Routes = []netip.Prefix{netip.MustParsePrefix(r)}
				q.Peers[0].AllowedIPs = q.Routes
				if _, err := l.WGApply(adminCtx, q); err != nil {
					t.Errorf("%s: %v", r, err)
				}
				q.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")}
				if _, err := l.WGApply(adminCtx, q); !api.IsCode(err, api.CodeForbidden) {
					t.Errorf("%s without a peer that allows it: %v", r, err)
				}
			}
			for _, r := range tc.bad {
				q := serverApply(pubOf("x"))
				q.Routes = []netip.Prefix{netip.MustParsePrefix(r)}
				q.Peers[0].AllowedIPs = q.Routes
				if _, err := l.WGApply(adminCtx, q); !api.IsCode(err, api.CodeForbidden) {
					t.Errorf("%s: %v", r, err)
				}
			}
		})
	}
}

// A rename moves the key directory of an object inside the helper's directory and nowhere else; a second call is
// a no-op, a name in use and a name that is not a name are refused.
func TestWireGuardRenameMovesTheKeyDirectory(t *testing.T) {
	f, h := newWGFixture(t)
	c := f.client
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "office"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "taken"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []wireguard.RenameReq{{From: "office", To: "../escape"}, {From: "../office", To: "hq"}, {From: "office", To: "office"}, {From: "office", To: "Bad Name"}} {
		if err := c.WGRename(adminCtx, bad); !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if err := c.WGRename(adminCtx, wireguard.RenameReq{From: "office", To: "taken"}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Errorf("a name in use: %v", err)
	}
	if err := c.WGRename(adminCtx, wireguard.RenameReq{From: "office", To: "hq"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "office")); !os.IsNotExist(err) {
		t.Errorf("the old directory is still there: %v", err)
	}
	if mode(t, filepath.Join(h.dir, "hq")) != 0o700 {
		t.Errorf("the mode of the moved directory changed")
	}
	// again, and for an object that never had keys
	if err := c.WGRename(adminCtx, wireguard.RenameReq{From: "office", To: "hq"}); err != nil {
		t.Errorf("a second rename: %v", err)
	}
	if err := c.WGRename(adminCtx, wireguard.RenameReq{From: "ghost", To: "spirit"}); err != nil {
		t.Errorf("an object without keys: %v", err)
	}
	// the public key is the same under the new name
	r, err := c.WGKeys(adminCtx, wireguard.KeysReq{Name: "hq"})
	if err != nil || r.PublicKey == "" {
		t.Errorf("keys of the renamed object: %+v %v", r, err)
	}
}
