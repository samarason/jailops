package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/internal/ipam"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// A server tunnel, a peer enrolled on it and a client joined with the peer's token: the token carries the peer's
// keys once, and no private or preshared key appears in any answer, the audit log, the events or the daemon's log.
func TestWireGuardThroughTheAPI(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	g := e.Global()
	srv, err := g.WireGuard().Create(c, api.WireGuard{Metadata: api.ObjectMeta{Name: "office"}, Spec: api.WireGuardSpec{
		Mode: api.WireGuardServer, Address: []string{"10.99.0.1/24"}, Networks: []string{"lan"}, Endpoint: "vpn.example.com:51820"}})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Spec.Interface != "wg-office" || srv.Spec.ListenPort != 51820 || len(srv.Spec.AllowedIPs) != 1 || srv.Spec.AllowedIPs[0] != "10.99.0.0/24" {
		t.Fatalf("defaults %+v", srv.Spec)
	}
	if !srv.Status.Up || !wireguard.ValidKey(srv.Status.PublicKey) || srv.Status.FirewallRule != "pass in on $ext_if proto udp to port 51820" {
		t.Fatalf("status %+v", srv.Status)
	}
	if rs := pfRules(e.PF, "jailops/wg.office"); !strings.Contains(rs, "pass in quick on wg-office inet from 10.99.0.0/24 to 10.20.0.0/24") {
		t.Errorf("anchor:\n%s", rs)
	}
	// an operator reads, an admin changes
	op := e.Client(api.PermOperator)
	if _, err := op.WireGuard().Get(c, "office"); err != nil {
		t.Fatalf("an operator cannot read: %v", err)
	}
	if _, err := op.WireGuard().AddPeer(c, "office", api.WireGuardPeerAdd{Name: "x"}); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an operator enrolled a peer: %v", err)
	}
	if _, err := e.Client(api.PermReadonly).WireGuard().Get(c, "office"); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("a reader saw the tunnel: %v", err)
	}
	p, err := g.WireGuard().AddPeer(c, "office", api.WireGuardPeerAdd{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Peer.AllowedIPs[0] != "10.99.0.2/32" || p.Warning == "" || !strings.Contains(p.Config, "PrivateKey = ") {
		t.Fatalf("%+v", p)
	}
	tok, err := wireguard.DecodeToken(p.Token)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ServerPublicKey != srv.Status.PublicKey || tok.Endpoint != "vpn.example.com:51820" || strings.Join(tok.AllowedIPs, ",") != "10.99.0.0/24,10.20.0.0/24" || tok.Keepalive != 25 {
		t.Fatalf("token %+v", tok)
	}
	p2, err := g.WireGuard().AddPeer(c, "office", api.WireGuardPeerAdd{Name: "phone"})
	if err != nil || p2.Peer.AllowedIPs[0] != "10.99.0.3/32" {
		t.Fatalf("%+v %v", p2, err)
	}
	if _, err := g.WireGuard().AddPeer(c, "office", api.WireGuardPeerAdd{Name: "laptop"}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("a second laptop: %v", err)
	}
	if conf, ok := e.WG.Iface("office"); !ok || len(conf.Peers) != 2 {
		t.Fatalf("the peers were not applied: %+v", conf)
	}
	// the client end, on the same daemon under another name, routed elsewhere
	cl, err := g.WireGuard().Join(c, api.WireGuardJoin{Token: p.Token, Name: "home", Endpoint: "127.0.0.1:51820",
		Address: []string{"10.98.0.2/32"}, AllowedIPs: []string{"10.98.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if cl.Spec.Mode != api.WireGuardClient || cl.Spec.PeerPublicKey != srv.Status.PublicKey || cl.Spec.Keepalive != 25 || cl.Spec.Interface != "wg-home" {
		t.Fatalf("client %+v", cl.Spec)
	}
	if _, err := g.WireGuard().Join(c, api.WireGuardJoin{Token: "jwg1.bm90IGpzb24"}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a broken token: %v", err)
	}
	if _, err := g.WireGuard().Join(c, api.WireGuardJoin{Token: p.Token, Name: "home"}); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("joined twice: %v", err)
	}
	if _, err := g.WireGuard().Down(c, "home"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.WG.Iface("home"); ok {
		t.Fatal("down kept the interface")
	}
	if _, err := g.WireGuard().Up(c, "home"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.WG.Iface("home"); !ok {
		t.Fatal("up made no interface")
	}
	k, err := g.WireGuard().RotateKeys(c, "office")
	if err != nil || k.PublicKey == srv.Status.PublicKey || k.Warning == "" {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := g.WireGuard().RemovePeer(c, "office", "laptop"); err != nil {
		t.Fatal(err)
	}
	// everything that can be read back
	var all strings.Builder
	for _, path := range []string{"/api/v1/wireguard", "/api/v1/wireguard/office", "/api/v1/wireguard/home", "/api/v1/audit?limit=500", "/api/v1/operations", "/api/v1/doctor"} {
		code, body := e.Raw("GET", path, e.Token(api.PermAdmin), "")
		if code != 200 {
			t.Fatalf("%s: %d %s", path, code, body)
		}
		all.WriteString(body)
	}
	entries, _ := g.Audit(c, 500)
	b, _ := json.Marshal(entries)
	all.Write(b)
	readback, logs := all.String(), e.Log()
	secrets := append(e.WG.Secrets(), tok.PrivateKey, tok.PresharedKey)
	for _, s := range secrets {
		if strings.Contains(readback, s) {
			t.Errorf("a secret appears in what the API returns")
		}
		if strings.Contains(logs, s) {
			t.Errorf("a secret appears in the daemon's log")
		}
		if strings.Contains(strings.Join(e.WG.Calls(), "\n"), s) {
			t.Errorf("a secret appears in what the helper was asked")
		}
	}
	// the token is not in the audit entry either, which names the object only
	var sawPeer bool
	for _, en := range entries {
		if en.Action == "POST /api/v1/wireguard/{name}/peers" && en.Resource == "/api/v1/wireguard/office/peers/laptop" {
			sawPeer = true
		}
	}
	if !sawPeer {
		t.Errorf("the enrollment was not audited: %+v", entries)
	}
	if err := g.WireGuard().Delete(c, "office"); err != nil {
		t.Fatal(err)
	}
	if e.WG.HasKeys("office") {
		t.Error("delete kept the keys")
	}
	if rs := pfRules(e.PF, "jailops/wg.office"); rs != "" {
		t.Errorf("the anchor stayed:\n%s", rs)
	}
}

func TestWireGuardValidation(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	g := e.Global()
	mk := func(name string, s api.WireGuardSpec) error {
		_, err := g.WireGuard().Create(c, api.WireGuard{Metadata: api.ObjectMeta{Name: name}, Spec: s})
		return err
	}
	srv := func() api.WireGuardSpec {
		return api.WireGuardSpec{Mode: api.WireGuardServer, Address: []string{"10.99.0.1/24"}}
	}
	if err := mk("office", srv()); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for what, c := range map[string]struct {
		name string
		spec func(*api.WireGuardSpec)
		code api.Code
	}{
		"same port":           {"b", func(s *api.WireGuardSpec) { s.Address = []string{"10.98.0.1/24"} }, api.CodeAlreadyExists},
		"overlapping address": {"b", func(s *api.WireGuardSpec) { s.ListenPort = 51821; s.Address = []string{"10.99.0.9/25"} }, api.CodeIPConflict},
		"unknown network": {"b", func(s *api.WireGuardSpec) {
			s.ListenPort = 51821
			s.Address = []string{"10.98.0.1/24"}
			s.Networks = []string{"nope"}
		}, api.CodeNotFound},
		"bad interface":        {"b", func(s *api.WireGuardSpec) { s.Interface = "em0" }, api.CodeInvalid},
		"name too long":        {"abcdefghijklmn", func(s *api.WireGuardSpec) {}, api.CodeInvalid},
		"no address":           {"b", func(s *api.WireGuardSpec) { s.Address = nil }, api.CodeInvalid},
		"two ipv4 addresses":   {"b", func(s *api.WireGuardSpec) { s.Address = []string{"10.97.0.1/24", "10.96.0.1/24"} }, api.CodeInvalid},
		"bad mode":             {"b", func(s *api.WireGuardSpec) { s.Mode = "relay" }, api.CodeInvalid},
		"client without token": {"b", func(s *api.WireGuardSpec) { s.Mode = api.WireGuardClient; s.PeerPublicKey = key }, api.CodeInvalid},
		"bad endpoint":         {"b", func(s *api.WireGuardSpec) { s.Endpoint = "no port" }, api.CodeInvalid},
		"bad peer key": {"b", func(s *api.WireGuardSpec) {
			s.ListenPort = 51821
			s.Address = []string{"10.98.0.1/24"}
			s.Peers = []api.WireGuardPeer{{Name: "p", PublicKey: "short", AllowedIPs: []string{"10.98.0.2/32"}}}
		}, api.CodeInvalid},
		"pool not a network": {"b", func(s *api.WireGuardSpec) {
			s.ListenPort = 51821
			s.Address = []string{"10.98.0.1/24"}
			s.AllowedIPs = []string{"10.98.0.1/24"}
		}, api.CodeInvalid},
	} {
		s := srv()
		c.spec(&s)
		if err := mk(c.name, s); !api.IsCode(err, c.code) {
			t.Errorf("%s: want %s, got %v", what, c.code, err)
		}
	}
	// the pool runs out
	if err := mk("tiny", api.WireGuardSpec{Mode: api.WireGuardServer, Address: []string{"10.95.0.1/30"}, ListenPort: 51822}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.WireGuard().AddPeer(c, "tiny", api.WireGuardPeerAdd{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.WireGuard().AddPeer(c, "tiny", api.WireGuardPeerAdd{Name: "two"}); !api.IsCode(err, api.CodePoolExhausted) {
		t.Fatalf("a full pool: %v", err)
	}
	if _, err := g.WireGuard().AddPeer(c, "tiny", api.WireGuardPeerAdd{Name: "three", Address: []string{"10.95.0.1"}}); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("the server's own address: %v", err)
	}
}

func pfRules(pf *pfctl.Fake, anchor string) string {
	s, _ := pf.Read(context.Background(), anchor)
	return s
}

func wgDoctorCheck(t *testing.T, e interface {
	Raw(method, path, token, body string) (int, string)
	Token(api.Permission) string
}, name string) api.DoctorCheck {
	t.Helper()
	code, body := e.Raw("GET", "/api/v1/doctor", e.Token(api.PermAdmin), "")
	if code != 200 {
		t.Fatalf("doctor: %d %s", code, body)
	}
	var resp api.Response
	var rep api.DoctorReport
	if err := json.Unmarshal([]byte(body), &resp); err != nil || json.Unmarshal(resp.Metadata, &rep) != nil {
		t.Fatalf("doctor: %s", body)
	}
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return api.DoctorCheck{}
}

// net.descriptions lists interfaces of JailOps whose description is missing or old; a reconcile pass fixes them.
// wireguard.tools appears only on a host with a tunnel and says how to install the tools.
func TestDoctorDescriptionsAndWireGuardTools(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	web := mustJail(t, e, "web")
	if so, err := e.Admin.Jails().Start(c, "web"); err != nil {
		t.Fatal(err)
	} else if _, err := so.Wait(c); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(c)
	if ch := wgDoctorCheck(t, e, "net.descriptions"); ch.Status != api.DoctorOK {
		t.Fatalf("%+v", ch)
	}
	if ch := wgDoctorCheck(t, e, "wireguard.tools"); ch.Name != "" {
		t.Fatalf("a host without a tunnel got %+v", ch)
	}
	hostEnd := ipam.EpairName(web.Metadata.UUID, 0)
	// (the start hook makes the epair on a real host)
	if _, _, err := e.Net.EpairCreate(c, strings.TrimSuffix(hostEnd, "a")); err != nil {
		t.Fatal(err)
	}
	_ = e.Net.SetDescription(c, hostEnd, "jailops jail=alpha/web net=lan (host side)")
	// A pass of the daemon's own reconciler (kicked by the jail create) may land between the damage and the check and
	// repair it, which is slow machines only (the race detector): damage it again, the window is narrow each time.
	var ch api.DoctorCheck
	for try := 0; try < 20; try++ {
		_ = e.Net.SetDescription(c, hostEnd, "") // clearing leaves the bare marker: made, not described
		if ch = wgDoctorCheck(t, e, "net.descriptions"); ch.Status == api.DoctorWarn {
			break
		}
	}
	if ch.Status != api.DoctorWarn || !strings.Contains(ch.Message, hostEnd+` ("jailops managed")`) {
		t.Fatalf("%+v", ch)
	}
	_ = e.Net.SetDescription(c, hostEnd, "jailops jail=alpha/web net=lan (host side)")
	e.D.Reconciler().Pass(c)
	if ch := wgDoctorCheck(t, e, "net.descriptions"); ch.Status != api.DoctorOK {
		t.Fatalf("after a pass: %+v", ch)
	}
	if _, err := e.Global().WireGuard().Create(c, api.WireGuard{Metadata: api.ObjectMeta{Name: "office"},
		Spec: api.WireGuardSpec{Mode: api.WireGuardServer, Address: []string{"10.99.0.1/24"}}}); err != nil {
		t.Fatal(err)
	}
	if ch := wgDoctorCheck(t, e, "wireguard.tools"); ch.Status != api.DoctorOK {
		t.Fatalf("%+v", ch)
	}
	e.WG.SetTools(wireguard.ToolsRes{})
	if ch := wgDoctorCheck(t, e, "wireguard.tools"); ch.Status != api.DoctorWarn || ch.Hint != "pkg install wireguard-tools" {
		t.Fatalf("%+v", ch)
	}
	if ch := wgDoctorCheck(t, e, "wireguard.firewall"); ch.Status == api.DoctorOK {
		t.Fatalf("%+v", ch)
	}
}
