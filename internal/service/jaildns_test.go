package service_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// refusing is the helper's file operations refusing to write one path: what it answers when the jail made that path a
// symlink (out of its root or not), since it replaces only regular files.
type refusing struct {
	service.FS
	path string
	on   *atomic.Bool
}

func (r refusing) WriteAtomic(ctx context.Context, p string, b []byte) error {
	if p == r.path && r.on.Load() {
		return api.Errorf(api.CodeForbidden, "%q exists and is not a regular file", p)
	}
	return r.FS.WriteAtomic(ctx, p, b)
}

func resolvOf(jail string) string {
	return "/jailops/projects/alpha/jails/" + jail + "/root/etc/resolv.conf"
}

func setHostResolv(t *testing.T, e *dtest.Env, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(e.Host.Etc, "resolv.conf"), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// createJail creates a jail and starts it.
func createJail(t *testing.T, e *dtest.Env, s *service.Service, name string) {
	t.Helper()
	op, err := s.CreateJail(as(globalAdmin, dtest.SeedProject), dtest.WebJail(name))
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create %s: %+v\n%s", name, got, e.Log())
	}
	jailAction(t, s, name, "start")
}

func jailAction(t *testing.T, s *service.Service, name, action string) {
	t.Helper()
	op, err := s.JailAction(as(globalAdmin, dtest.SeedProject), name, api.JailAction{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("%s %s: %+v", action, name, got)
	}
}

// A network without dns hands the jails the host's own nameservers; when the host resolves only through loopback,
// the gateway, with what the administrator has to do. A change of the network's dns reaches the running jails at
// once, not a stopped one, not a jail that keeps its own file, and not a file the helper refuses to replace.
func TestJailDNSDefaultsAndLiveChange(t *testing.T) {
	var linked atomic.Bool
	e := dtest.New(t, dtest.Options{Clients: func(c *daemon.Clients) { c.Files = refusing{c.Files, resolvOf("link"), &linked} }})
	e.Seed()
	s := e.D.Service()
	ctx := as(globalAdmin, "")
	for _, j := range []string{"web", "db", "own", "link"} {
		createJail(t, e, s, j)
	}
	jailAction(t, s, "db", "stop")
	linked.Store(true) // root in the jail replaced its resolv.conf with a symlink
	if got := e.File(resolvOf("web")); !strings.Contains(got, "nameserver 198.51.100.1\n") || strings.Contains(got, "search") {
		t.Fatalf("the host's nameserver, without its search domains: %q", got)
	}
	n, err := s.GetNetwork(ctx, "lan")
	if err != nil || n.Status.DNS == nil || n.Status.DNS.Source != api.DNSFromHost || !slices.Equal(n.Status.DNS.Nameservers, []string{"198.51.100.1"}) {
		t.Fatalf("%+v %v", n.Status.DNS, err)
	}

	// a host that resolves through a local cache: the jails ask the gateway
	setHostResolv(t, e, "# local cache\nnameserver 127.0.0.1\nnameserver ::1\n")
	n, _ = s.GetNetwork(ctx, "lan")
	d := n.Status.DNS
	if d.Source != api.DNSFromGateway || !slices.Equal(d.Nameservers, []string{"10.20.0.1"}) ||
		!strings.Contains(d.Advice, "interface: 10.20.0.1") || !strings.Contains(d.Advice, "access-control: 10.20.0.0/24 allow") ||
		!strings.Contains(d.Advice, "port 53") {
		t.Fatalf("%+v", d)
	}
	if got := e.File(resolvOf("web")); !strings.Contains(got, "198.51.100.1") {
		t.Fatalf("a change of the host's resolv.conf reaches a jail only when it starts: %q", got)
	}
	jailAction(t, s, "web", "restart")
	if got := e.File(resolvOf("web")); !strings.Contains(got, "nameserver 10.20.0.1\n") {
		t.Fatalf("the gateway after a restart: %q", got)
	}

	// the owner of "own" runs his own resolver
	mine := "nameserver 127.0.0.1\n"
	e.Files.Put(resolvOf("own"), []byte(mine))
	stopped := e.File(resolvOf("db"))

	n, err = s.PatchNetwork(ctx, "lan", map[string]any{"spec": map[string]any{"dns": []any{"192.0.2.53"}}}, service.AnyGeneration)
	if err != nil {
		t.Fatal(err)
	}
	d = n.Status.DNS
	if d.Source != api.DNSFromNetwork || !slices.Equal(d.Updated, []string{"alpha/web"}) || len(d.NotUpdated) != 2 ||
		!strings.Contains(d.NotUpdated[0], "alpha/link") || !strings.Contains(d.NotUpdated[1], "alpha/own: its resolv.conf is its own") {
		t.Fatalf("%+v", d)
	}
	if got := e.File(resolvOf("web")); !strings.Contains(got, "nameserver 192.0.2.53\n") || strings.Contains(got, "10.20.0.1") {
		t.Fatalf("the running jail: %q", got)
	}
	if e.File(resolvOf("db")) != stopped || e.File(resolvOf("own")) != mine {
		t.Fatalf("the stopped jail or the one that keeps its file changed: %q %q", e.File(resolvOf("db")), e.File(resolvOf("own")))
	}
	jailAction(t, s, "db", "start")
	jailAction(t, s, "own", "restart")
	if !strings.Contains(e.File(resolvOf("db")), "nameserver 192.0.2.53\n") || e.File(resolvOf("own")) != mine {
		t.Fatalf("at the next start: %q %q", e.File(resolvOf("db")), e.File(resolvOf("own")))
	}
}

// doctor (network.dns) probes a gateway the jails ask once a jail on the network runs: a warning with what to do
// while nothing answers there, OK once a resolver does.
func TestDoctorProbesTheGatewayResolver(t *testing.T) {
	e, s := newEnv(t)
	createJail(t, e, s, "web")
	check := func() api.DoctorCheck {
		t.Helper()
		for _, c := range s.Doctor(as(globalAdmin, "")).Checks {
			if c.Name == "network.dns" {
				return c
			}
		}
		t.Fatal("no network.dns check")
		return api.DoctorCheck{}
	}
	if c := check(); c.Status != api.DoctorOK || !strings.Contains(c.Message, "lan: 198.51.100.1 (the host's nameservers") {
		t.Fatalf("%+v", c)
	}
	setHostResolv(t, e, "nameserver 127.0.0.1\n")
	if c := check(); c.Status != api.DoctorWarn || !strings.Contains(c.Message, "cannot be reached") || !strings.Contains(c.Hint, "interface: 10.20.0.1") {
		t.Fatalf("%+v", c)
	}
	var asked string
	answer := func(rcode byte) {
		e.DialFn = func(_ context.Context, network, addr string) (net.Conn, error) {
			asked = network + " " + addr
			a, b := net.Pipe()
			go func() {
				q := make([]byte, 512)
				n, err := b.Read(q)
				if err != nil || n < 12 {
					return
				}
				r := append([]byte{q[0], q[1], 0x81, 0x80 | rcode}, q[4:n]...)
				_, _ = b.Write(r)
			}()
			return a, nil
		}
	}
	answer(5)
	if c := check(); c.Status != api.DoctorWarn || !strings.Contains(c.Message, "refuses the query") || asked != "udp 10.20.0.1:53" {
		t.Fatalf("%+v %s", c, asked)
	}
	answer(0)
	if c := check(); c.Status != api.DoctorOK || !strings.Contains(c.Message, "lan: the gateway 10.20.0.1 answers DNS") {
		t.Fatalf("%+v", c)
	}
	setHostResolv(t, e, "nameserver fe80::1%vtnet0\n")
	if c := check(); c.Status != api.DoctorWarn || !strings.Contains(c.Message, "no nameserver") {
		t.Fatalf("a link-local nameserver only is neither usable by a jail nor loopback: %+v", c)
	}
}
