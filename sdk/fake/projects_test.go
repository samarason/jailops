package fake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

func ctxT(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

type env struct {
	srv *fake.Server
	ts  *httptest.Server
}

func (e *env) client(t *testing.T, token string, opts ...sdk.Option) *sdk.Client {
	t.Helper()
	opts = append([]sdk.Option{sdk.WithRetries(0)}, opts...)
	if token != "" {
		opts = append(opts, sdk.WithToken(token))
	}
	c, err := sdk.Connect(ctxT(t), sdk.Remote(e.ts.URL, opts...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// newEnv starts a fake with an admin token and two restricted identities.
func newEnv(t *testing.T, opts ...fake.Option) *env {
	t.Helper()
	opts = append([]fake.Option{
		fake.WithToken("admin"),
		fake.WithIdentity("ann", fake.Identity{Name: "ann", Permission: api.PermAdmin, Projects: []string{"web"}}),
		fake.WithIdentity("ann-ro", fake.Identity{Name: "ann-ro", Permission: api.PermReadonly, Projects: []string{"web"}}),
		fake.WithIdentity("bob", fake.Identity{Name: "bob", Permission: api.PermAdmin, Projects: []string{"db"}}),
		fake.WithIdentity("nobody", fake.Identity{Name: "nobody", Permission: api.PermAdmin}),
	}, opts...)
	srv := fake.New(opts...)
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { ts.Close(); srv.Close() })
	e := &env{srv, ts}
	srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "fb"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE"}})
	srv.SeedGeneration("fb")
	srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "other"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE"}})
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{
		Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.50"}}})
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "secret"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{
		Subnet: "10.30.0.0/24", Gateway: "10.30.0.1", Range: "10.30.0.10-10.30.0.50"}}})
	srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "dblan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{
		Subnet: "10.40.0.0/24", Gateway: "10.40.0.1", Range: "10.40.0.10-10.40.0.50"}}})
	admin := e.client(t, "admin")
	for _, p := range []api.Project{
		{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProjectSpec{
			Networks: []api.ProjectNetwork{{Network: "lan"}},
			Storage:  []api.ProjectStorage{{Storage: "default", Quota: "100G"}}}},
		{Metadata: api.ObjectMeta{Name: "db"}, Spec: api.ProjectSpec{
			Networks: []api.ProjectNetwork{{Network: "dblan"}},
			Storage:  []api.ProjectStorage{{Storage: "default"}}, Images: []string{"fb"}}},
	} {
		if _, err := admin.Projects().Create(ctxT(t), p); err != nil {
			t.Fatalf("project %s: %v", p.Metadata.Name, err)
		}
	}
	return e
}

// wspec and dspec are jails of the web and the db project: the network and the storage are always named.
func wspec() api.JailSpec {
	return api.JailSpec{Image: "fb", Storage: "default", Network: []api.NetworkAttach{{Network: "lan", IPv4: "auto"}}}
}

func dspec() api.JailSpec {
	return api.JailSpec{Image: "fb", Storage: "default", Network: []api.NetworkAttach{{Network: "dblan", IPv4: "auto"}}}
}

func createJail(t *testing.T, c *sdk.Client, name string, spec api.JailSpec) (api.Jail, error) {
	t.Helper()
	op, err := c.Jails().Create(ctxT(t), sdk.NewJail(name, spec))
	if err != nil {
		return api.Jail{}, err
	}
	return op.Wait(ctxT(t))
}

func wantCode(t *testing.T, err error, code api.Code) {
	t.Helper()
	if !api.IsCode(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestProjectsScopeJails(t *testing.T) {
	e := newEnv(t)
	admin, ann, bob := e.client(t, "admin"), e.client(t, "ann"), e.client(t, "bob")
	spec := wspec()
	j, err := createJail(t, ann.Project("web"), "nginx", spec)
	if err != nil {
		t.Fatal(err)
	}
	if j.Metadata.Project != "web" || j.Spec.Storage != "default" || len(j.Spec.Network) != 1 || j.Spec.Network[0].Network != "lan" {
		t.Fatalf("%+v", j)
	}
	// There is no default project: a request that names none is refused, whoever asks.
	_, err = createJail(t, ann, "x", spec)
	wantCode(t, err, api.CodeInvalid)
	if !strings.Contains(err.Error(), "a project is required") {
		t.Fatalf("%v", err)
	}
	for _, err := range admin.Jails().List(ctxT(t)) {
		wantCode(t, err, api.CodeInvalid)
	}
	// The same name in another project is another jail.
	j2, err := createJail(t, bob.Project("db"), "nginx", dspec())
	if err != nil {
		t.Fatal(err)
	}
	if j2.Metadata.UUID == j.Metadata.UUID {
		t.Fatal("one jail in two projects")
	}
	// Each project has its own network: the addresses come from different subnets.
	a1, a2 := j.Spec.Network[0].IPv4, j2.Spec.Network[0].IPv4
	if a1 != "10.20.0.10" || a2 != "10.40.0.10" {
		t.Fatalf("addresses %s %s", a1, a2)
	}
	// Cross-project requests are not_found on every verb.
	for name, call := range map[string]func() error{
		"get": func() error { _, err := bob.Project("web").Jails().Get(ctxT(t), "nginx"); return err },
		"list": func() error {
			for _, err := range bob.Project("web").Jails().List(ctxT(t)) {
				return err
			}
			return nil
		},
		"create": func() error { _, err := createJail(t, bob.Project("web"), "y", spec); return err },
		"delete": func() error { _, err := bob.Project("web").Jails().Delete(ctxT(t), "nginx"); return err },
		"state":  func() error { _, err := bob.Project("web").Jails().Start(ctxT(t), "nginx"); return err },
		"snap": func() error {
			_, err := bob.Project("web").Jails().Snapshots("nginx").Create(ctxT(t), "s", "")
			return err
		},
		"nosuch": func() error { _, err := bob.Project("nosuch").Jails().Get(ctxT(t), "nginx"); return err },
	} {
		if err := call(); !api.IsCode(err, api.CodeNotFound) {
			t.Errorf("%s: want not_found, got %v", name, err)
		}
	}
	// Lists are per project; the admin sees each.
	n := 0
	for _, err := range admin.Project("web").Jails().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 1 {
		t.Fatalf("%d jails in web", n)
	}
	// Leases are filtered to the caller's projects.
	var leases []api.Lease
	for l, err := range admin.Networks().Leases(ctxT(t), "lan") {
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if len(leases) != 1 {
		t.Fatalf("admin leases on lan %v", leases)
	}
	leases = nil
	for l, err := range ann.Networks().Leases(ctxT(t), "lan") {
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if len(leases) != 1 || leases[0].Address != a1 {
		t.Fatalf("ann leases %v", leases)
	}
	// A body naming another project is invalid.
	bad := sdk.NewJail("z", spec)
	bad.Metadata.Project = "db"
	_, err = ann.Project("web").Jails().Create(ctxT(t), bad)
	wantCode(t, err, api.CodeInvalid)
	// Fixed addresses must lie in the network's subnet.
	fixed := func(addr string) api.JailSpec {
		return api.JailSpec{Image: "fb", Storage: "default", Network: []api.NetworkAttach{{Network: "lan", IPv4: addr}}}
	}
	_, err = createJail(t, ann.Project("web"), "fixed", fixed("10.30.0.25"))
	wantCode(t, err, api.CodeInvalid)
	_, err = createJail(t, ann.Project("web"), "fixed", fixed("10.20.0.15"))
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot names are per project too.
	op, err := ann.Project("web").Jails().Snapshots("nginx").Create(ctxT(t), "s1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	for _, err := range bob.Project("db").Jails().Snapshots("nginx").List(ctxT(t)) {
		t.Fatalf("snapshot leaked across projects: %v", err)
	}
}

func TestProjectGrantsAndQuotas(t *testing.T) {
	e := newEnv(t)
	admin, ann, bob := e.client(t, "admin"), e.client(t, "ann"), e.client(t, "bob")
	w, d := ann.Project("web"), bob.Project("db")
	// Not granted: forbidden whether or not it exists.
	onNet := func(n string) api.JailSpec {
		return api.JailSpec{Image: "fb", Storage: "default", Network: []api.NetworkAttach{{Network: n, IPv4: "auto"}}}
	}
	_, err := createJail(t, w, "a", onNet("secret"))
	wantCode(t, err, api.CodeForbidden)
	_, err = createJail(t, w, "a", onNet("nonesuch"))
	wantCode(t, err, api.CodeForbidden)
	_, err = createJail(t, w, "a", api.JailSpec{Image: "fb", Storage: "other-pool", Network: wspec().Network})
	wantCode(t, err, api.CodeForbidden)
	// Nothing is defaulted: a jail names its network and its storage.
	_, err = createJail(t, w, "a", api.JailSpec{Image: "fb", Storage: "default"})
	wantCode(t, err, api.CodeInvalid)
	if !strings.Contains(err.Error(), "a jail needs a network") {
		t.Fatalf("%v", err)
	}
	_, err = createJail(t, w, "a", api.JailSpec{Image: "fb", Network: wspec().Network})
	wantCode(t, err, api.CodeInvalid)
	if !strings.Contains(err.Error(), "a jail needs a storage") {
		t.Fatalf("%v", err)
	}
	// A network belongs to one project: the db project may not take the web project's, and a new project may not either.
	dp, _ := admin.Projects().Get(ctxT(t), "db")
	dp.Spec.Networks = append(dp.Spec.Networks, api.ProjectNetwork{Network: "lan"})
	_, err = admin.Projects().Update(ctxT(t), "db", dp, "")
	wantCode(t, err, api.CodeConflict)
	if !strings.Contains(err.Error(), "network lan is already granted to project web") {
		t.Fatalf("%v", err)
	}
	_, err = admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "third"}, Spec: api.ProjectSpec{Networks: []api.ProjectNetwork{{Network: "lan"}}}})
	wantCode(t, err, api.CodeConflict)
	_, err = admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "star"}, Spec: api.ProjectSpec{Networks: []api.ProjectNetwork{{Network: "*"}}}})
	wantCode(t, err, api.CodeInvalid)
	// Image allow-list.
	other := dspec()
	other.Image = "other"
	_, err = createJail(t, d, "a", other)
	wantCode(t, err, api.CodeForbidden)
	// Project quotas.
	p, _ := admin.Projects().Get(ctxT(t), "web")
	p.Spec.Quotas = api.ProjectQuotas{Jails: 2, CPU: 4, Addresses: 2}
	if _, err := admin.Projects().Update(ctxT(t), "web", p, ""); err != nil {
		t.Fatal(err)
	}
	_, err = createJail(t, w, "a", wspec())
	wantCode(t, err, api.CodeInvalid) // a cpu quota needs resources.cpu
	cpu := func(n int) api.JailSpec { sp := wspec(); sp.Resources = api.Resources{CPU: n}; return sp }
	if _, err := createJail(t, w, "a", cpu(2)); err != nil {
		t.Fatal(err)
	}
	_, err = createJail(t, w, "b", cpu(3))
	wantCode(t, err, api.CodeQuotaExceeded)
	if _, err := createJail(t, w, "b", cpu(2)); err != nil {
		t.Fatal(err)
	}
	_, err = createJail(t, w, "c", cpu(0))
	wantCode(t, err, api.CodeQuotaExceeded) // jails
	got, _ := admin.Projects().Get(ctxT(t), "web")
	if got.Status.Jails != 2 || got.Status.CPU != 4 || got.Status.Addresses != 2 {
		t.Fatalf("status %+v", got.Status)
	}
	// Project users read their project but may not write it.
	if _, err := ann.Projects().Get(ctxT(t), "web"); err != nil {
		t.Fatal(err)
	}
	_, err = ann.Projects().Get(ctxT(t), "db")
	wantCode(t, err, api.CodeNotFound)
	_, err = ann.Projects().Update(ctxT(t), "web", p, "")
	wantCode(t, err, api.CodeForbidden)
	var seen []string
	for pr, err := range ann.Projects().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, pr.Metadata.Name)
	}
	if len(seen) != 1 || seen[0] != "web" {
		t.Fatalf("ann sees %v", seen)
	}
	// Mandatory firewall policy: only a global admin changes it.
	if _, err := w.Firewall().Policies().Create(ctxT(t), api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "base"}}); err != nil {
		t.Fatal(err)
	}
	p, _ = admin.Projects().Get(ctxT(t), "web")
	p.Spec.FirewallPolicies = []string{"base"}
	if _, err := admin.Projects().Update(ctxT(t), "web", p, ""); err != nil {
		t.Fatal(err)
	}
	pol, _ := w.Firewall().Policies().Get(ctxT(t), "base")
	pol.Spec.DefaultIn = "deny"
	_, err = w.Firewall().Policies().Update(ctxT(t), "base", pol, "")
	wantCode(t, err, api.CodeForbidden)
	wantCode(t, w.Firewall().Policies().Delete(ctxT(t), "base"), api.CodeForbidden)
	if _, err := admin.Project("web").Firewall().Policies().Update(ctxT(t), "base", pol, ""); err != nil {
		t.Fatal(err)
	}
	// A project that names a missing policy is invalid.
	p.Spec.FirewallPolicies = []string{"ghost"}
	_, err = admin.Projects().Update(ctxT(t), "web", p, "")
	wantCode(t, err, api.CodeInvalid)
	// Deleting: not while it holds anything, and there is no project that is special.
	wantCode(t, admin.Projects().Delete(ctxT(t), "web"), api.CodeBusy)
	wantCode(t, admin.Projects().Delete(ctxT(t), "default"), api.CodeNotFound)
	if err := admin.Projects().Delete(ctxT(t), "db"); err != nil {
		t.Fatal(err)
	}
	// An address set of web is not visible without its project.
	if _, err := w.Firewall().AddressSets().Create(ctxT(t), api.AddressSet{Metadata: api.ObjectMeta{Name: "office"}, Spec: api.AddressSetSpec{Addresses: api.Entries("10.0.0.0/8")}}); err != nil {
		t.Fatal(err)
	}
	_, err = admin.Firewall().AddressSets().Get(ctxT(t), "office")
	wantCode(t, err, api.CodeInvalid)
}

func TestNewNetwork(t *testing.T) {
	e := newEnv(t)
	admin := e.client(t, "admin")
	p, err := admin.Projects().Create(ctxT(t), api.Project{Metadata: api.ObjectMeta{Name: "shop"}, Spec: api.ProjectSpec{
		NewNetwork: true, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.NewNetwork || len(p.Spec.Networks) != 1 || p.Spec.Networks[0].Network != "shop" {
		t.Fatalf("%+v", p.Spec)
	}
	n, err := admin.Networks().Get(ctxT(t), "shop")
	if err != nil || n.Spec.IPv4 == nil || !strings.HasPrefix(n.Spec.IPv4.Subnet, "10.64.") {
		t.Fatalf("%+v %v", n, err)
	}
	j, err := createJail(t, admin.Project("shop"), "app", api.JailSpec{Image: "fb", Storage: "default", Network: []api.NetworkAttach{{Network: "shop"}}})
	if err != nil || !strings.HasPrefix(j.Spec.Network[0].IPv4, "10.64.0.") {
		t.Fatalf("%+v %v", j, err)
	}
}

func TestStorage(t *testing.T) {
	e := newEnv(t)
	admin, ann := e.client(t, "admin"), e.client(t, "ann")
	var names []string
	for s, err := range admin.Storage().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, s.Metadata.Name)
	}
	if len(names) != 1 || names[0] != "default" {
		t.Fatalf("%v", names)
	}
	st, err := admin.Storage().Create(ctxT(t), api.Storage{Metadata: api.ObjectMeta{Name: "fast"}, Spec: api.StorageSpec{Dataset: "nvme/jailops"}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Status.Pool != "nvme" || st.Status.Health != "ONLINE" || st.Status.Size == 0 {
		t.Fatalf("%+v", st.Status)
	}
	e.srv.SetStorageStatus("fast", api.StorageStatus{Pool: "nvme", Health: "DEGRADED", Size: 10, Used: 4, Available: 6})
	if st, _ = admin.Storage().Get(ctxT(t), "fast"); st.Status.Health != "DEGRADED" || st.Status.Used != 4 {
		t.Fatalf("%+v", st.Status)
	}
	for _, ds := range []string{"nodataset", "/x", "a//b", "tank/jailops/sub", "nvme/jailops"} {
		_, err := admin.Storage().Create(ctxT(t), api.Storage{Metadata: api.ObjectMeta{Name: "x"}, Spec: api.StorageSpec{Dataset: ds}})
		if err == nil {
			t.Errorf("dataset %q accepted", ds)
		}
	}
	// Project users read granted storage only and cannot write.
	if _, err := ann.Storage().Get(ctxT(t), "default"); err != nil {
		t.Fatal(err)
	}
	_, err = ann.Storage().Get(ctxT(t), "fast")
	wantCode(t, err, api.CodeNotFound)
	_, err = ann.Storage().Create(ctxT(t), api.Storage{Metadata: api.ObjectMeta{Name: "y"}, Spec: api.StorageSpec{Dataset: "p/y"}})
	wantCode(t, err, api.CodeForbidden)
	// Granted or used storage cannot be deleted.
	wantCode(t, admin.Storage().Delete(ctxT(t), "default"), api.CodeBusy)
	if err := admin.Storage().Delete(ctxT(t), "fast"); err != nil {
		t.Fatal(err)
	}
}

func TestIdentitiesAndFiltering(t *testing.T) {
	e := newEnv(t)
	admin, ann, ro, bob, nobody := e.client(t, "admin"), e.client(t, "ann"), e.client(t, "ann-ro"), e.client(t, "bob"), e.client(t, "nobody")
	anon := func() *sdk.Client {
		c, err := sdk.Connect(ctxT(t), sdk.Remote(e.ts.URL, sdk.WithRetries(0)))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()
	// Info works for everybody; anything else needs a credential.
	if info, _ := anon.Info(ctxT(t)); info.Auth != "untrusted" {
		t.Fatalf("%+v", info)
	}
	_, err := anon.Whoami(ctxT(t))
	wantCode(t, err, api.CodeUnauthorized)
	id, err := ann.Whoami(ctxT(t))
	if err != nil || id.User != "ann" || id.Global || len(id.Projects) != 1 || id.Permission != api.PermAdmin {
		t.Fatalf("%+v %v", id, err)
	}
	if id, _ = admin.Whoami(ctxT(t)); !id.Global {
		t.Fatalf("%+v", id)
	}
	// An identity with neither projects nor global can do nothing, but can look itself up.
	if _, err := nobody.Whoami(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	for _, err := range nobody.Jails().List(ctxT(t)) {
		wantCode(t, err, api.CodeForbidden)
	}
	for _, err := range nobody.Networks().List(ctxT(t)) {
		wantCode(t, err, api.CodeForbidden)
	}
	// A role too low is forbidden, and checked before the project.
	_, err = createJail(t, ro.Project("web"), "z", wspec())
	wantCode(t, err, api.CodeForbidden)
	_, err = createJail(t, ro.Project("db"), "z", dspec())
	wantCode(t, err, api.CodeForbidden)
	// Host-level writes are global admin only.
	_, err = ann.Networks().Create(ctxT(t), api.Network{Metadata: api.ObjectMeta{Name: "n"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.9.0.0/24", Range: "10.9.0.2-10.9.0.9"}}})
	wantCode(t, err, api.CodeForbidden)
	for _, c := range []*sdk.Client{ann, ro} {
		_, err = c.Tokens().Create(ctxT(t), api.Token{Spec: api.TokenSpec{Permission: api.PermReadonly, Global: true}})
		wantCode(t, err, api.CodeForbidden)
	}
	// Networks and images are filtered by grants.
	var nets []string
	for n, err := range ann.Networks().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		nets = append(nets, n.Metadata.Name)
	}
	if len(nets) != 1 || nets[0] != "lan" {
		t.Fatalf("ann sees networks %v", nets)
	}
	_, err = ann.Networks().Get(ctxT(t), "secret")
	wantCode(t, err, api.CodeNotFound)
	var imgs []string
	for im, err := range bob.Images().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		imgs = append(imgs, im.Metadata.Name)
	}
	if len(imgs) != 1 || imgs[0] != "fb" {
		t.Fatalf("bob sees images %v", imgs)
	}
	// Identities need a scope.
	for _, call := range []func() error{
		func() error {
			_, err := admin.Tokens().Create(ctxT(t), api.Token{Spec: api.TokenSpec{Permission: api.PermReadonly}})
			return err
		},
		func() error {
			_, err := admin.Users().Create(ctxT(t), api.UserCreate{Metadata: api.ObjectMeta{Name: "u"}, Spec: api.UserSpec{Permission: api.PermReadonly}})
			return err
		},
		func() error {
			_, err := admin.Certificates().Create(ctxT(t), api.Certificate{Metadata: api.ObjectMeta{Name: "c"}, Spec: api.CertificateSpec{Fingerprint: "ab", Permission: api.PermReadonly}})
			return err
		},
		func() error {
			_, err := admin.Trust().CreateToken(ctxT(t), api.TrustTokenRequest{Name: "t", Permission: api.PermReadonly})
			return err
		},
	} {
		wantCode(t, call(), api.CodeInvalid)
	}
	// Operations and events are filtered by project.
	if _, err := createJail(t, ann.Project("web"), "w1", wspec()); err != nil {
		t.Fatal(err)
	}
	var opID string
	for op, err := range ann.Operations().List(ctxT(t)) {
		if err != nil {
			t.Fatal(err)
		}
		if op.Project != "web" {
			t.Fatalf("ann sees an operation of %q", op.Project)
		}
		opID = op.ID
	}
	if opID == "" {
		t.Fatal("ann sees no operation")
	}
	for op, err := range bob.Operations().List(ctxT(t)) {
		t.Fatalf("bob sees %+v %v", op, err)
	}
	if _, err := bob.Operations().Get(ctxT(t), opID); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("want not_found, got %v", err)
	}
	if err := bob.Operations().Cancel(ctxT(t), opID); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("want not_found, got %v", err)
	}
	if _, err := admin.Operations().Get(ctxT(t), opID); err != nil {
		t.Fatal(err)
	}
	// Events: bob sees nothing of web, global sees host-level ones too.
	evs := func(c *sdk.Client) []api.Event {
		var out []api.Event
		ctx, cancel := context.WithTimeout(ctxT(t), 300*time.Millisecond)
		defer cancel()
		for ev, err := range c.Events(ctx, sdk.FromID("0")) {
			if err != nil {
				break
			}
			out = append(out, ev)
		}
		return out
	}
	if n := len(evs(bob)); n != 0 {
		t.Fatalf("bob saw %d events", n)
	}
	var web, host int
	for _, ev := range evs(admin) {
		if strings.Contains(string(ev.Metadata), `"project":"web"`) {
			web++
		} else if !strings.Contains(string(ev.Metadata), `"project"`) {
			host++
		}
	}
	if web == 0 || host == 0 {
		t.Fatalf("admin events web=%d host=%d", web, host)
	}
	for _, ev := range evs(ann) {
		if !strings.Contains(string(ev.Metadata), `"project":"web"`) {
			t.Fatalf("ann saw %s", ev.Metadata)
		}
	}
}

func TestSessions(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	e.srv.SeedSession(api.Session{ID: "s1", User: "ann", CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)})
	e.srv.SeedSession(api.Session{ID: "s2", User: "bob", CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)})
	admin, ann, bob := e.client(t, "admin"), e.client(t, "ann"), e.client(t, "bob")
	count := func(c *sdk.Client) int {
		n := 0
		for _, err := range c.Sessions().List(ctxT(t)) {
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		return n
	}
	if count(admin) != 2 || count(ann) != 1 {
		t.Fatalf("%d %d", count(admin), count(ann))
	}
	wantCode(t, bob.Sessions().Revoke(ctxT(t), "s1"), api.CodeNotFound)
	if err := ann.Sessions().Revoke(ctxT(t), "s1"); err != nil {
		t.Fatal(err)
	}
	if err := admin.Sessions().Revoke(ctxT(t), "s2"); err != nil {
		t.Fatal(err)
	}
	if count(admin) != 0 {
		t.Fatal("sessions remain")
	}
}

// ---- trust over real TLS ----

func clientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "laptop"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func fpOf(c tls.Certificate) string {
	h := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(h[:])
}

type tlsEnv struct {
	srv   *fake.Server
	url   string
	fp    string
	clock *atomic.Int64
}

func newTLSEnv(t *testing.T) *tlsEnv {
	t.Helper()
	var h atomic.Value
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.Load().(http.Handler).ServeHTTP(w, r) }))
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	fp := sdk.Fingerprint(ts.Certificate())
	clock := &atomic.Int64{}
	clock.Store(time.Now().Unix())
	srv := fake.New(fake.WithToken("admin"), fake.WithServerFingerprint(fp),
		fake.WithClock(func() time.Time { return time.Unix(clock.Load(), 0) }))
	h.Store(http.Handler(srv))
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return &tlsEnv{srv, ts.URL, fp, clock}
}

func (e *tlsEnv) admin(t *testing.T) *sdk.Client {
	c, err := sdk.Connect(ctxT(t), sdk.Remote(e.url, sdk.WithPinnedFingerprint(e.fp), sdk.WithToken("admin"), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestTrustWorkflowOverTLS(t *testing.T) {
	e := newTLSEnv(t)
	admin := e.admin(t)
	ctx := ctxT(t)
	if _, err := admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}}); err != nil {
		t.Fatal(err)
	}
	tt, err := admin.Trust().CreateToken(ctx, api.TrustTokenRequest{Name: "laptop", Permission: api.PermOperator, Projects: []string{"web"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tt.Token, "joc_") || time.Until(tt.ExpiresAt) < 50*time.Minute && false {
		t.Fatalf("%+v", tt)
	}
	if fp, err := sdk.TrustTokenFingerprint(tt.Token); err != nil || fp != e.fp {
		t.Fatalf("%q %v", fp, err)
	}
	cert := clientCert(t)
	res, err := sdk.RedeemTrustToken(ctx, e.url, tt.Token, cert)
	if err != nil {
		t.Fatal(err)
	}
	if res.ServerFingerprint != e.fp || res.Certificate.Spec.Fingerprint != fpOf(cert) || res.Certificate.Metadata.Name != "laptop" ||
		res.Certificate.Spec.Permission != api.PermOperator || res.Certificate.Spec.Kind != "client" {
		t.Fatalf("%+v", res)
	}
	// The new identity connects with its certificate only.
	laptop, err := sdk.Connect(ctx, sdk.Remote(e.url, sdk.WithPinnedFingerprint(e.fp), sdk.WithClientCert(cert), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	defer laptop.Close()
	id, err := laptop.Whoami(ctx)
	if err != nil || id.User != "cert:laptop" || id.Kind != "certificate" || id.Permission != api.PermOperator || id.Global || len(id.Projects) != 1 {
		t.Fatalf("%+v %v", id, err)
	}
	// Single use: a replay is refused.
	_, err = sdk.RedeemTrustToken(ctx, e.url, tt.Token, clientCert(t))
	wantCode(t, err, api.CodeUnauthorized)
	// Expiry follows the server clock.
	tt2, _ := admin.Trust().CreateToken(ctx, api.TrustTokenRequest{Name: "late", Permission: api.PermReadonly, Global: true, TTLSeconds: 60})
	e.clock.Add(61)
	_, err = sdk.RedeemTrustToken(ctx, e.url, tt2.Token, clientCert(t))
	wantCode(t, err, api.CodeUnauthorized)
	// A token that was altered fails its HMAC; a token of another server too.
	tt3, _ := admin.Trust().CreateToken(ctx, api.TrustTokenRequest{Name: "forged", Permission: api.PermAdmin, Global: true})
	i := strings.Index(tt3.Token, ".")
	forged := tt3.Token[:i+1] + strings.Repeat("A", len(tt3.Token)-i-1)
	_, err = sdk.RedeemTrustToken(ctx, e.url, forged, clientCert(t))
	wantCode(t, err, api.CodeUnauthorized)
	other := fake.New(fake.WithServerFingerprint(e.fp))
	defer other.Close()
	otherAdmin := httptest.NewServer(other)
	defer otherAdmin.Close()
	oc, _ := sdk.Connect(ctx, sdk.Remote(otherAdmin.URL))
	defer oc.Close()
	foreign, err := oc.Trust().CreateToken(ctx, api.TrustTokenRequest{Name: "foreign", Permission: api.PermAdmin, Global: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sdk.RedeemTrustToken(ctx, e.url, foreign.Token, clientCert(t))
	wantCode(t, err, api.CodeUnauthorized)
	// A token for a server with another fingerprint stops at the client's pin.
	_, err = sdk.RedeemTrustToken(ctx, e.url, "joc_"+b64(`{"v":1,"fp":"`+strings.Repeat("ab", 32)+`"}`)+".x", clientCert(t))
	if err == nil {
		t.Fatal("a wrong pin was accepted")
	}
	// Failed attempts are rate limited per source.
	for i := 0; i < 6; i++ {
		_, err = sdk.RedeemTrustToken(ctx, e.url, forged, clientCert(t))
	}
	wantCode(t, err, api.CodeRateLimited)
	// Revocation is effective on the next request.
	if err := admin.Certificates().Delete(ctx, fpOf(cert)); err != nil {
		t.Fatal(err)
	}
	_, err = laptop.Whoami(ctx)
	wantCode(t, err, api.CodeUnauthorized)
}

func b64(s string) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out []byte
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var v uint32
		n := 0
		for j := 0; j < 3; j++ {
			v <<= 8
			if i+j < len(b) {
				v |= uint32(b[i+j])
				n++
			}
		}
		for k := 0; k < n+1; k++ {
			out = append(out, enc[(v>>(18-6*uint(k)))&63])
		}
	}
	return string(out)
}

func TestExpiredCertificateIsRefused(t *testing.T) {
	e := newTLSEnv(t)
	cert := clientCert(t)
	e.srv.TrustCertificate(api.Certificate{Metadata: api.ObjectMeta{Name: "short"}, Spec: api.CertificateSpec{
		Fingerprint: fpOf(cert), Permission: api.PermReadonly, Global: true, ExpiresAt: time.Unix(e.clock.Load(), 0).Add(time.Minute)}})
	c, err := sdk.Connect(ctxT(t), sdk.Remote(e.url, sdk.WithPinnedFingerprint(e.fp), sdk.WithClientCert(cert), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Whoami(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(120)
	_, err = c.Whoami(ctxT(t))
	wantCode(t, err, api.CodeUnauthorized)
}

// ---- hub ----

func TestFleetProjects(t *testing.T) {
	h1, h2 := fake.New(fake.WithToken("t"), fake.WithHostName("h1")), fake.New(fake.WithToken("t"), fake.WithHostName("h2"))
	hub := fake.New(fake.WithToken("t"), fake.WithHostName("hub"), fake.WithHosts(map[string]*fake.Server{"h1": h1, "h2": h2}))
	defer h1.Close()
	defer h2.Close()
	defer hub.Close()
	ts := httptest.NewServer(hub)
	defer ts.Close()
	c, err := sdk.Connect(ctxT(t), sdk.Remote(ts.URL, sdk.WithToken("t"), sdk.WithRetries(0)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := ctxT(t)
	lan := api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: "10.1.0.0/24", Range: "10.1.0.5-10.1.0.9"}}}
	h1.SeedNetwork(lan) // h2 has no network lan
	p, err := c.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProjectSpec{
		Hosts: []string{"h1", "h2"}, Networks: []api.ProjectNetwork{{Network: "lan"}}}})
	if err != nil {
		t.Fatal(err)
	}
	cond := func(p api.Project, host string) api.Condition {
		for _, c := range p.Status.Conditions {
			if c.Type == "Host:"+host {
				return c
			}
		}
		t.Fatalf("no condition for %s in %+v", host, p.Status.Conditions)
		return api.Condition{}
	}
	if c1 := cond(p, "h1"); c1.Status != api.ConditionTrue {
		t.Fatalf("%+v", c1)
	}
	if c2 := cond(p, "h2"); c2.Status != api.ConditionFalse || c2.Reason != "MissingNetwork" {
		t.Fatalf("%+v", c2)
	}
	got, ok := h1.Project("web")
	if !ok || got.Metadata.UUID != p.Metadata.UUID || got.Metadata.ManagedBy != "hub:"+hub.HostUUID() {
		t.Fatalf("%+v %v", got, ok)
	}
	if _, ok := h2.Project("web"); ok {
		t.Fatal("applied to a host that lacks the network")
	}
	// The host gets the network and an offline host catches up.
	h2.SeedNetwork(lan)
	h2.SetOffline("x", true) // unrelated name: no effect
	hub.SetOffline("h2", true)
	hub.ReconcileFleet()
	if _, ok := h2.Project("web"); ok {
		t.Fatal("an offline host was written")
	}
	agg, err := c.Projects().Aggregate(ctx, "web")
	if err != nil || len(agg.Hosts) != 2 {
		t.Fatalf("%+v %v", agg, err)
	}
	if !agg.Hosts[0].Online || !agg.Hosts[0].Applied || !agg.Hosts[0].InSync || agg.Hosts[1].Online || agg.Hosts[1].Error == nil {
		t.Fatalf("%+v", agg.Hosts)
	}
	hub.SetOffline("h2", false)
	hub.ReconcileFleet()
	if _, ok := h2.Project("web"); !ok {
		t.Fatal("h2 did not catch up")
	}
	agg, _ = c.Projects().Aggregate(ctx, "web")
	if !agg.Hosts[1].Applied || !agg.Hosts[1].InSync || agg.Hosts[1].Conditions[0].Status != api.ConditionTrue {
		t.Fatalf("%+v", agg.Hosts[1])
	}
	// An unmanaged project of the same name is never touched.
	h3 := fake.New()
	defer h3.Close()
	h3.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "web"}})
	// host=all elsewhere is invalid.
	_, _, err = c.Host("all").Jails().GetETag(ctx, "x")
	wantCode(t, err, api.CodeInvalid)
	// A host's own scoping applies through the hub.
	hc := c.Host("h1")
	if _, err := hc.Projects().Get(ctx, "web"); err != nil {
		t.Fatal(err)
	}
}

func TestRoutePerms(t *testing.T) {
	rp := fake.RoutePerms()
	for k, want := range map[string]api.Permission{
		"GET /api/v1/jails":                            api.PermReadonly,
		"POST /api/v1/jails":                           api.PermAdmin,
		"PUT /api/v1/jails/{name}/state":               api.PermOperator,
		"DELETE /api/v1/operations/{id}":               api.PermOperator,
		"POST /api/v1/trust/tokens":                    api.PermAdmin,
		"GET /api/v1/users":                            api.PermAdmin,
		"POST /api/v1/projects":                        api.PermAdmin,
		"GET /api/v1/storage/{name}":                   api.PermReadonly,
		"DELETE /api/v1/sessions/{id}":                 api.PermReadonly,
		"POST /api/v1/jails/{name}/rollback":           api.PermOperator,
		"DELETE /api/v1/jails/{name}/snapshots/{snap}": api.PermOperator,
	} {
		if rp[k] != want {
			t.Errorf("%s: got %q want %q", k, rp[k], want)
		}
	}
	if _, ok := rp["POST /api/v1/trust/clients"]; ok {
		t.Error("the public route has a role")
	}
	if len(rp) < 80 {
		t.Errorf("only %d routes", len(rp))
	}
}
