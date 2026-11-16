package server_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// fleet builds a hub and two hosts that trust the hub's certificate as a global hub.
func fleet(t *testing.T) (hub, h1, h2 *dtest.Env) {
	t.Helper()
	ctx := ctxT(t)
	mk := func(name string) *dtest.Env {
		addr := freeAddr(t)
		return dtest.New(t, dtest.Options{Listen: true, Hostname: name, Mutate: func(c *daemon.Config) { c.Listen.HTTPS.Address = addr }})
	}
	h1, h2 = mk("h1"), mk("h2")
	hub = dtest.New(t, dtest.Options{Listen: true, Hub: true, Hostname: "hub"})
	sctx := service.WithActor(ctx, service.Actor{Name: "t", Perm: api.PermAdmin, Global: true})
	for _, h := range []*dtest.Env{h1, h2} {
		if _, err := h.D.Service().CreateCertificate(sctx, api.Certificate{Metadata: api.ObjectMeta{Name: "hub"},
			Spec: api.CertificateSpec{Fingerprint: hub.D.Fingerprint(), Permission: api.PermAdmin, Global: true, Kind: "hub"}}); err != nil {
			t.Fatal(err)
		}
	}
	for name, h := range map[string]*dtest.Env{"h1": h1, "h2": h2} {
		if _, err := hub.Admin.Remotes().Create(ctx, api.Remote{Metadata: api.ObjectMeta{Name: name},
			Spec: api.RemoteSpec{Address: h.D.HTTPSAddr(), Fingerprint: h.D.Fingerprint()}}); err != nil {
			t.Fatal(err)
		}
	}
	return hub, h1, h2
}

func hubCond(t *testing.T, hub *dtest.Env, project, host string) api.Condition {
	t.Helper()
	p, err := hub.Admin.Projects().Get(ctxT(t), project)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Status.Conditions {
		if c.Type == "Host:"+host {
			return c
		}
	}
	t.Fatalf("no condition for %s: %+v", host, p.Status.Conditions)
	return api.Condition{}
}

func TestFleetProjectIsAppliedToItsHosts(t *testing.T) {
	hub, h1, h2 := fleet(t)
	ctx := ctxT(t)
	// h1 has the network and storage; h2 lacks the network.
	if _, err := h1.Admin.Networks().Create(ctx, brWeb()); err != nil {
		t.Fatal(err)
	}
	spec := api.ProjectSpec{Hosts: []string{"h1", "h2"},
		Networks: []api.ProjectNetwork{{Network: "web"}}, Storage: []api.ProjectStorage{{Storage: "default", Quota: "100G"}},
		Quotas: api.ProjectQuotas{Jails: 5}}
	// The hub itself does not need web: a hub that only manages hosts holds the definition.
	if _, err := hub.Admin.Networks().Create(ctx, brWeb()); err != nil {
		t.Fatal(err)
	}
	proj, err := hub.Admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	hub.D.Service().FleetReconcile(ctx)
	// h1 holds the project with the same UUID, owned by the hub.
	got, err := h1.Admin.Projects().Get(ctx, "web")
	if err != nil {
		t.Fatalf("%v\n%s", err, hub.Log())
	}
	if got.Metadata.UUID != proj.Metadata.UUID || got.Metadata.ManagedBy != "hub:"+hub.D.Service().HostUUID() || got.Spec.Quotas.Jails != 5 {
		t.Fatalf("%+v", got.Metadata)
	}
	if c := hubCond(t, hub, "web", "h1"); c.Status != api.ConditionTrue || c.Reason != service.FleetApplied {
		t.Fatalf("%+v", c)
	}
	// h2 lacks the network: reported before anything is applied there.
	c := hubCond(t, hub, "web", "h2")
	if c.Status != api.ConditionFalse || c.Reason != service.FleetMissingNetwork || !strings.Contains(c.Message, "web") {
		t.Fatalf("%+v", c)
	}
	if _, err := h2.Admin.Projects().Get(ctx, "web"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("the project was applied to a host that lacks its network: %v", err)
	}
	// Once h2 has it, the next pass applies the project.
	if _, err := h2.Admin.Networks().Create(ctx, brWeb()); err != nil {
		t.Fatal(err)
	}
	hub.D.Service().FleetReconcile(ctx)
	if _, err := h2.Admin.Projects().Get(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if c := hubCond(t, hub, "web", "h2"); c.Status != api.ConditionTrue {
		t.Fatalf("%+v", c)
	}
	// Each host enforces its own copy: a jail on h1 is limited by h1's quota alone.
	hc := h1.Admin.Project("web")
	op, err := hc.Jails().Create(ctx, sdk.NewJail("a", webSpecOn(h1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatalf("%v\n%s", err, h1.Log())
	}
	// The aggregate reads the project on every host.
	agg, err := hub.Admin.Projects().Aggregate(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(agg.Hosts) != 2 || agg.Project.Metadata.Name != "web" || agg.Total.Jails != 1 {
		t.Fatalf("%+v", agg)
	}
	for _, hs := range agg.Hosts {
		if !hs.Online || !hs.Applied || !hs.InSync || hs.Error != nil {
			t.Fatalf("%+v", hs)
		}
	}
	// A project the caller may not use is not_found here as well.
	if _, err := hub.Admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "other"}}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, func() error {
		_, err := hub.Scoped(api.PermReadonly, "other").Projects().Aggregate(ctx, "web")
		return err
	}(), api.CodeNotFound)
	// host=all is for this route only.
	if code, _ := hub.Raw("GET", "/api/v1/jails?host=all&project=web", hub.Token(api.PermAdmin), ""); code != 400 {
		t.Fatalf("%d", code)
	}
}

func TestFleetOfflineHostCatchesUp(t *testing.T) {
	hub, h1, h2 := fleet(t)
	ctx := ctxT(t)
	for _, h := range []*dtest.Env{h1, h2} {
		if _, err := h.Admin.Networks().Create(ctx, brWeb()); err != nil {
			t.Fatal(err)
		}
	}
	spec := api.ProjectSpec{Hosts: []string{"h1", "h2"}, Networks: []api.ProjectNetwork{{Network: "web"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}
	if _, err := hub.Admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: spec}); err != nil {
		t.Fatal(err)
	}
	svc := hub.D.Service()
	svc.FleetReconcile(ctx)
	// h1 goes away; the definition changes meanwhile.
	h1.Stop()
	if _, err := hub.Admin.Projects().Patch(ctx, "web", map[string]any{"spec": map[string]any{"quotas": map[string]any{"jails": 3}}}, ""); err != nil {
		t.Fatal(err)
	}
	svc.FleetReconcile(ctx)
	if c := hubCond(t, hub, "web", "h1"); c.Status != api.ConditionFalse || c.Reason != service.FleetOffline {
		t.Fatalf("%+v", c)
	}
	if c := hubCond(t, hub, "web", "h2"); c.Status != api.ConditionTrue {
		t.Fatalf("%+v", c)
	}
	if p, _ := h2.Admin.Projects().Get(ctx, "web"); p.Spec.Quotas.Jails != 3 {
		t.Fatalf("an online host was held back by an offline one: %+v", p.Spec.Quotas)
	}
	// The aggregate says which host is down.
	agg, err := hub.Admin.Projects().Aggregate(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	for _, hs := range agg.Hosts {
		if hs.Host == "h1" && (hs.Online || hs.Error == nil) {
			t.Fatalf("%+v", hs)
		}
		if hs.Host == "h2" && (!hs.Online || !hs.InSync) {
			t.Fatalf("%+v", hs)
		}
	}
	// h1 returns and catches up on the next pass.
	h1.Start()
	svc.FleetReconcile(ctx)
	p, err := h1.Admin.Projects().Get(ctx, "web")
	if err != nil || p.Spec.Quotas.Jails != 3 {
		t.Fatalf("%v %+v", err, p.Spec.Quotas)
	}
	if c := hubCond(t, hub, "web", "h1"); c.Status != api.ConditionTrue {
		t.Fatalf("%+v", c)
	}
	// Deleting the project removes it from the hosts the hub applied it to; an offline host is retried.
	h2.Stop()
	if err := hub.Admin.Projects().Delete(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := h1.Admin.Projects().Get(ctx, "web"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("h1 still holds the project: %v", err)
	}
	h2.Start()
	svc.FleetReconcile(ctx)
	if _, err := h2.Admin.Projects().Get(ctx, "web"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("h2 still holds the project: %v", err)
	}
}

// The hub never changes a project it does not own.
func TestFleetNeverTouchesAForeignProject(t *testing.T) {
	hub, h1, _ := fleet(t)
	ctx := ctxT(t)
	for _, h := range []*dtest.Env{h1} {
		if _, err := h.Admin.Networks().Create(ctx, brWeb()); err != nil {
			t.Fatal(err)
		}
	}
	local := api.ProjectSpec{Comment: "local", Quotas: api.ProjectQuotas{Jails: 1}}
	if _, err := h1.Admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: local}); err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Admin.Projects().Create(ctx, api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProjectSpec{Hosts: []string{"h1"}}}); err != nil {
		t.Fatal(err)
	}
	hub.D.Service().FleetReconcile(ctx)
	if c := hubCond(t, hub, "web", "h1"); c.Reason != service.FleetConflict {
		t.Fatalf("%+v", c)
	}
	if p, _ := h1.Admin.Projects().Get(ctx, "web"); p.Spec.Comment != "local" || p.Metadata.ManagedBy != "" {
		t.Fatalf("%+v", p)
	}
	if err := hub.Admin.Projects().Delete(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := h1.Admin.Projects().Get(ctx, "web"); err != nil {
		t.Fatalf("the hub deleted a project it does not own: %v", err)
	}
}

func brWeb() api.Network {
	return api.Network{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.NetworkSpec{
		IPv4: &api.IPv4Net{Subnet: "10.50.0.0/24", Gateway: "10.50.0.1", Range: "10.50.0.10-10.50.0.100"}}}
}

func webSpecOn(e *dtest.Env) api.JailSpec {
	// The host needs the image; a minimal one is created on first use.
	ctx := context.Background()
	if _, err := e.Admin.Images().Get(ctx, "fb"); err != nil {
		e.Seed()
	}
	sp := webSpec()
	sp.Network = []api.NetworkAttach{{Network: "web"}} // the project "web" holds web
	return sp
}

var _ = fmt.Sprint
