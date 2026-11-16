package server_test

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// Every jail has a routed link of its own: its host end carries the gateway as a /32 and the host routes the jail's
// address through it, so jails reach each other only through the host.
func TestEveryJailHasARoutedLinkOfItsOwn(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	c := ctxT(t)
	n := dtest.LAN()
	n.Metadata.Name = "priv"
	n.Spec.IPv4 = &api.IPv4Net{Subnet: "10.30.0.0/24", Gateway: "10.30.0.1", Range: "10.30.0.10-10.30.0.50"}
	n.Spec.Uplink = "em0"
	if _, err := e.Admin.Networks().Create(c, n); err != nil {
		t.Fatal(err)
	}
	// A network belongs to one project: no sharing, so no ranges to keep apart.
	if _, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "p1"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "priv"}},
		Storage:  []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	_, err := e.Admin.Projects().Create(c, api.Project{Metadata: api.ObjectMeta{Name: "p2"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "priv"}}}})
	if !api.IsCode(err, api.CodeConflict) {
		t.Fatalf("a second project took the network: %v", err)
	}
	// A jail attaches with a link of its own.
	jl := dtest.WebJail("w1")
	jl.Spec.Network = []api.NetworkAttach{{Network: "priv", IPv4: "auto"}}
	jl.Spec.Storage = "default"
	op, err := e.Admin.Project("p1").Jails().Create(c, jl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	so, err := e.Admin.Project("p1").Jails().Start(c, "w1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := so.Wait(c); err != nil {
		t.Fatal(err)
	}
	des, err := e.D.Service().Desired(c)
	if err != nil {
		t.Fatal(err)
	}
	var addr, route []string
	for _, jd := range des.Jails {
		for _, steps := range jd.Attach {
			for _, st := range steps {
				switch st.Op {
				case render.OpAddAddr:
					addr = append(addr, st.Describe())
				case render.OpAddHostRoute:
					route = append(route, st.Describe())
				}
			}
		}
	}
	if len(addr) != 1 || !strings.Contains(addr[0], " inet 10.30.0.1/32 alias") {
		t.Fatalf("the host end lacks the gateway /32: %v", addr)
	}
	if len(route) != 1 || !strings.HasPrefix(route[0], "route add -inet 10.30.0.10/32 -interface jo") {
		t.Fatalf("the host lacks the route to the jail: %v", route)
	}
}
