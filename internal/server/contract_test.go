package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/server"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func ctxT(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func seeded(t *testing.T) *dtest.Env {
	t.Helper()
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	return e
}

func mustJail(t *testing.T, e *dtest.Env, name string) api.Jail {
	t.Helper()
	op, err := e.Admin.Jails().Create(ctxT(t), dtest.WebJail(name))
	if err != nil {
		t.Fatal(err)
	}
	j, err := op.Wait(ctxT(t))
	if err != nil {
		t.Fatalf("create %s: %v\n%s", name, err, e.Log())
	}
	return j
}

func wantCode(t *testing.T, err error, code api.Code) {
	t.Helper()
	if err == nil || !api.IsCode(err, code) {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestInfoAndExtensions(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	anon := e.Anonymous()
	info, err := anon.Info(ctxT(t))
	if err != nil {
		t.Fatal(err)
	}
	if info.Auth != "untrusted" || info.APIVersion != "1.0" || info.Role != api.RoleHost || info.Hub {
		t.Fatalf("%+v", info)
	}
	// an anonymous caller learns no host name, id, software version or environment
	if info.HostUUID != "" || info.Hostname != "" || info.Version != "" || info.Environment.Pool != "" {
		t.Fatalf("%+v", info)
	}
	if ti, err := e.Admin.Info(ctxT(t)); err != nil || ti.HostUUID == "" || ti.Hostname != "testhost" || ti.Version != "test" {
		t.Fatalf("%+v %v", ti, err)
	}
	for _, want := range []string{"operations", "etag", "events", "jails", "doctor", "audit_log"} {
		if !slices.Contains(info.APIExtensions, want) {
			t.Errorf("missing extension %s", want)
		}
	}
	// No backup backend is wired, so the transport extensions are not advertised.
	for _, no := range []string{"backup_pull", "backup_push", "restore_preflight"} {
		if slices.Contains(info.APIExtensions, no) {
			t.Errorf("%s advertised without a backup backend", no)
		}
	}
	ai, err := e.Admin.Info(ctxT(t))
	if err != nil || ai.Auth != "trusted" {
		t.Fatalf("%+v %v", ai, err)
	}
	// Anything else needs credentials.
	_, err = anon.Operations().Get(ctxT(t), "x")
	wantCode(t, err, api.CodeUnauthorized)
}

func TestJailLifecycle(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	j := mustJail(t, e, "web")
	if j.Metadata.UUID == "" || j.Metadata.Scope != api.ScopeHost || j.Metadata.Generation != 1 || j.Metadata.Host != e.D.Service().HostUUID() {
		t.Fatalf("%+v", j.Metadata)
	}
	if j.Spec.Network[0].IPv4 != "10.20.0.10" || j.Spec.OS != api.OSFreeBSD || j.Spec.Layout != api.LayoutThin || j.Spec.Hostname != "web" {
		t.Fatalf("%+v", j.Spec)
	}
	_, err := e.Admin.Jails().Create(c, dtest.WebJail("web"))
	wantCode(t, err, api.CodeAlreadyExists)
	bad := dtest.WebJail("db")
	bad.Spec.Image = "nope@stable"
	_, err = e.Admin.Jails().Create(c, bad)
	wantCode(t, err, api.CodeNotFound)

	// Start, state, restart, stop.
	op, err := e.Admin.Jails().Start(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	j, err = op.Wait(c)
	if err != nil || j.Status.Power != api.PowerRunning || j.Status.JID == 0 || len(j.Status.Addresses) != 1 {
		t.Fatalf("%v %+v", err, j.Status)
	}
	if _, ok, _ := e.Jails.Get(c, "alpha_web"); !ok {
		t.Fatal("jail is not running in the runtime")
	}
	if !e.HasFile("/etc/jailops/jails/alpha_web/jail.conf") {
		t.Fatalf("jail.conf was not rendered: %v", e.Files.Paths())
	}
	if rc := e.File("/jailops/projects/alpha/jails/web/root/etc/rc.conf.local"); !strings.Contains(rc, "10.20.0.10") {
		t.Fatalf("rc.conf.local: %q", rc)
	}
	st, err := e.Admin.Jails().State(c, "web")
	if err != nil || st.Power != api.PowerRunning {
		t.Fatalf("%v %+v", err, st)
	}
	for _, act := range []func(context.Context, string, ...sdk.ActionOption) (*sdk.Operation[api.Jail], error){e.Admin.Jails().Restart, e.Admin.Jails().Stop} {
		op, err := act(c, "web")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := op.Wait(c); err != nil {
			t.Fatalf("%v\n%s", err, e.Log())
		}
	}
	st, _ = e.Admin.Jails().State(c, "web")
	if st.Power != api.PowerStopped {
		t.Fatalf("%+v", st)
	}
	_, err = e.Admin.Jails().Get(c, "ghost")
	wantCode(t, err, api.CodeNotFound)

	// Delete: a running jail is busy, a stopped one goes.
	op, _ = e.Admin.Jails().Start(c, "web")
	op.Wait(c)
	_, err = e.Admin.Jails().Delete(c, "web")
	wantCode(t, err, api.CodeBusy)
	op, _ = e.Admin.Jails().Stop(c, "web")
	op.Wait(c)
	dop, err := e.Admin.Jails().Delete(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dop.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	_, err = e.Admin.Jails().Get(c, "web")
	wantCode(t, err, api.CodeNotFound)
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/projects/alpha/jails/web"); ok {
		t.Fatal("datasets were not destroyed")
	}
}

// GET .../usage is a read of the jail: readonly may ask, the reply names what
// could not be measured, and nothing is stored on the jail.
func TestJailUsageOverHTTP(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	ro := e.Client(api.PermReadonly)
	u, err := ro.Jails().Usage(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if u.Jail != "web" || u.Power != api.PowerStopped || u.Accounting != nil || u.Disk.Error == "" {
		t.Fatalf("%+v", u)
	}
	const container = "tank/jailops/projects/alpha/jails/web"
	rows, err := e.ZFS.List(c, zfs.ListOpts{Root: container, Recursive: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		e.ZFS.SetSpace(r.Name, 1000, 1000)
	}
	e.ZFS.SetSpace(container+"/root", 4096, 1<<30)
	e.Run.On("rctl", []string{"-u", "jail:alpha_web"}, "maxproc=5\ncputime=61\nmemoryuse=1048576\n")
	op, err := e.Admin.Jails().Start(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	u, err = ro.Jails().Usage(c, "web")
	if err != nil || u.Power != api.PowerRunning || u.Accounting == nil {
		t.Fatalf("%v %+v", err, u)
	}
	if a := u.Accounting; a.Error != "" || a.Processes != 5 || a.CPUSeconds != 61 || a.MemoryBytes != 1048576 {
		t.Fatalf("%+v", a)
	}
	if u.Disk.Error != "" || u.Disk.RootBytes != 4096 || u.Disk.RootReferencedBytes != 1<<30 || u.Disk.DataBytes == 0 || u.Disk.DataBytes%1000 != 0 {
		t.Fatalf("%+v", u.Disk)
	}
	j, _ := e.Admin.Jails().Get(c, "web")
	if j.Metadata.Generation != 1 {
		t.Fatalf("measuring changed the jail: %+v", j.Metadata)
	}
	_, err = ro.Jails().Usage(c, "ghost")
	wantCode(t, err, api.CodeNotFound)
}

func TestSnapshotsRollbackUpgrade(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	sn, err := e.Admin.Jails().Snapshots("web").Create(c, "before", "first")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := sn.Wait(c)
	if err != nil || snap.Metadata.Name != "before" || snap.Spec.Comment != "first" || snap.Spec.Jail != "web" {
		t.Fatalf("%v %+v", err, snap)
	}
	if _, err := e.Admin.Jails().Snapshots("web").Create(c, "before", ""); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatalf("%v", err)
	}
	auto, err := e.Admin.Jails().Snapshots("web").Create(c, "", "")
	if err != nil {
		t.Fatal(err)
	}
	as, err := auto.Wait(c)
	if err != nil || !strings.HasPrefix(as.Metadata.Name, "snap-") {
		t.Fatalf("%v %+v", err, as)
	}
	var names []string
	for s, err := range e.Admin.Jails().Snapshots("web").List(c) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, s.Metadata.Name)
	}
	if len(names) != 2 {
		t.Fatalf("%v", names)
	}
	// Data rollback without confirmation is refused before an operation exists.
	_, err = e.Admin.Jails().Rollback(c, "web", api.JailRollback{Scope: api.RollbackData, Snapshot: as.Metadata.Name})
	wantCode(t, err, api.CodeDataLoss)
	rb, err := e.Admin.Jails().Rollback(c, "web", api.JailRollback{Scope: api.RollbackData, Snapshot: as.Metadata.Name, ConfirmDataLoss: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rb.Wait(c); err != nil {
		t.Fatalf("data rollback: %v\n%s", err, e.Log())
	}
	// Root rollback has nothing to return to on generation 1.
	rb, _ = e.Admin.Jails().Rollback(c, "web", api.JailRollback{})
	_, err = rb.Wait(c)
	wantCode(t, err, api.CodeNotFound)

	// Build generation 2, upgrade (dry run first), then roll the root back.
	bop, err := e.Admin.Images().Build(c, "fb", api.ImageBuild{FromGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	g2, err := bop.Wait(c)
	if err != nil || g2.Number != 2 || g2.Parent != 1 {
		t.Fatalf("%v %+v\n%s", err, g2, e.Log())
	}
	dry, err := e.Admin.Jails().Upgrade(c, "web", api.JailUpgrade{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	dr, err := dry.WaitResult(c)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, e.Log())
	}
	if !strings.Contains(string(dr.Operation.Metadata), `"plan"`) || !strings.Contains(string(dr.Operation.Metadata), "zfs snapshot") {
		t.Fatalf("dry run shows no plan: %s", dr.Operation.Metadata)
	}
	before, _ := e.Admin.Jails().Get(c, "web")
	if before.Status.Generation != "fb#g1" {
		t.Fatalf("dry run changed the jail: %+v", before.Status)
	}
	up, err := e.Admin.Jails().Upgrade(c, "web", api.JailUpgrade{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := up.Wait(c); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, e.Log())
	}
	after, _ := e.Admin.Jails().Get(c, "web")
	if after.Status.Generation != "fb#g2" {
		t.Fatalf("%+v", after.Status)
	}
	rb, _ = e.Admin.Jails().Rollback(c, "web", api.JailRollback{})
	if _, err := rb.Wait(c); err != nil {
		t.Fatalf("root rollback: %v\n%s", err, e.Log())
	}
	back, _ := e.Admin.Jails().Get(c, "web")
	if back.Status.Generation != "fb#g1" {
		t.Fatalf("%+v", back.Status)
	}
	// The generation a jail uses cannot be deleted.
	_, err = e.Admin.Images().DeleteGeneration(c, "fb", 1)
	wantCode(t, err, api.CodeImageInUse)
	// Snapshot delete.
	d, err := e.Admin.Jails().Snapshots("web").Delete(c, "before")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Wait(c); err != nil {
		t.Fatal(err)
	}
	_, err = e.Admin.Jails().Snapshots("web").Get(c, "before")
	wantCode(t, err, api.CodeNotFound)
}

func TestETagAndMerge(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	j, etag, err := e.Admin.Jails().GetETag(c, "web")
	if err != nil || etag != `"1"` {
		t.Fatalf("%v %q", err, etag)
	}
	j.Metadata.Labels = map[string]string{"tier": "web"}
	up, err := e.Admin.Jails().Update(c, "web", j, etag)
	if err != nil || up.Metadata.Generation != 2 || up.Metadata.Labels["tier"] != "web" {
		t.Fatalf("%v %+v", err, up.Metadata)
	}
	// A second write with the old etag is a conflict (412) and changes nothing.
	j.Metadata.Labels = map[string]string{"tier": "db"}
	_, err = e.Admin.Jails().Update(c, "web", j, etag)
	wantCode(t, err, api.CodeConflict)
	// An identical PUT keeps the generation.
	same, err := e.Admin.Jails().Update(c, "web", up, "")
	if err != nil || same.Metadata.Generation != 2 {
		t.Fatalf("%v %+v", err, same.Metadata)
	}
	// Merge patch with If-Match.
	p, err := e.Admin.Jails().Patch(c, "web", map[string]any{"spec": map[string]any{"resources": map[string]any{"memory": "1G"}}}, `"2"`)
	if err != nil || p.Spec.Resources.Memory != "1G" || p.Metadata.Generation != 3 {
		t.Fatalf("%v %+v", err, p)
	}
	_, err = e.Admin.Jails().Patch(c, "web", map[string]any{"metadata": map[string]any{"labels": nil}}, `"2"`)
	wantCode(t, err, api.CodeConflict)
	// Server-owned fields and the image cannot be changed by a client.
	p.Metadata.UUID, p.Metadata.Scope = "00000000-0000-4000-8000-000000000000", api.ScopeFleet
	p.Status.Power = api.PowerError
	q, err := e.Admin.Jails().Update(c, "web", p, "")
	if err != nil || q.Metadata.UUID == p.Metadata.UUID || q.Metadata.Scope != api.ScopeHost || q.Status.Power != api.PowerStopped {
		t.Fatalf("%v %+v", err, q)
	}
	q.Spec.Image = "other@stable"
	_, err = e.Admin.Jails().Update(c, "web", q, "")
	wantCode(t, err, api.CodeInvalid)
	// Modify retries on conflict.
	err = sdk.Modify[api.Jail](c, e.Admin.Jails(), "web", func(j *api.Jail) { j.Spec.Boot.Priority = 7 })
	if err != nil {
		t.Fatal(err)
	}
	got, _ := e.Admin.Jails().Get(c, "web")
	if got.Spec.Boot.Priority != 7 || got.Metadata.Generation <= 3 {
		t.Fatalf("%+v", got.Metadata)
	}
	// The change survives a rebuild of the registry from the datasets.
	if err := e.D.Service().RefreshJails(c); err != nil {
		t.Fatal(err)
	}
	got2, _ := e.Admin.Jails().Get(c, "web")
	if got2.Spec.Boot.Priority != 7 {
		t.Fatalf("spec.json was not written: %+v", got2.Spec.Boot)
	}
	// Label filter.
	n := 0
	for _, err := range e.Admin.Jails().List(c, sdk.Label("tier", "web")) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	for _, err := range e.Admin.Jails().List(c, sdk.Label("tier", "none")) {
		if err != nil {
			t.Fatal(err)
		}
		n += 10
	}
	if n != 1 {
		t.Fatalf("label filter matched %d", n)
	}
}

func TestIPAMAndNetworks(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	net, err := e.Admin.Networks().Get(c, "lan")
	if err != nil || net.Metadata.Scope != api.ScopeFleet {
		t.Fatalf("%v %+v", err, net)
	}
	a := mustJail(t, e, "a")
	b := mustJail(t, e, "b")
	if a.Spec.Network[0].IPv4 != "10.20.0.10" || b.Spec.Network[0].IPv4 != "10.20.0.11" {
		t.Fatalf("%s %s", a.Spec.Network[0].IPv4, b.Spec.Network[0].IPv4)
	}
	var leases []api.Lease
	for l, err := range e.Admin.Networks().Leases(c, "lan") {
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if len(leases) != 2 || leases[0].Jail != "alpha/a" || leases[1].Address != "10.20.0.11" {
		t.Fatalf("%+v", leases)
	}
	n2, _ := e.Admin.Networks().Get(c, "lan")
	if n2.Status.Allocated != 2 || n2.Status.Free != 39 {
		t.Fatalf("%+v", n2.Status)
	}
	fixed := dtest.WebJail("fixed")
	fixed.Spec.Network[0].IPv4 = "10.20.0.10"
	op, err := e.Admin.Jails().Create(c, fixed)
	if err == nil {
		_, err = op.Wait(c)
	}
	wantCode(t, err, api.CodeIPConflict)
	fixed.Spec.Network[0].IPv4 = "10.99.0.5"
	op, err = e.Admin.Jails().Create(c, fixed)
	if err == nil {
		_, err = op.Wait(c)
	}
	wantCode(t, err, api.CodeInvalid)
	// Exhaust the range.
	small, _ := e.Admin.Networks().Create(c, api.Network{Metadata: api.ObjectMeta{Name: "tiny"}, Spec: api.NetworkSpec{
		IPv4: &api.IPv4Net{Subnet: "10.30.0.0/24", Gateway: "10.30.0.1", Range: "10.30.0.5-10.30.0.5"}}})
	if small.Metadata.Name != "tiny" {
		t.Fatalf("%+v", small.Spec)
	}
	pr, _ := e.Admin.Projects().Get(c, dtest.SeedProject)
	pr.Spec.Networks = append(pr.Spec.Networks, api.ProjectNetwork{Network: "tiny"})
	if _, err := e.Admin.Projects().Update(c, dtest.SeedProject, pr, ""); err != nil {
		t.Fatal(err)
	}
	for i, want := range []api.Code{"", api.CodePoolExhausted} {
		j := dtest.WebJail("t" + string(rune('a'+i)))
		j.Spec.Network[0].Network = "tiny"
		op, err := e.Admin.Jails().Create(c, j)
		if err == nil {
			_, err = op.Wait(c)
		}
		if want == "" && err != nil || want != "" && !api.IsCode(err, want) {
			t.Fatalf("jail %d: %v", i, err)
		}
	}
	// A network in use cannot be deleted.
	err = e.Admin.Networks().Delete(c, "lan")
	wantCode(t, err, api.CodeBusy)
	// Updates are validated.
	n2.Spec.IPv4.Subnet = "10.77.0.0/24"
	n2.Spec.IPv4.Gateway = "10.77.0.1"
	n2.Spec.IPv4.Range = "10.77.0.5-10.77.0.9"
	_, err = e.Admin.Networks().Update(c, "lan", n2, "")
	wantCode(t, err, api.CodeIPConflict)
	_, err = e.Admin.Networks().Create(c, api.Network{Metadata: api.ObjectMeta{Name: "Bad Name"}, Spec: n2.Spec})
	wantCode(t, err, api.CodeInvalid)
}

func TestFirewall(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	fw := e.Admin.Firewall()
	set, err := fw.AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "office"}, Spec: api.AddressSetSpec{Addresses: api.Entries("203.0.113.0/24")}})
	if err != nil || set.Metadata.Generation != 1 {
		t.Fatalf("%v %+v", err, set)
	}
	_, err = fw.AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "loop"}, Spec: api.AddressSetSpec{Addresses: api.Entries("set:loop")}})
	wantCode(t, err, api.CodeInvalid)
	_, err = fw.AddressSets().Create(c, api.AddressSet{Metadata: api.ObjectMeta{Name: "bad"}, Spec: api.AddressSetSpec{Addresses: api.Entries("not an address")}})
	wantCode(t, err, api.CodeInvalid)
	pol := api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"22"}}}}}
	if _, err := fw.Policies().Create(c, pol); err != nil {
		t.Fatal(err)
	}
	bad := pol
	bad.Metadata.Name = "bad"
	bad.Spec.Rules = []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", Ports: []string{"99999"}}}
	_, err = fw.Policies().Create(c, bad)
	wantCode(t, err, api.CodeInvalid)
	// A set that a policy uses cannot go.
	err = fw.AddressSets().Delete(c, "office")
	wantCode(t, err, api.CodeBusy)
	// the refusal names the policies, in the message, the hint and the detail
	var busy *api.Error
	if !errors.As(err, &busy) || busy.Message != `address set "office" is used by firewall policy "web"` || busy.Detail["policies"] != "web" || !strings.Contains(busy.Hint, "set:office") {
		t.Fatalf("refusal: %+v", err)
	}
	j := dtest.WebJail("web")
	j.Spec.Firewall.Policies = []string{"web"}
	op, err := e.Admin.Jails().Create(c, j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	err = fw.Policies().Delete(c, "web")
	wantCode(t, err, api.CodeBusy)
	so, _ := e.Admin.Jails().Start(c, "web")
	if _, err := so.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	// The anchor is rendered for the start hook and loaded by the reconciler.
	rs := e.File(e.Cfg.StateDir + "/rendered/pf/alpha_web.conf")
	if !strings.Contains(rs, "203.0.113.0/24") || !strings.Contains(rs, "10.20.0.10") {
		t.Fatalf("anchor file: %q", rs)
	}
	e.D.Reconciler().Pass(c)
	live, _ := e.PF.Read(c, "jailops/alpha/web")
	if !strings.Contains(live, "203.0.113.0/24") {
		t.Fatalf("anchor not loaded: %q", live)
	}
	// Changing the set reloads the anchor of the running jail.
	set.Spec.Addresses = api.Entries("198.51.100.0/24")
	if _, err := fw.AddressSets().Update(c, "office", set, `"1"`); err != nil {
		t.Fatal(err)
	}
	e.D.Reconciler().Pass(c)
	live, _ = e.PF.Read(c, "jailops/alpha/web")
	if !strings.Contains(live, "198.51.100.0/24") || strings.Contains(live, "203.0.113.0/24") {
		t.Fatalf("anchor not reloaded: %q", live)
	}
}

func TestImagesAndGenerations(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	_, err := e.Admin.Images().Create(c, api.Image{Metadata: api.ObjectMeta{Name: "fb"}, Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.0-RELEASE", Source: api.ImageSource{Type: "pkgbase"}}})
	wantCode(t, err, api.CodeAlreadyExists)
	_, err = e.Admin.Images().Create(c, api.Image{Metadata: api.ObjectMeta{Name: "x"}, Spec: api.ImageSpec{OS: api.OSFreeBSD}})
	wantCode(t, err, api.CodeInvalid)
	im, err := e.Admin.Images().Get(c, "fb")
	if err != nil || len(im.Status.Generations) != 1 || im.Status.Generations[0].Name != "fb#g1" {
		t.Fatalf("%v %+v", err, im.Status)
	}
	var gens []api.ImageGeneration
	for g, err := range e.Admin.Images().Generations(c, "fb") {
		if err != nil {
			t.Fatal(err)
		}
		gens = append(gens, g)
	}
	if len(gens) != 1 || gens[0].Manifest == "" {
		t.Fatalf("%+v", gens)
	}
	// An image used by a jail cannot be deleted, and the error names the jail; a used generation neither.
	mustJail(t, e, "web")
	err = e.Admin.Images().Delete(c, "fb")
	wantCode(t, err, api.CodeImageInUse)
	if !strings.Contains(err.Error(), "web") {
		t.Fatalf("the error must name the jail: %v", err)
	}
	_, err = e.Admin.Images().DeleteGeneration(c, "fb", 1)
	wantCode(t, err, api.CodeImageInUse)
	for i := 0; i < 2; i++ { // the alias follows the newest generation, so g2 is free once g3 exists
		bop, _ := e.Admin.Images().Build(c, "fb", api.ImageBuild{FromGeneration: 1})
		if _, err := bop.Wait(c); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.Admin.Images().DeleteGeneration(c, "fb", 3)
	wantCode(t, err, api.CodeImageInUse)
	// An alias pinned to g2 moves to the newest remaining generation when g2 goes; an alias is managed explicitly.
	if im, err := e.Admin.Images().SetAlias(c, "fb", "pinned", 2); err != nil || im.Status.Aliases["pinned"] != 2 {
		t.Fatalf("%v %+v", err, im)
	}
	_, err = e.Admin.Images().SetAlias(c, "fb", "pinned", 9)
	wantCode(t, err, api.CodeNotFound)
	dop, err := e.Admin.Images().DeleteGeneration(c, "fb", 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dop.Wait(c); err != nil {
		t.Fatal(err)
	}
	im, err = e.Admin.Images().Get(c, "fb")
	if err != nil || im.Status.Aliases["pinned"] != 3 {
		t.Fatalf("the alias must move to the next newest generation: %v %+v", err, im.Status.Aliases)
	}
	if im, err := e.Admin.Images().DeleteAlias(c, "fb", "pinned"); err != nil || im.Status.Aliases["pinned"] != 0 || slices.Contains(im.Spec.Aliases, "pinned") {
		t.Fatalf("%v %+v", err, im)
	}
	_, err = e.Admin.Images().DeleteAlias(c, "fb", "pinned")
	wantCode(t, err, api.CodeNotFound)
	// Deleting the image removes every generation and alias once no jail uses it.
	jop, err := e.Admin.Jails().Delete(c, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jop.Wait(c); err != nil {
		t.Fatal(err)
	}
	if err := e.Admin.Images().Delete(c, "fb"); err != nil {
		t.Fatal(err)
	}
	_, err = e.Admin.Images().Get(c, "fb")
	wantCode(t, err, api.CodeNotFound)
	if ok, _ := e.ZFS.Exists(c, "tank/jailops/images/fb"); ok {
		t.Fatal("the image dataset was left behind")
	}
	_, err = e.Admin.Images().Build(c, "nope", api.ImageBuild{})
	wantCode(t, err, api.CodeNotFound)
}

func TestImageUpgradeBuildsAndMovesTheJails(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	mustJail(t, e, "web")
	so, _ := e.Admin.Jails().Start(c, "web")
	if _, err := so.Wait(c); err != nil {
		t.Fatalf("%v\n%s", err, e.Log())
	}
	// Only a global admin: a project admin is forbidden, and so is a global operator (the role of image builds).
	_, err := e.Scoped(api.PermAdmin, dtest.SeedProject).Images().Upgrade(c, "fb", api.ImageUpgrade{})
	wantCode(t, err, api.CodeForbidden)
	_, err = e.Client(api.PermOperator).Images().Upgrade(c, "fb", api.ImageUpgrade{})
	wantCode(t, err, api.CodeForbidden)
	_, err = e.Admin.Images().Upgrade(c, "nope", api.ImageUpgrade{})
	wantCode(t, err, api.CodeNotFound)
	// The repository has nothing newer: no generation is kept and the jail stays.
	op, err := e.Admin.Images().Upgrade(c, "fb", api.ImageUpgrade{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := op.Wait(c)
	if err != nil || !res.Unchanged || res.Generation != nil || len(res.Jails) != 1 || res.Jails[0].Status != api.ImageUpgradeSkipped {
		t.Fatalf("%+v %v\n%s", res, err, e.Log())
	}
	if im, _ := e.Admin.Images().Get(c, "fb"); len(im.Status.Generations) != 1 {
		t.Fatalf("%+v", im.Status)
	}
	// A newer package set: the generation is built, the jail moves, the history and the events are those of an OS update.
	e.SetRepoVersion("15.0p2")
	evctx, cancel := context.WithCancel(c)
	defer cancel()
	events := e.Events(evctx, e.Global())
	op, err = e.Admin.Images().Upgrade(c, "fb", api.ImageUpgrade{})
	if err != nil {
		t.Fatal(err)
	}
	if info := op.Info(); info.Project != "" || info.Resources["images"][0] != "/api/v1/images/fb" || info.Resources["jails"][0] != "/api/v1/jails/web" {
		t.Fatalf("%+v", info)
	}
	res, err = op.Wait(c)
	if err != nil || res.Unchanged || res.Generation == nil || res.Generation.Number != 2 || res.From != "fb#g1" {
		t.Fatalf("%+v %v\n%s", res, err, e.Log())
	}
	if j := res.Jails[0]; j.Jail != "web" || j.Project != dtest.SeedProject || j.Status != api.ImageUpgradeUpgraded || j.From != "fb#g1" || j.To != "fb#g2" || j.Record == "" {
		t.Fatalf("%+v", j)
	}
	after, _ := e.Admin.Jails().Get(c, "web")
	if after.Status.Generation != "fb#g2" || after.Status.Power != api.PowerRunning {
		t.Fatalf("%+v", after.Status)
	}
	h, err := e.Admin.Jails().UpdateHistory(c, "web")
	if err != nil || len(h) != 1 || h[0].ID != res.Jails[0].Record || h[0].Kind != api.UpdateKindOS || h[0].Result != api.UpdateOK {
		t.Fatalf("%+v %v", h, err)
	}
	seen := map[string]bool{}
	for !seen["image-generation-created"] || !seen["update.applied"] || !seen["image-upgraded"] {
		select {
		case ev := <-events:
			var l api.LifecycleEvent
			if ev.Type == api.EventLifecycle && json.Unmarshal(ev.Metadata, &l) == nil {
				seen[l.Action] = true
			}
		case <-c.Done():
			t.Fatalf("events not seen: %v", seen)
		}
	}
	// A dry run lists what would move and changes nothing.
	e.SetRepoVersion("15.0p3")
	op, _ = e.Admin.Images().Upgrade(c, "fb", api.ImageUpgrade{DryRun: true})
	res, err = op.Wait(c)
	if err != nil || !res.DryRun || res.Generation != nil || len(res.Plan) == 0 || res.Jails[0].Status != api.ImageUpgradePlanned || res.Jails[0].To != "fb#g3" {
		t.Fatalf("%+v %v", res, err)
	}
	if im, _ := e.Admin.Images().Get(c, "fb"); len(im.Status.Generations) != 2 {
		t.Fatalf("a dry run built: %+v", im.Status)
	}
}

func TestOperationsListWaitCancel(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	op, err := e.Admin.Jails().Create(c, dtest.WebJail("web"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Wait(c); err != nil {
		t.Fatal(err)
	}
	info := op.Info()
	if info.ID == "" || info.Status != api.OpSuccess && info.Status != api.OpPending && info.Status != api.OpRunning {
		t.Fatalf("%+v", info)
	}
	got, err := e.Admin.Operations().Get(c, op.ID())
	if err != nil || got.Status != api.OpSuccess || got.Progress != 100 || got.MayCancel || len(got.Metadata) == 0 {
		t.Fatalf("%v %+v", err, got)
	}
	if got.Resources["jails"][0] != "/api/v1/jails/web" {
		t.Fatalf("%+v", got.Resources)
	}
	n := 0
	for o, err := range e.Admin.Operations().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		if o.Status.Final() {
			n++
		}
	}
	if n < 1 { // the list is the project's: the image build of the seeding belongs to no project
		t.Fatalf("%d operations", n)
	}
	_, err = e.Admin.Operations().Get(c, "nope")
	wantCode(t, err, api.CodeNotFound)
	// A finished operation cannot be cancelled.
	err = e.Admin.Operations().Cancel(c, op.ID())
	wantCode(t, err, api.CodeInvalid)
	// Wait with a short timeout returns the record even when not final.
	// A long-running operation: hold the jail lock via a slow runner.
}

func TestUnsupportedAndRouting(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	// Server side: 501 with api.CodeUnsupported, never success.
	for _, p := range []string{"/api/v1/cluster", "/api/v1/rollouts"} {
		code, body := e.Raw("POST", p, e.Token(api.PermAdmin), "{}")
		if code != 501 || !strings.Contains(body, `"unsupported"`) {
			t.Errorf("%s: %d %s", p, code, body)
		}
	}
	code, body := e.Raw("GET", "/api/v1/nothing", e.Token(api.PermAdmin), "")
	if code != 404 || !strings.Contains(body, `"not_found"`) {
		t.Fatalf("%d %s", code, body)
	}
	code, body = e.Raw("DELETE", "/api/v1/operations", e.Token(api.PermAdmin), "")
	if code != 501 && code != 405 {
		t.Fatalf("%d %s", code, body)
	}
	// Backups: no backend, so lists are empty and restores are unsupported.
	n := 0
	for _, err := range e.Admin.Backups().List(c) {
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 0 {
		t.Fatal("backups")
	}
	_, err := e.Admin.Backups().Preflight(c, api.RestoreRequest{Backup: "x"})
	if !sdk.IsUnsupported(err) {
		t.Fatalf("%v", err)
	}
	if code, body := e.Raw("POST", "/api/v1/restores?project=alpha", e.Token(api.PermAdmin), `{"backup":"x","dry_run":true}`); code != 501 {
		t.Fatalf("%d %s", code, body)
	}
}

func TestBackupTargetsAndPolicies(t *testing.T) {
	e := seeded(t)
	c := ctxT(t)
	b := e.Admin.Backups()
	_, err := b.Targets().Create(c, api.BackupTarget{Metadata: api.ObjectMeta{Name: "disk"}, Spec: api.BackupTargetSpec{Kind: "pool"}})
	wantCode(t, err, api.CodeInvalid)
	tg, err := b.Targets().Create(c, api.BackupTarget{Metadata: api.ObjectMeta{Name: "disk"}, Spec: api.BackupTargetSpec{Kind: "directory", Path: "/backup/jail"}})
	if err != nil || tg.Metadata.Generation != 1 {
		t.Fatalf("%v %+v", err, tg)
	}
	pol := api.BackupPolicy{Metadata: api.ObjectMeta{Name: "nightly"}, Spec: api.BackupPolicySpec{
		Selector: map[string]string{"all": "true"}, Targets: []string{"disk"}, Schedule: "0 3 * * *", Retention: api.RetentionPolicy{Daily: 7}}}
	if _, err := b.Policies().Create(c, pol); err != nil {
		t.Fatal(err)
	}
	pol.Metadata.Name, pol.Spec.Schedule = "bad", "nonsense"
	_, err = b.Policies().Create(c, pol)
	wantCode(t, err, api.CodeInvalid)
	pol.Spec.Schedule, pol.Spec.Targets = "0 3 * * *", []string{"ghost"}
	_, err = b.Policies().Create(c, pol)
	wantCode(t, err, api.CodeNotFound)
	err = b.Targets().Delete(c, "disk")
	wantCode(t, err, api.CodeBusy)
	if err := b.Policies().Delete(c, "nightly"); err != nil {
		t.Fatal(err)
	}
	if err := b.Targets().Delete(c, "disk"); err != nil {
		t.Fatal(err)
	}
}

func TestErrorsAreStructured(t *testing.T) {
	e := seeded(t)
	_, err := e.Admin.Jails().Get(ctxT(t), "ghost")
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeNotFound || ae.Message == "" {
		t.Fatalf("%v", err)
	}
	code, body := e.Raw("POST", "/api/v1/jails?project=alpha", e.Token(api.PermAdmin), "{not json")
	if code != 400 || !strings.Contains(body, `"invalid"`) {
		t.Fatalf("%d %s", code, body)
	}
	big := `{"metadata":{"name":"x"},"spec":{"image":"` + strings.Repeat("a", 5<<20) + `"}}`
	code, body = e.Raw("POST", "/api/v1/jails?project=alpha", e.Token(api.PermAdmin), big)
	if code != 400 || !strings.Contains(body, "larger") {
		t.Fatalf("%d %.200s", code, body)
	}
	code, body = e.Raw("PUT", "/api/v1/jails/ghost?project=alpha", e.Token(api.PermAdmin), `{}`)
	if code != 404 {
		t.Fatalf("%d %s", code, body)
	}
	code, _ = e.Raw("PUT", "/api/v1/networks/lan", e.Token(api.PermAdmin), `{}`)
	if code != 400 {
		t.Fatalf("%d", code)
	}
}

func TestRequestIDs(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	req := func(id string) string {
		r, _ := http.NewRequest("GET", e.HTTP.URL+"/api/v1", nil)
		if id != "" {
			r.Header.Set("X-Request-ID", id)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("X-Request-ID")
	}
	if got := req("0123456789abcdef"); got != "0123456789abcdef" {
		t.Fatalf("a valid id was replaced: %q", got)
	}
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for _, bad := range []string{"", "short", "NOT-HEX-NOT-HEX!", "0123456789abcdef0"} {
		if got := req(bad); !re.MatchString(got) || got == bad {
			t.Fatalf("%q -> %q", bad, got)
		}
	}
	// The access log carries the id and the route pattern, never a body.
	if !strings.Contains(e.Log(), "rid=0123456789abcdef") {
		t.Fatalf("%s", e.Log())
	}
}

func TestHandlerPanicIsAnErrorEnvelopeNotACrash(t *testing.T) {
	e := dtest.New(t, dtest.Options{Hub: true})
	ctx := service.WithActor(context.Background(), service.Actor{Name: "t", Perm: api.PermAdmin, Global: true})
	if _, err := e.D.Service().CreateRemote(ctx, api.Remote{Metadata: api.ObjectMeta{Name: "r"}, Spec: api.RemoteSpec{Address: "127.0.0.1:1", Fingerprint: strings.Repeat("ab", 32)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.D.Service().CreateProject(ctx, api.Project{Metadata: api.ObjectMeta{Name: "alpha"}}); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{Svc: e.D.Service(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Remotes: func(context.Context, api.Remote) (http.RoundTripper, error) { panic("transport exploded") }})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/jails?host=r&project=alpha", nil)
	req.Header.Set("Authorization", "Bearer "+e.Token(api.PermAdmin))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var env api.Response
	_ = json.NewDecoder(resp.Body).Decode(&env)
	resp.Body.Close()
	if resp.StatusCode != 500 || env.Error == nil || env.Error.Code != api.CodeInternal || strings.Contains(env.Error.Message, "exploded") {
		t.Fatalf("%d %+v", resp.StatusCode, env)
	}
	// The server still serves.
	resp, err = http.Get(ts.URL + "/api/v1")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v", err)
	}
	resp.Body.Close()
}

func TestWebUIIsServedOutsideTheAPI(t *testing.T) {
	e := dtest.New(t, dtest.Options{})
	resp, err := http.Get(e.HTTP.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 404 { // 404 when the UI is not built into this tree
		t.Fatalf("%d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Error("no CSP on the UI")
	}
	// An unknown API path is a JSON error, never the UI.
	code, body := e.Raw("GET", "/api/v1/definitely-not-there", e.Token(api.PermAdmin), "")
	if code != 404 || !strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Fatalf("%d %.80s", code, body)
	}
	if code, _ := e.Raw("GET", "/healthz", "", ""); code != 200 {
		t.Fatalf("health: %d", code)
	}
	// The snapshot shape the UI sends is accepted.
	e.Seed()
	mustJail(t, e, "web")
	code, body = e.Raw("POST", "/api/v1/jails/web/snapshots?project=alpha", e.Token(api.PermAdmin), `{"comment":"from the ui"}`)
	if code != 202 {
		t.Fatalf("%d %s", code, body)
	}
	var accepted struct {
		Metadata api.Operation `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(body), &accepted); err != nil || accepted.Metadata.ID == "" {
		t.Fatalf("%v %s", err, body)
	}
	if _, err := e.Admin.Operations().Wait(ctxT(t), accepted.Metadata.ID); err != nil {
		t.Fatal(err)
	}
	for s, err := range e.Admin.Jails().Snapshots("web").List(ctxT(t)) {
		if err != nil || s.Spec.Comment != "from the ui" {
			t.Fatalf("%v %+v", err, s)
		}
	}
}
