package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

// The rename of every kind: the object and what refers to it change in one operation, a failure at any step leaves
// everything as it was, and the refusals say why.

// faultZFS fails the renames and property changes of datasets when the injector says so, like the file fake does
// for writes: the sweeps of the rollback tests reach every step.
type faultZFS struct {
	zfs.Client
	f func() *fault.Injector
}

func (z faultZFS) Rename(ctx context.Context, from, to string, o zfs.RenameOpts) error {
	if err := z.f().Hit("zfs rename " + from); err != nil {
		return err
	}
	return z.Client.Rename(ctx, from, to, o)
}

func (z faultZFS) Set(ctx context.Context, name string, props map[string]string) error {
	if err := z.f().Hit("zfs set " + name); err != nil {
		return err
	}
	return z.Client.Set(ctx, name, props)
}

// faultEnv is newEnv with the dataset changes in the reach of e.Fault.
func faultEnv(t *testing.T) (*dtest.Env, *service.Service) {
	t.Helper()
	var e *dtest.Env
	get := func() *fault.Injector {
		if e == nil {
			return nil
		}
		return e.Fault
	}
	e = dtest.New(t, dtest.Options{Clients: func(c *daemon.Clients) { c.ZFS = faultZFS{c.ZFS, get} }})
	e.Seed()
	return e, e.D.Service()
}

func renameOpts(to string) service.RenameOptions {
	return service.RenameOptions{NewName: to, Expect: service.AnyGeneration}
}

func mkJail(t *testing.T, e *dtest.Env, s *service.Service, ctx context.Context, j api.Jail) {
	t.Helper()
	op, err := s.CreateJail(ctx, j)
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("create %s: %+v\n%s", j.Metadata.Name, got, e.Log())
	}
}

func renameJailAction(t *testing.T, e *dtest.Env, s *service.Service, ctx context.Context, name, action string) {
	t.Helper()
	op, err := s.JailAction(ctx, name, api.JailAction{Action: action})
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("%s %s: %+v\n%s", action, name, got, e.Log())
	}
}

// doRename runs a rename to its end and returns its result: doRename(t, s)(s.RenameNetwork(...)).
func doRename(t *testing.T, s *service.Service) func(op api.Operation, _ *api.RenameResult, err error) api.RenameResult {
	return func(op api.Operation, _ *api.RenameResult, err error) api.RenameResult {
		t.Helper()
		return finishRename(t, s, op, err)
	}
}

func finishRename(t *testing.T, s *service.Service, op api.Operation, err error) api.RenameResult {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, s, op)
	if got.Status != api.OpSuccess {
		t.Fatalf("rename: %+v %+v", got, got.Error)
	}
	var res api.RenameResult
	if err := json.Unmarshal(got.Metadata, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// failRename runs a rename that must fail inside its operation (or at once) and returns the error:
// failRename(t, s)(s.RenameJail(...)).
func failRename(t *testing.T, s *service.Service) func(op api.Operation, _ *api.RenameResult, err error) error {
	return func(op api.Operation, _ *api.RenameResult, err error) error {
		t.Helper()
		return failedRename(t, s, op, err)
	}
}

func failedRename(t *testing.T, s *service.Service, op api.Operation, err error) error {
	t.Helper()
	if err != nil {
		return err
	}
	got := wait(t, s, op)
	if got.Status != api.OpFailure || got.Error == nil {
		t.Fatalf("the rename did not fail: %+v", got)
	}
	return got.Error
}

func hasChange(res api.RenameResult, kind, object string) bool {
	for _, c := range res.Changes {
		if c.Kind == kind && strings.Contains(c.Object, object) {
			return true
		}
	}
	return false
}

func specFile(e *dtest.Env, project, name string) string {
	return e.File("/jailops/projects/" + project + "/jails/" + name + "/spec.json")
}

// networkState is what a network rename touches, in a form two states can be compared in.
func networkState(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	g := as(globalAdmin, "")
	var b strings.Builder
	nets, _ := s.ListNetworks(g, nil)
	for _, n := range nets {
		b.WriteString("net " + n.Metadata.Name + "\n")
	}
	p, _ := s.GetProject(g, dtest.SeedProject)
	for _, n := range p.Spec.Networks {
		b.WriteString("grant " + n.Network + "\n")
	}
	j, _ := s.GetJail(as(globalAdmin, dtest.SeedProject), "web")
	for _, a := range j.Spec.Network {
		b.WriteString("jail " + a.Network + "\n")
	}
	if strings.Contains(specFile(e, dtest.SeedProject, "web"), `"office"`) {
		b.WriteString("spec.json office\n")
	}
	return b.String()
}

func TestRenameNetwork(t *testing.T) {
	e, s := newEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	g := as(globalAdmin, "")
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	renameJailAction(t, e, s, alpha, "web", "start")
	lan, _ := s.GetNetwork(g, "lan")
	ifs, _ := e.Net.List(context.Background())
	if len(ifs) == 0 {
		t.Fatal("the fake host has no interfaces")
	}

	// a dry run lists every reference and changes nothing
	_, dry, err := s.RenameNetwork(g, "lan", service.RenameOptions{NewName: "office", DryRun: true, Expect: lan.Metadata.Generation})
	if err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || dry.Counts[api.RenameObject] != 1 || !hasChange(*dry, api.RenameReference, "project alpha") || !hasChange(*dry, api.RenameReference, "jail web") {
		t.Fatalf("dry run: %+v", dry)
	}
	if _, err := s.GetNetwork(g, "lan"); err != nil {
		t.Fatal("the dry run renamed the network")
	}

	// the refusals
	_, _, err = s.RenameNetwork(as(alphaOnly, dtest.SeedProject), "lan", renameOpts("office"))
	wantCode(t, err, api.CodeForbidden)
	_, _, err = s.RenameNetwork(g, "lan", renameOpts("Off_ice"))
	wantCode(t, err, api.CodeInvalid)
	_, _, err = s.RenameNetwork(g, "lan", renameOpts("lan"))
	wantCode(t, err, api.CodeInvalid)
	_, _, err = s.RenameNetwork(g, "nowhere", renameOpts("office"))
	wantCode(t, err, api.CodeNotFound)
	other := e.MakeNetwork("x")
	_, _, err = s.RenameNetwork(g, "lan", renameOpts(other))
	wantCode(t, err, api.CodeAlreadyExists)
	_, _, err = s.RenameNetwork(g, "lan", service.RenameOptions{NewName: "office", Expect: lan.Metadata.Generation + 7})
	wantCode(t, err, api.CodeConflict)
	synced := dtest.LAN()
	synced.Metadata.Name, synced.Metadata.ManagedBy = "synced", "sync:fleet"
	synced.Spec.IPv4 = &api.IPv4Net{Subnet: "10.99.0.0/24", Gateway: "10.99.0.1", Range: "10.99.0.10-10.99.0.20"}
	if _, err := s.CreateNetwork(g, synced); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RenameNetwork(g, "synced", renameOpts("other"))
	wantCode(t, err, api.CodeForbidden)
	if hintOf(err) == "" {
		t.Error("the refusal of a managed network has no hint")
	}

	// the rename: every reference follows, the running jail keeps its interfaces
	before := networkState(t, e, s)
	res := doRename(t, s)(s.RenameNetwork(g, "lan", service.RenameOptions{NewName: "office", Expect: lan.Metadata.Generation}))
	if res.From != "lan" || res.To != "office" || res.Counts[api.RenameReference] < 2 || len(res.Steps) == 0 {
		t.Fatalf("%+v", res)
	}
	after := networkState(t, e, s)
	for _, want := range []string{"net office", "grant office", "jail office", "spec.json office"} {
		if !strings.Contains(after, want) {
			t.Fatalf("after the rename: %s (before %s)", after, before)
		}
	}
	if strings.Contains(after, "net lan\n") {
		t.Fatal("the old name is still there")
	}
	j, err := s.GetJail(alpha, "web")
	if err != nil || j.Status.Power != api.PowerRunning {
		t.Fatalf("the jail stopped: %+v %v", j.Status, err)
	}
	// the interfaces keep their names (the reconcile loop may add those of the other network meanwhile)
	ifs2, _ := e.Net.List(context.Background())
	have := map[string]bool{}
	for _, i := range ifs2 {
		have[i.Name] = true
		if strings.Contains(i.Description, "net=lan ") {
			t.Errorf("interface %s still says %q", i.Name, i.Description)
		}
	}
	for _, i := range ifs {
		if !have[i.Name] {
			t.Errorf("interface %s is gone", i.Name)
		}
	}
	if rs, _ := e.PF.Read(context.Background(), render.NetAnchor("lan")); rs != "" {
		t.Errorf("the anchor of the old name is still loaded: %q", rs)
	}
	// the audit log has the operation
	entries, err := s.DB().Audit.List(context.Background(), store.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range entries {
		found = found || (a.Method == "OPERATION" && strings.Contains(a.Detail, "rename network lan to office") && a.Result == "ok")
	}
	if !found {
		t.Fatal("no audit entry")
	}
	// and the name is free again
	if _, err := s.GetNetwork(g, "lan"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatalf("lan: %v", err)
	}
}

// A failure at any step of a rename leaves the state as it was.
func TestRenameNetworkRollsBackEveryStep(t *testing.T) {
	e, s := faultEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	g := as(globalAdmin, "")
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	mkJail(t, e, s, alpha, dtest.WebJail("db"))
	before := networkState(t, e, s)
	for k := 1; ; k++ {
		if k > 40 {
			t.Fatal("the rename never succeeded")
		}
		e.Fault.Reset(k)
		op, _, err := s.RenameNetwork(g, "lan", renameOpts("office"))
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		e.Fault.Reset(0)
		if got.Status == api.OpSuccess {
			if k == 1 {
				t.Fatal("no step was faulted")
			}
			break
		}
		if !errors.Is(got.Error, got.Error) || !strings.Contains(got.Error.Message, fault.ErrInjected.Error()) {
			t.Fatalf("step %d: %+v", k, got.Error)
		}
		if now := networkState(t, e, s); now != before {
			t.Fatalf("failure at mutation %d left\n%s\ninstead of\n%s", k, now, before)
		}
	}
	if now := networkState(t, e, s); !strings.Contains(now, "jail office") {
		t.Fatal(now)
	}
}

// A daemon that dies in the middle of a rename undoes it at its next start.
func TestRenameInterruptedIsRolledBackAtStart(t *testing.T) {
	e, s := newEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	g := as(globalAdmin, "")
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	before := networkState(t, e, s)
	service.SetRenameCrash(s, 3) // the network and the project are renamed, the jail is not
	op, _, err := s.RenameNetwork(g, "lan", renameOpts("office"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := s.GetNetwork(g, "office"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the rename never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	e.Stop()
	e2 := dtest.New(t, dtest.Options{Reuse: e})
	s2 := e2.D.Service()
	if now := networkState(t, e2, s2); now != before {
		t.Fatalf("after the restart\n%s\ninstead of\n%s\n%s", now, before, e2.Log())
	}
	rec := s2.Recovered()
	if len(rec) != 1 || rec[0].Action != "rolled-back" || !strings.HasPrefix(rec[0].Run, "rename/") {
		t.Fatalf("%+v", rec)
	}
	got, err := s2.GetOperation(g, op.ID)
	if err != nil || got.Status != api.OpFailure {
		t.Fatalf("%+v %v", got, err)
	}
}

// Two operations on the same objects do not run at once.
func TestRenameRefusedWhileBusy(t *testing.T) {
	_, s := newEnv(t)
	g := as(globalAdmin, "")
	release := make(chan struct{})
	defer close(release)
	if _, err := s.Submit(g, service.OpSpec{Description: "hold lan", Locks: []string{"network/lan"},
		Run: func(ctx context.Context, h *service.OpHandle) (any, error) { <-release; return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.RenameNetwork(g, "lan", renameOpts("office"))
	wantCode(t, err, api.CodeBusy)
}

// jailState is what a jail rename touches.
func jailState(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	l, _ := s.ListJails(as(globalAdmin, dtest.SeedProject), nil)
	for _, j := range l {
		b.WriteString("jail " + j.Metadata.Name + " depends " + strings.Join(j.Spec.Boot.Depends, ",") + "\n")
	}
	for _, ds := range []string{"tank/jailops/projects/alpha/jails/web", "tank/jailops/projects/alpha/jails/www"} {
		if ok, _ := e.ZFS.Exists(ctx, ds); ok {
			m, _ := e.ZFS.Get(ctx, ds, "mountpoint")
			r, _ := e.ZFS.Get(ctx, ds+"/root", "mountpoint")
			b.WriteString("dataset " + ds + " " + m["mountpoint"].Value + " " + r["mountpoint"].Value + "\n")
		}
	}
	for _, f := range []string{"alpha_web.json", "alpha_www.json"} {
		if _, err := os.Stat(filepath.Join(e.Cfg.StateDir, "updates", f)); err == nil {
			b.WriteString("history " + f + "\n")
		}
	}
	return b.String()
}

func TestRenameJail(t *testing.T) {
	e, s := newEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	db := dtest.WebJail("db")
	db.Spec.Boot.Depends = []string{"web"}
	mkJail(t, e, s, alpha, db)
	renameJailAction(t, e, s, alpha, "web", "start")
	hist := filepath.Join(e.Cfg.StateDir, "updates", "alpha_web.json")
	if err := os.MkdirAll(filepath.Dir(hist), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hist, []byte(`[{"id":"1","project":"alpha","jail":"web","kind":"upgrade"}]`), 0o640); err != nil {
		t.Fatal(err)
	}

	// a running jail is refused, with the way out
	_, _, err := s.RenameJail(alpha, "web", renameOpts("www"))
	wantCode(t, err, api.CodeBusy)
	if !strings.Contains(hintOf(err), "stop") {
		t.Fatalf("hint: %q", hintOf(err))
	}
	renameJailAction(t, e, s, alpha, "web", "stop")
	_, _, err = s.RenameJail(alpha, "web", renameOpts("db"))
	wantCode(t, err, api.CodeAlreadyExists)
	_, _, err = s.RenameJail(alpha, "web", renameOpts("No Way"))
	wantCode(t, err, api.CodeInvalid)
	_, _, err = s.RenameJail(as(alphaOnly, "ghost"), "web", renameOpts("www"))
	if err == nil {
		t.Fatal("a jail of another project was renamed")
	}

	_, dry, err := s.RenameJail(alpha, "web", service.RenameOptions{NewName: "www", DryRun: true, Expect: service.AnyGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if !hasChange(*dry, api.RenameDataset, "jails/web") || !hasChange(*dry, api.RenameReference, "jail db") || !hasChange(*dry, api.RenameState, "update history") {
		t.Fatalf("dry run: %+v", dry)
	}
	if len(dry.Warnings) == 0 {
		t.Error("no warning about the hostname")
	}

	before := jailState(t, e, s)
	res := doRename(t, s)(s.RenameJail(as(alphaOnly, dtest.SeedProject), "web", renameOpts("www")))
	if res.Counts[api.RenameDataset] == 0 {
		t.Fatalf("%+v", res)
	}
	after := jailState(t, e, s)
	for _, want := range []string{"jail www", "depends www", "dataset tank/jailops/projects/alpha/jails/www /jailops/projects/alpha/jails/www /jailops/projects/alpha/jails/www/root", "history alpha_www.json"} {
		if !strings.Contains(after, want) {
			t.Fatalf("after:\n%s\nbefore:\n%s", after, before)
		}
	}
	if strings.Contains(after, "jails/web") || strings.Contains(after, "alpha_web") {
		t.Fatalf("the old name is left:\n%s", after)
	}
	b, _ := os.ReadFile(filepath.Join(e.Cfg.StateDir, "updates", "alpha_www.json"))
	if !strings.Contains(string(b), `"jail":"www"`) {
		t.Fatalf("history: %s", b)
	}
	if !strings.Contains(specFile(e, dtest.SeedProject, "www"), `"name": "www"`) {
		t.Fatal(specFile(e, dtest.SeedProject, "www"))
	}
	// and it starts under its new name
	renameJailAction(t, e, s, alpha, "www", "start")
	if _, ok, _ := e.Jails.Get(context.Background(), "alpha_www"); !ok {
		t.Fatal("the kernel does not know alpha_www")
	}
}

func TestRenameJailRollsBackEveryStep(t *testing.T) {
	e, s := faultEnv(t)
	alpha := as(globalAdmin, dtest.SeedProject)
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	db := dtest.WebJail("db")
	db.Spec.Boot.Depends = []string{"web"}
	mkJail(t, e, s, alpha, db)
	before := jailState(t, e, s)
	for k := 1; ; k++ {
		if k > 80 {
			t.Fatal("the rename never succeeded")
		}
		e.Fault.Reset(k)
		op, _, err := s.RenameJail(alpha, "web", renameOpts("www"))
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		e.Fault.Reset(0)
		if got.Status == api.OpSuccess {
			if k < 5 {
				t.Fatalf("only %d steps were faulted", k-1)
			}
			break
		}
		if now := jailState(t, e, s); now != before {
			t.Fatalf("failure at mutation %d (%s) left\n%s\ninstead of\n%s", k, got.Error.Message, now, before)
		}
	}
	if now := jailState(t, e, s); !strings.Contains(now, "jail www") {
		t.Fatal(now)
	}
}

func TestRenameJailNeedsTheAdminRole(t *testing.T) {
	e, s := newEnv(t)
	mkJail(t, e, s, as(globalAdmin, dtest.SeedProject), dtest.WebJail("web"))
	ctx := context.Background()
	op := e.Client(api.PermOperator).Project(dtest.SeedProject)
	if _, err := op.Jails().Rename(ctx, "web", api.Rename{NewName: "www"}, ""); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("an operator renamed a jail: %v", err)
	}
	h, err := e.Admin.Jails().Rename(ctx, "web", api.Rename{NewName: "www", DryRun: true}, "")
	if err != nil {
		t.Fatal(err)
	}
	if res, err := h.Wait(ctx); err != nil || !res.DryRun || res.To != "www" {
		t.Fatalf("%+v %v", res, err)
	}
	j, etag, err := e.Admin.Jails().GetETag(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Admin.Jails().Rename(ctx, "web", api.Rename{NewName: "www"}, "999"); !api.IsCode(err, api.CodeConflict) {
		t.Fatalf("a stale ETag was accepted: %v", err)
	}
	h, err = e.Admin.Jails().Rename(ctx, "web", api.Rename{NewName: "www"}, etag)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := h.Wait(ctx); err != nil || res.From != "web" {
		t.Fatalf("%+v %v (%s)", res, err, j.Metadata.Name)
	}
	if _, err := e.Admin.Jails().Get(ctx, "www"); err != nil {
		t.Fatal(err)
	}
}

// imageState is what an image rename touches.
func imageState(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	ctx := context.Background()
	g := as(globalAdmin, "")
	var b strings.Builder
	ims, _ := s.ListImages(g, nil)
	for _, im := range ims {
		b.WriteString("image " + im.Metadata.Name + "\n")
	}
	for _, n := range []string{"fb", "freebsd-15-1"} {
		ds := "tank/jailops/images/" + n + "/g1"
		if ok, _ := e.ZFS.Exists(ctx, ds); ok {
			m, _ := e.ZFS.Get(ctx, ds, "mountpoint", "jailops:image")
			b.WriteString("dataset " + ds + " " + m["mountpoint"].Value + " " + m["jailops:image"].Value + "\n")
		}
	}
	for _, p := range []string{dtest.SeedProject, "beta"} {
		l, _ := s.ListJails(as(globalAdmin, p), nil)
		for _, j := range l {
			c, _ := e.ZFS.Get(ctx, "tank/jailops/projects/"+p+"/jails/"+j.Metadata.Name, "jailops:image")
			b.WriteString("jail " + j.Metadata.Name + " " + j.Spec.Image + " " + c["jailops:image"].Value + "\n")
		}
	}
	if pr, err := s.GetProject(g, "beta"); err == nil {
		b.WriteString("beta images " + strings.Join(pr.Spec.Images, ",") + "\n")
	}
	for _, f := range []string{"fb.json", "freebsd-15-1.json"} {
		if _, err := os.Stat(filepath.Join(e.Cfg.StateDir, "image-upgrades", f)); err == nil {
			b.WriteString("runs " + f + "\n")
		}
	}
	return b.String()
}

func imageFixture(t *testing.T, e *dtest.Env, s *service.Service) {
	t.Helper()
	alpha := as(globalAdmin, dtest.SeedProject)
	mkJail(t, e, s, alpha, dtest.WebJail("web"))
	pin := dtest.WebJail("pin")
	pin.Spec.Image = "fb#g1"
	mkJail(t, e, s, alpha, pin)
	renameJailAction(t, e, s, alpha, "web", "start")
	net := e.MakeNetwork("beta")
	if _, err := s.CreateProject(as(globalAdmin, ""), api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}, Images: []string{"fb"}}}); err != nil {
		t.Fatal(err)
	}
	mkJail(t, e, s, as(globalAdmin, "beta"), dtest.WebJailOn("api", net))
	runs := filepath.Join(e.Cfg.StateDir, "image-upgrades", "fb.json")
	if err := os.MkdirAll(filepath.Dir(runs), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runs, []byte(`[{"result":"unchanged"}]`), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestRenameImage(t *testing.T) {
	e, s := newEnv(t)
	imageFixture(t, e, s)
	g := as(globalAdmin, "")
	_, _, err := s.RenameImage(as(alphaOnly, dtest.SeedProject), "fb", renameOpts("freebsd-15-1"))
	wantCode(t, err, api.CodeForbidden)
	before := imageState(t, e, s)
	res := doRename(t, s)(s.RenameImage(g, "fb", renameOpts("freebsd-15-1")))
	after := imageState(t, e, s)
	for _, want := range []string{
		"image freebsd-15-1\n",
		"dataset tank/jailops/images/freebsd-15-1/g1 /jailops/images/freebsd-15-1/g1 freebsd-15-1",
		"jail web freebsd-15-1@stable freebsd-15-1", "jail pin freebsd-15-1#g1 freebsd-15-1", "jail api freebsd-15-1@stable freebsd-15-1",
		"beta images freebsd-15-1", "runs freebsd-15-1.json",
	} {
		if !strings.Contains(after, want) {
			t.Fatalf("missing %q after:\n%s\nbefore:\n%s\n%+v", want, after, before, res)
		}
	}
	if strings.Contains(after, " fb") || strings.Contains(after, "fb.json") {
		t.Fatalf("the old name is left:\n%s", after)
	}
	if len(res.Warnings) == 0 {
		t.Error("no warning about backups")
	}
	// the jail kept running, and the renamed image still makes jails
	if j, _ := s.GetJail(as(globalAdmin, dtest.SeedProject), "web"); j.Status.Power != api.PowerRunning {
		t.Fatalf("web: %+v", j.Status)
	}
	mkJail(t, e, s, as(globalAdmin, dtest.SeedProject), func() api.Jail { j := dtest.WebJail("new"); j.Spec.Image = "freebsd-15-1@stable"; return j }())
	gens, err := s.ListGenerations(g, "freebsd-15-1")
	if err != nil || len(gens) != 1 {
		t.Fatalf("%+v %v", gens, err)
	}
}

func TestRenameImageRollsBackEveryStep(t *testing.T) {
	e, s := faultEnv(t)
	imageFixture(t, e, s)
	g := as(globalAdmin, "")
	before := imageState(t, e, s)
	for k := 1; ; k++ {
		if k > 120 {
			t.Fatal("the rename never succeeded")
		}
		e.Fault.Reset(k)
		op, _, err := s.RenameImage(g, "fb", renameOpts("freebsd-15-1"))
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		e.Fault.Reset(0)
		if got.Status == api.OpSuccess {
			if k < 5 {
				t.Fatalf("only %d steps were faulted", k-1)
			}
			break
		}
		if now := imageState(t, e, s); now != before {
			t.Fatalf("failure at mutation %d (%s) left\n%s\ninstead of\n%s", k, got.Error.Message, now, before)
		}
	}
}

// projectFixture: two stopped jails, a policy, a set, a profile and a token of project alpha.
func projectFixture(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	alpha := as(globalAdmin, dtest.SeedProject)
	if _, err := s.CreateAddressSet(alpha, api.AddressSet{Metadata: api.ObjectMeta{Name: "office"}, Spec: api.AddressSetSpec{Addresses: api.Entries("192.0.2.0/24")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePolicy(alpha, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow",
		Rules: []api.FirewallRule{{Action: "allow", Direction: "in", Proto: "tcp", From: []string{"set:office"}, Ports: []string{"443"}}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProfile(alpha, api.Profile{Metadata: api.ObjectMeta{Name: "small"}, Spec: api.ProfileSpec{Config: map[string]string{"firewall.policies": "web"}}}); err != nil {
		t.Fatal(err)
	}
	web := dtest.WebJail("web")
	web.Spec.Profiles = []string{"small"}
	mkJail(t, e, s, alpha, web)
	db := dtest.WebJail("db")
	db.Spec.Boot.Depends = []string{"web"}
	mkJail(t, e, s, alpha, db)
	return e.IdentityToken(api.PermOperator, false, dtest.SeedProject)
}

// projectState is what a project rename touches.
func projectState(t *testing.T, e *dtest.Env, s *service.Service) string {
	t.Helper()
	ctx := context.Background()
	g := as(globalAdmin, "")
	var b strings.Builder
	ps, _ := s.ListProjects(g, nil)
	for _, p := range ps {
		b.WriteString("project " + p.Metadata.Name + "\n")
		pc := as(globalAdmin, p.Metadata.Name)
		js, _ := s.ListJails(pc, nil)
		for _, j := range js {
			b.WriteString("  jail " + j.Metadata.Name + " " + j.Metadata.Project + "\n")
		}
		pols, _ := s.ListPolicies(pc, nil)
		for _, x := range pols {
			b.WriteString("  policy " + x.Metadata.Name + "\n")
		}
		sets, _ := s.ListAddressSets(pc, nil)
		for _, x := range sets {
			b.WriteString("  set " + x.Metadata.Name + "\n")
		}
		profs, _ := s.ListProfiles(pc, nil)
		for _, x := range profs {
			b.WriteString("  profile " + x.Metadata.Name + "\n")
		}
	}
	for _, n := range []string{"alpha", "alfa"} {
		ds := "tank/jailops/projects/" + n
		if ok, _ := e.ZFS.Exists(ctx, ds); ok {
			m, _ := e.ZFS.Get(ctx, ds+"/jails/web", "mountpoint", "jailops:project")
			b.WriteString("dataset " + ds + " " + m["mountpoint"].Value + " " + m["jailops:project"].Value + "\n")
		}
	}
	toks, _ := s.ListTokens(g, nil)
	for _, tk := range toks {
		if len(tk.Spec.Projects) > 0 {
			b.WriteString("token " + strings.Join(tk.Spec.Projects, ",") + "\n")
		}
	}
	return b.String()
}

func TestRenameProject(t *testing.T) {
	e, s := newEnv(t)
	tok := projectFixture(t, e, s)
	g := as(globalAdmin, "")
	renameJailAction(t, e, s, as(globalAdmin, dtest.SeedProject), "web", "start")
	_, _, err := s.RenameProject(g, dtest.SeedProject, renameOpts("alfa"))
	wantCode(t, err, api.CodeBusy) // a jail runs
	renameJailAction(t, e, s, as(globalAdmin, dtest.SeedProject), "web", "stop")
	_, _, err = s.RenameProject(as(alphaOnly, dtest.SeedProject), dtest.SeedProject, renameOpts("alfa"))
	wantCode(t, err, api.CodeForbidden)
	_, _, err = s.RenameProject(g, dtest.SeedProject, renameOpts("host"))
	if err == nil {
		t.Fatal("the reserved name was taken")
	}
	before := projectState(t, e, s)
	res := doRename(t, s)(s.RenameProject(g, dtest.SeedProject, renameOpts("alfa")))
	after := projectState(t, e, s)
	for _, want := range []string{"project alfa", "jail web alfa", "jail db alfa", "policy web", "set office", "profile small",
		"dataset tank/jailops/projects/alfa /jailops/projects/alfa/jails/web alfa", "token alfa"} {
		if !strings.Contains(after, want) {
			t.Fatalf("missing %q after:\n%s\nbefore:\n%s\n%+v", want, after, before, res)
		}
	}
	if strings.Contains(after, "alpha") {
		t.Fatalf("the old name is left:\n%s", after)
	}
	// the token of the project works in the new one, and its jails start under their new keys
	c := e.Anonymous()
	_ = c
	code, body := e.Raw("GET", "/api/v1/jails?project=alfa", tok, "")
	if code != 200 || !strings.Contains(body, `"web"`) {
		t.Fatalf("%d %s", code, body)
	}
	renameJailAction(t, e, s, as(globalAdmin, "alfa"), "web", "start")
	if _, ok, _ := e.Jails.Get(context.Background(), "alfa_web"); !ok {
		t.Fatal("alfa_web does not run")
	}
}

func TestRenameProjectRollsBackEveryStep(t *testing.T) {
	e, s := faultEnv(t)
	projectFixture(t, e, s)
	g := as(globalAdmin, "")
	before := projectState(t, e, s)
	for k := 1; ; k++ {
		if k > 200 {
			t.Fatal("the rename never succeeded")
		}
		e.Fault.Reset(k)
		op, _, err := s.RenameProject(g, dtest.SeedProject, renameOpts("alfa"))
		if err != nil {
			t.Fatal(err)
		}
		got := wait(t, s, op)
		e.Fault.Reset(0)
		if got.Status == api.OpSuccess {
			if k < 10 {
				t.Fatalf("only %d steps were faulted", k-1)
			}
			break
		}
		if now := projectState(t, e, s); now != before {
			t.Fatalf("failure at mutation %d (%s) left\n%s\ninstead of\n%s", k, got.Error.Message, now, before)
		}
	}
}

// A policy named in the list of a jail or in the list of a project is renamed in place: the order of the list stays.
func TestRenamePolicyInTheListsOfAJailAndAProject(t *testing.T) {
	e, s := newEnv(t)
	projectFixture(t, e, s)
	alpha := as(globalAdmin, dtest.SeedProject)
	for _, n := range []string{"first", "second", "floor1", "floor2"} {
		if _, err := s.CreatePolicy(alpha, api.FirewallPolicy{Metadata: api.ObjectMeta{Name: n}, Spec: api.FirewallPolicySpec{DefaultIn: "deny", DefaultOut: "allow"}}); err != nil {
			t.Fatal(err)
		}
	}
	j, err := s.GetJail(alpha, "web")
	if err != nil {
		t.Fatal(err)
	}
	j.Spec.Firewall.Policies = []string{"first", "second"}
	if _, err := s.UpdateJail(alpha, "web", j, service.AnyGeneration); err != nil {
		t.Fatal(err)
	}
	p, _ := s.GetProject(as(globalAdmin, ""), dtest.SeedProject)
	p.Spec.FirewallPolicies = []string{"floor1", "floor2"}
	if _, err := s.UpdateProject(as(globalAdmin, ""), dtest.SeedProject, p, service.AnyGeneration); err != nil {
		t.Fatal(err)
	}
	res := doRename(t, s)(s.RenamePolicy(alpha, "first", renameOpts("primary")))
	if !hasChange(res, api.RenameReference, "jail web") {
		t.Fatalf("%+v", res)
	}
	if j, _ := s.GetJail(alpha, "web"); !slices.Equal(j.Spec.Firewall.Policies, []string{"primary", "second"}) {
		t.Fatalf("%q", j.Spec.Firewall.Policies)
	}
	res = doRename(t, s)(s.RenamePolicy(alpha, "floor2", renameOpts("floorb")))
	if !hasChange(res, api.RenameReference, "project "+dtest.SeedProject) {
		t.Fatalf("%+v", res)
	}
	if p, _ := s.GetProject(as(globalAdmin, ""), dtest.SeedProject); !slices.Equal(p.Spec.FirewallPolicies, []string{"floor1", "floorb"}) {
		t.Fatalf("%q", p.Spec.FirewallPolicies)
	}
	// a policy that a list names is not deleted
	wantCode(t, s.DeletePolicy(alpha, "second", service.AnyGeneration), api.CodeBusy)
	wantCode(t, s.DeletePolicy(alpha, "floor1", service.AnyGeneration), api.CodeBusy)
}

func TestRenameFirewallObjectsAndProfiles(t *testing.T) {
	e, s := newEnv(t)
	projectFixture(t, e, s)
	alpha := as(globalAdmin, dtest.SeedProject)
	// an address set: the rules that name it follow
	res := doRename(t, s)(s.RenameAddressSet(alpha, "office", renameOpts("hq")))
	if !hasChange(res, api.RenameReference, "firewall policy web") {
		t.Fatalf("%+v", res)
	}
	pol, err := s.GetPolicy(alpha, "web")
	if err != nil || pol.Spec.Rules[0].From[0] != "set:hq" {
		t.Fatalf("%+v %v", pol.Spec, err)
	}
	_, _, err = s.RenameAddressSet(alpha, "hq", renameOpts("no_underscore"))
	wantCode(t, err, api.CodeInvalid) // a set name has no underscore: its table in pf has one for every hyphen
	// a policy: the profile and the jails that name it follow
	res = doRename(t, s)(s.RenamePolicy(alpha, "web", renameOpts("public")))
	if !hasChange(res, api.RenameReference, "profile small") {
		t.Fatalf("%+v", res)
	}
	prof, _ := s.GetProfile(alpha, "small")
	if prof.Spec.Config["firewall.policies"] != "public" {
		t.Fatalf("%+v", prof.Spec)
	}
	// a profile: the jails that apply it follow
	res = doRename(t, s)(s.RenameProfile(alpha, "small", renameOpts("tiny")))
	if !hasChange(res, api.RenameReference, "jail web") {
		t.Fatalf("%+v", res)
	}
	j, _ := s.GetJail(alpha, "web")
	if len(j.Spec.Profiles) != 1 || j.Spec.Profiles[0] != "tiny" {
		t.Fatalf("%+v", j.Spec.Profiles)
	}
	// a project administrator renames the objects of the project, not those of others
	_, _, err = s.RenamePolicy(as(alphaOnly, "ghost"), "public", renameOpts("x"))
	if err == nil {
		t.Fatal("renamed in a project the identity has no access to")
	}
	doRename(t, s)(s.RenamePolicy(as(alphaOnly, dtest.SeedProject), "public", renameOpts("web")))
	// the mandatory policy of a project is a global administrator's
	p, _ := s.GetProject(as(globalAdmin, ""), dtest.SeedProject)
	p.Spec.FirewallPolicies = []string{"web"}
	if _, err := s.UpdateProject(as(globalAdmin, ""), dtest.SeedProject, p, service.AnyGeneration); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.RenamePolicy(as(alphaOnly, dtest.SeedProject), "web", renameOpts("base"))
	wantCode(t, err, api.CodeForbidden)
	doRename(t, s)(s.RenamePolicy(alpha, "web", renameOpts("base")))
	if p, _ := s.GetProject(as(globalAdmin, ""), dtest.SeedProject); !slices.Equal(p.Spec.FirewallPolicies, []string{"base"}) {
		t.Fatalf("mandatory: %q", p.Spec.FirewallPolicies)
	}
}
