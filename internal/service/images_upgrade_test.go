package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/internal/sys/jailos"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// tickingEnv is newEnv with a clock that moves one second per reading: the
// rollback snapshot of a jail is named by the second, and these tests move a
// jail again within a second of its last move.
func tickingEnv(t *testing.T) (*dtest.Env, *service.Service) {
	t.Helper()
	var mu sync.Mutex
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	e := dtest.New(t, dtest.Options{Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Second)
		return now
	}})
	e.Seed()
	return e, e.D.Service()
}

// upgradeImage runs an image upgrade to the end and returns its result.
func upgradeImage(t *testing.T, s *service.Service, ctx context.Context, image string, req api.ImageUpgrade) api.ImageUpgradeResult {
	t.Helper()
	op, err := s.UpgradeImage(ctx, image, req)
	if err != nil {
		t.Fatal(err)
	}
	got := wait(t, s, op)
	if got.Status != api.OpSuccess {
		t.Fatalf("upgrade image: %+v", got)
	}
	var res api.ImageUpgradeResult
	if err := json.Unmarshal(got.Metadata, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// twoProjectJails makes the jails of the image upgrade tests: in alpha "web"
// (running), "db" (stopped) and "pin" (pinned to fb#g1); in beta "api".
func twoProjectJails(t *testing.T, e *dtest.Env, s *service.Service) {
	t.Helper()
	alpha := as(globalAdmin, dtest.SeedProject)
	net := e.MakeNetwork("beta")
	if _, err := s.CreateProject(as(globalAdmin, ""), api.Project{Metadata: api.ObjectMeta{Name: "beta"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: net}}, Storage: []api.ProjectStorage{{Storage: "default"}}}}); err != nil {
		t.Fatal(err)
	}
	mk := func(ctx context.Context, j api.Jail) {
		t.Helper()
		op, err := s.CreateJail(ctx, j)
		if err != nil {
			t.Fatal(err)
		}
		if got := wait(t, s, op); got.Status != api.OpSuccess {
			t.Fatalf("create %s: %+v\n%s", j.Metadata.Name, got, e.Log())
		}
	}
	mk(alpha, dtest.WebJail("web"))
	mk(alpha, dtest.WebJail("db"))
	pin := dtest.WebJail("pin")
	pin.Spec.Image = "fb#g1"
	mk(alpha, pin)
	mk(as(globalAdmin, "beta"), dtest.WebJailOn("api", net))
	op, err := s.JailAction(alpha, "web", api.JailAction{Action: "start"})
	if err != nil {
		t.Fatal(err)
	}
	if got := wait(t, s, op); got.Status != api.OpSuccess {
		t.Fatalf("start web: %+v\n%s", got, e.Log())
	}
}

func generationOf(t *testing.T, s *service.Service, project, name string) (gen string, running bool) {
	t.Helper()
	j, err := s.GetJail(as(globalAdmin, project), name)
	if err != nil {
		t.Fatal(err)
	}
	return j.Status.Generation, j.Status.Power == api.PowerRunning
}

func TestUpgradeImageMovesEveryThinJailAndStopsAtTheFirstFailure(t *testing.T) {
	e, s := tickingEnv(t)
	twoProjectJails(t, e, s)
	host := as(globalAdmin, "")

	// The repository serves what g1 holds: nothing is kept and no jail is touched.
	res := upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	if !res.Unchanged || res.Generation != nil || res.From != "fb#g1" || len(res.Jails) != 4 {
		t.Fatalf("%+v", res)
	}
	for _, j := range res.Jails {
		if j.Status != api.ImageUpgradeSkipped {
			t.Fatalf("%+v", j)
		}
	}
	if im, _ := s.GetImage(host, "fb"); len(im.Status.Generations) != 1 {
		t.Fatalf("an unchanged upgrade kept a generation: %+v", im.Status)
	}

	// A newer package set: g2 is built and every candidate moves, stopped or running; the pin is the user's choice.
	e.SetRepoVersion("15.0p2")
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	if res.Unchanged || res.Generation == nil || res.Generation.Number != 2 || res.Generation.Parent != 1 || len(res.Plan) == 0 {
		t.Fatalf("%+v", res)
	}
	want := map[string]string{"alpha/db": api.ImageUpgradeUpgraded, "alpha/pin": api.ImageUpgradeSkipped, "alpha/web": api.ImageUpgradeUpgraded, "beta/api": api.ImageUpgradeUpgraded}
	if len(res.Jails) != len(want) {
		t.Fatalf("%+v", res.Jails)
	}
	for i, j := range res.Jails {
		key := j.Project + "/" + j.Jail
		if j.Status != want[key] {
			t.Fatalf("jail %d: %+v", i, j)
		}
		if j.Status == api.ImageUpgradeUpgraded && (j.From != "fb#g1" || j.To != "fb#g2" || j.Record == "") {
			t.Fatalf("%+v", j)
		}
		if j.Status == api.ImageUpgradeSkipped && j.Reason != "pinned to fb#g1" {
			t.Fatalf("%+v", j)
		}
	}
	for _, c := range []struct {
		project, name, gen string
		running            bool
	}{{"alpha", "web", "fb#g2", true}, {"alpha", "db", "fb#g2", false}, {"alpha", "pin", "fb#g1", false}, {"beta", "api", "fb#g2", false}} {
		if gen, up := generationOf(t, s, c.project, c.name); gen != c.gen || up != c.running {
			t.Fatalf("%s/%s: on %s, running %v\n%s", c.project, c.name, gen, up, e.Log())
		}
	}
	// The same history record as an OS update of `update apply`.
	h, err := s.UpdateHistory(as(globalAdmin, "beta"), "api")
	if err != nil || len(h) != 1 || h[0].Kind != api.UpdateKindOS || h[0].Result != api.UpdateOK || h[0].ID != res.Jails[3].Record || h[0].To != "fb#g2" {
		t.Fatalf("%+v %v", h, err)
	}

	// g3 fails its health check: the first jail is swapped back and the rest are not attempted.
	e.SetRepoVersion("15.0p3")
	e.Jails.SetExecFn(func(_ string, o jailos.ExecOpts) (run.Result, error) {
		if strings.Join(o.Argv, " ") == "/bin/true" {
			return run.Result{Stderr: []byte("not healthy")}, errors.New("exit status 1")
		}
		return run.Result{}, nil
	})
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	if res.Generation == nil || res.Generation.Number != 3 || len(res.Jails) != 4 {
		t.Fatalf("%+v", res)
	}
	if j := res.Jails[0]; j.Jail != "db" || j.Status != api.ImageUpgradeFailed || !strings.Contains(j.Reason, "health check") || !strings.Contains(j.Reason, "swapped back") {
		t.Fatalf("%+v", j)
	}
	if j := res.Jails[1]; j.Jail != "pin" || j.Status != api.ImageUpgradeSkipped {
		t.Fatalf("%+v", j)
	}
	for _, j := range res.Jails[2:] {
		if j.Status != api.ImageUpgradeNotAttempted || j.Reason != "stopped after alpha/db failed" {
			t.Fatalf("%+v", j)
		}
	}
	for _, c := range []struct{ project, name string }{{"alpha", "web"}, {"alpha", "db"}, {"beta", "api"}} {
		if gen, _ := generationOf(t, s, c.project, c.name); gen != "fb#g2" {
			t.Fatalf("%s/%s moved to %s", c.project, c.name, gen)
		}
	}
	h, _ = s.UpdateHistory(as(globalAdmin, dtest.SeedProject), "db")
	if len(h) != 2 || h[0].Result != api.UpdateRolledBack || !h[0].RootRolledBack {
		t.Fatalf("%+v", h)
	}
	if h, _ := s.UpdateHistory(as(globalAdmin, "beta"), "api"); len(h) != 1 {
		t.Fatalf("a jail that was not attempted got a record: %+v", h)
	}
}

func TestUpgradeImageIsAGlobalAdminsOperationAndHonoursTheProjectFilter(t *testing.T) {
	e, s := tickingEnv(t)
	twoProjectJails(t, e, s)
	host := as(globalAdmin, "")
	e.SetRepoVersion("15.0p2")

	// A project identity may not upgrade an image, however it names the project, so it never moves another project's jails.
	for _, ctx := range []context.Context{as(alphaOnly, dtest.SeedProject), as(alphaOnly, ""), as(nobody, "")} {
		for _, req := range []api.ImageUpgrade{{}, {Project: "beta"}, {Project: dtest.SeedProject}, {NoJails: true}} {
			_, err := s.UpgradeImage(ctx, "fb", req)
			wantCode(t, err, api.CodeForbidden)
		}
	}
	for _, c := range []struct{ project, name string }{{"alpha", "web"}, {"beta", "api"}} {
		if gen, _ := generationOf(t, s, c.project, c.name); gen != "fb#g1" {
			t.Fatalf("%s/%s moved to %s", c.project, c.name, gen)
		}
	}
	if im, _ := s.GetImage(host, "fb"); len(im.Status.Generations) != 1 {
		t.Fatalf("%+v", im.Status)
	}
	_, err := s.UpgradeImage(host, "fb", api.ImageUpgrade{Project: "nope"})
	wantCode(t, err, api.CodeNotFound)
	_, err = s.UpgradeImage(host, "nope", api.ImageUpgrade{})
	wantCode(t, err, api.CodeNotFound)
	// An image without a generation says what to run first.
	if _, err := s.CreateImage(host, api.Image{Metadata: api.ObjectMeta{Name: "empty"}, Spec: api.ImageSpec{
		OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}}); err != nil {
		t.Fatal(err)
	}
	_, err = s.UpgradeImage(host, "empty", api.ImageUpgrade{})
	wantCode(t, err, api.CodeNotFound)
	var ae *api.Error
	if !errors.As(err, &ae) || !strings.Contains(ae.Hint, "jailops image build empty") {
		t.Fatalf("%v", err)
	}

	// A dry run plans the build and lists the jails that would move; nothing changes.
	res := upgradeImage(t, s, host, "fb", api.ImageUpgrade{DryRun: true})
	if !res.DryRun || res.Generation != nil || len(res.Plan) == 0 || len(res.Jails) != 4 {
		t.Fatalf("%+v", res)
	}
	for _, j := range res.Jails {
		if j.Jail == "pin" && j.Status != api.ImageUpgradeSkipped || j.Jail != "pin" && (j.Status != api.ImageUpgradePlanned || j.To != "fb#g2") {
			t.Fatalf("%+v", j)
		}
	}
	if im, _ := s.GetImage(host, "fb"); len(im.Status.Generations) != 1 {
		t.Fatalf("a dry run kept a generation: %+v", im.Status)
	}
	if gen, _ := generationOf(t, s, "alpha", "web"); gen != "fb#g1" {
		t.Fatalf("a dry run moved a jail to %s", gen)
	}

	// The project filter moves one project's jails and lists only them.
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{Project: "beta"})
	if res.Generation == nil || res.Generation.Number != 2 || len(res.Jails) != 1 || res.Jails[0].Jail != "api" || res.Jails[0].Status != api.ImageUpgradeUpgraded {
		t.Fatalf("%+v", res)
	}
	if gen, _ := generationOf(t, s, "alpha", "web"); gen != "fb#g1" {
		t.Fatalf("the filter did not hold: web is on %s", gen)
	}
	// NoJails builds only.
	e.SetRepoVersion("15.0p3")
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{NoJails: true})
	if res.Generation == nil || res.Generation.Number != 3 || len(res.Jails) != 4 {
		t.Fatalf("%+v", res)
	}
	for _, j := range res.Jails {
		if j.Jail != "pin" && j.Status != api.ImageUpgradeNotAttempted {
			t.Fatalf("%+v", j)
		}
	}
	if gen, _ := generationOf(t, s, "beta", "api"); gen != "fb#g2" {
		t.Fatalf("no_jails moved a jail to %s", gen)
	}
}

func TestImageReleaseOlderThan151IsRefused(t *testing.T) {
	_, s := tickingEnv(t)
	host := as(globalAdmin, "")
	for _, r := range []string{"15.0-RELEASE", "14.3-RELEASE", "bogus"} {
		_, err := s.CreateImage(host, api.Image{Metadata: api.ObjectMeta{Name: "old"}, Spec: api.ImageSpec{
			OS: api.OSFreeBSD, Release: r, Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}})
		wantCode(t, err, api.CodeInvalid)
	}
	for i, r := range []string{"15.1-RELEASE", "15.2-PRERELEASE", "16.0-CURRENT"} {
		if _, err := s.CreateImage(host, api.Image{Metadata: api.ObjectMeta{Name: "ok" + string(rune('a'+i))}, Spec: api.ImageSpec{
			OS: api.OSFreeBSD, Release: r, Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}}); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
}

// A run that stopped at a failing jail leaves the jails after it on the old generation. The next run builds nothing
// (the package set did not change) but still moves them to the newest generation.
func TestUpgradeImageMovesJailsThatAreBehindWhenNothingNewWasBuilt(t *testing.T) {
	e, s := tickingEnv(t)
	twoProjectJails(t, e, s)
	host := as(globalAdmin, "")
	e.SetRepoVersion("15.0p2")
	e.Jails.SetExecFn(func(_ string, o jailos.ExecOpts) (run.Result, error) {
		if strings.Join(o.Argv, " ") == "/bin/true" {
			return run.Result{Stderr: []byte("not healthy")}, errors.New("exit status 1")
		}
		return run.Result{}, nil
	})
	res := upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	if res.Generation == nil || res.Generation.Number != 2 {
		t.Fatalf("%+v", res)
	}
	for _, c := range []struct{ project, name string }{{"alpha", "web"}, {"alpha", "db"}, {"beta", "api"}} {
		if gen, _ := generationOf(t, s, c.project, c.name); gen != "fb#g1" {
			t.Fatalf("%s/%s is on %s after a failed run", c.project, c.name, gen)
		}
	}

	e.Jails.SetExecFn(func(string, jailos.ExecOpts) (run.Result, error) { return run.Result{}, nil })
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	if !res.Unchanged || res.Generation != nil {
		t.Fatalf("a generation was built again: %+v", res)
	}
	moved := 0
	for _, j := range res.Jails {
		if j.Status == api.ImageUpgradeUpgraded && j.To == "fb#g2" {
			moved++
		}
	}
	if moved != 3 {
		t.Fatalf("%+v", res.Jails)
	}
	for _, c := range []struct{ project, name string }{{"alpha", "web"}, {"alpha", "db"}, {"beta", "api"}} {
		if gen, _ := generationOf(t, s, c.project, c.name); gen != "fb#g2" {
			t.Fatalf("%s/%s is on %s", c.project, c.name, gen)
		}
	}
	// And a third run has nothing left to do.
	res = upgradeImage(t, s, host, "fb", api.ImageUpgrade{})
	for _, j := range res.Jails {
		if j.Status == api.ImageUpgradeUpgraded {
			t.Fatalf("%+v", j)
		}
	}
}
