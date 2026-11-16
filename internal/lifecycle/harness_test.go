package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/lifecycle/fakes"
	"jailops.net/jailops/internal/lifecycle/fault"
	"jailops.net/jailops/internal/lifecycle/zfsmodel"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

var bg = context.Background()

// fakeImages serves generations that the world creates directly in the model.
type fakeImages struct {
	z        *zfsmodel.Model
	aliases  map[string]int // "<image>@<alias>"
	gens     map[string]api.ImageGeneration
	collects int
	// roots records the storage roots the lifecycle asked about.
	roots []string
}

func (f *fakeImages) Resolve(ctx context.Context, root, ref string) (api.ImageGeneration, error) {
	f.roots = append(f.roots, root)
	if img, a, ok := strings.Cut(ref, "@"); ok {
		n, ok := f.aliases[img+"@"+a]
		if !ok {
			return api.ImageGeneration{}, api.Errorf(api.CodeNotFound, "no alias %s", ref)
		}
		ref = fmt.Sprintf("%s#g%d", img, n)
	}
	g, ok := f.gens[ref]
	if !ok {
		return g, api.Errorf(api.CodeNotFound, "no generation %s", ref)
	}
	return g, nil
}
func (f *fakeImages) Ensure(ctx context.Context, root, ref string) (api.ImageGeneration, error) {
	return f.Resolve(ctx, root, ref)
}
func (f *fakeImages) Collect(context.Context) ([]string, error) { f.collects++; return nil, nil }

type world struct {
	t      *testing.T
	F      *fault.Injector
	Z      *zfsmodel.Model
	Files  *fakes.Files
	Exec   *fakes.Exec
	Jails  *fakes.Jails
	Hooks  *fakes.Hooks
	Images *fakeImages
	J      *plan.MemJournal
	S      *Service
	now    time.Time
	// merge simulates etcupdate: it writes into the jail's etc dataset.
	mergeOut string
	mergeErr error
	started  []string // generation of the root at each jail start
	// attach is what Config.Attached answers: the volumes attached to each jail key.
	attach map[string][]Attached
}

func newWorld(t *testing.T) *world {
	f := &fault.Injector{}
	w := &world{t: t, F: f, Z: zfsmodel.New(f, "tank"), Files: fakes.NewFiles(f), Exec: &fakes.Exec{F: f},
		Jails: fakes.NewJails(f), Hooks: &fakes.Hooks{F: f}, J: &plan.MemJournal{}, now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	for _, d := range []string{"tank/jailops", "tank/jailops/images", "tank/jailops/images/fb", "tank/jailops/images/alp", "tank/jailops/projects", "tank/jailops/projects/alpha", "tank/jailops/projects/alpha/jails"} {
		if err := w.Z.Create(bg, d, map[string]string{"jailops:managed": "on"}); err != nil {
			t.Fatal(err)
		}
	}
	w.Images = &fakeImages{z: w.Z, aliases: map[string]int{}, gens: map[string]api.ImageGeneration{}}
	w.addGen("fb", 1, "freebsd", "15.0-RELEASE")
	w.addGen("fb", 2, "freebsd", "15.0-RELEASE")
	w.addGen("alp", 1, "linux", "3.22")
	w.Images.aliases["fb@stable"] = 1
	w.Images.aliases["fb@latest"] = 2
	w.Images.aliases["alp@stable"] = 1
	w.Exec.Handler = w.handle
	w.Files.Trees["/jailops/projects/alpha/jails/web/root/etc"] = []string{"rc.conf"}
	w.attach = map[string][]Attached{}
	w.S = &Service{
		Cfg: Config{Root: "tank/jailops", MountBase: "/jailops", RootOldRetention: 24 * time.Hour,
			Now:      func() time.Time { return w.now },
			Attached: func(key string) ([]Attached, error) { return w.attach[key], nil }},
		ZFS: w.Z, Exec: w.Exec, Jails: w.Jails, Files: w.Files, Hooks: w.Hooks, Images: w.Images,
		Executor: &plan.Executor{Journal: w.J},
	}
	w.Jails.OnStart = func(name string) error {
		w.started = append(w.started, w.Z.PropOrEmpty(w.S.Cfg.at(name).rootDS(), PropGen))
		return nil
	}
	return w
}

func (w *world) addGen(image string, n int, os, rel string) {
	ds := fmt.Sprintf("tank/jailops/images/%s/g%d", image, n)
	err := w.Z.Create(bg, ds, map[string]string{"jailops:managed": "on", PropOS: os, PropOSRelease: rel, "jailops:manifest": fmt.Sprintf("sha256:m%d", n), "mountpoint": "/" + strings.TrimPrefix(ds, "tank/")})
	if err != nil {
		w.t.Fatal(err)
	}
	w.Z.WriteFile(ds, "/etc/version", fmt.Sprintf("g%d", n))
	if err := w.Z.Snapshot(bg, nil, ds+"@ro"); err != nil {
		w.t.Fatal(err)
	}
	name := fmt.Sprintf("%s#g%d", image, n)
	w.Images.gens[name] = api.ImageGeneration{Number: n, Name: name, Dataset: ds, Manifest: fmt.Sprintf("sha256:m%d", n)}
}

func (w *world) handle(argv []string) ([]byte, error) {
	if argv[0] != "etcupdate" || argv[1] == "extract" {
		return nil, nil
	}
	// etcupdate -d <work> -t <new-etc.tar> -D <jail root> -L <log>
	args := map[string]string{}
	for i := 1; i+1 < len(argv); i += 2 {
		args[argv[i]] = argv[i+1]
	}
	jail := path.Base(path.Dir(args["-D"]))
	w.Z.WriteFile(fmt.Sprintf("tank/jailops/projects/alpha/jails/%s/etc", jail), "/etc/merged", "from "+args["-t"])
	return []byte(w.mergeOut), w.mergeErr
}

// dbVol is the volume db of the project alpha, which the test jails attach at /srv/db.
const dbVol = "tank/jailops/projects/alpha/volumes/db"

func spec(image string) api.JailSpec {
	return api.JailSpec{Image: image, Update: api.UpdatePolicy{Strategy: api.UpdateRebase, Healthcheck: "/bin/true"},
		Resources: api.Resources{Disk: "10G"},
		Volumes:   []api.VolumeAttach{{Name: "db", Mount: "/srv/db"}}}
}

func (w *world) jail(name string) api.Jail {
	return api.Jail{Metadata: api.ObjectMeta{Name: name, Project: "alpha", UUID: "uuid-" + name}, Spec: spec("fb@stable")}
}

func (w *world) storage() Storage { return Storage{Root: "tank/jailops", MountBase: "/jailops"} }

// volume makes the volume of the project alpha (owner 5000:5000, mode 0770) when it is not there yet.
func (w *world) volume(name string) {
	w.t.Helper()
	if ok, _ := w.Z.Exists(bg, VolumeDS(w.storage(), "alpha", name)); ok {
		return
	}
	req := VolumeRequest{Storage: w.storage(), Project: "alpha", Name: name, UUID: "vol-" + name, Size: "5G", UID: 5000, GID: 5000, Mode: 0o770}
	if _, err := w.S.CreateVolume(bg, req, nil, false); err != nil {
		w.t.Fatal(err)
	}
}

// attachTo attaches a volume to the jail key at a path, as the service's answer to Config.Attached.
func (w *world) attachTo(key, volume, mount string, ro bool) {
	w.t.Helper()
	w.volume(volume)
	st := w.storage()
	w.attach[key] = append(w.attach[key], Attached{Dataset: VolumeDS(st, "alpha", volume), Mountpoint: VolumeMP(st, "alpha", volume), Path: mount, ReadOnly: ro})
}

// created makes a stopped jail named web (normalised: nothing mounted below the container). The jail attaches the
// volume db at /srv/db.
func (w *world) created(name string) {
	w.t.Helper()
	w.attachTo("alpha_"+name, "db", "/srv/db", false)
	if _, err := w.S.CreateJail(bg, w.jail(name), false); err != nil {
		w.t.Fatal(err)
	}
	if err := w.S.StopJail(bg, "alpha_"+name); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) running(name string) {
	w.t.Helper()
	w.created(name)
	if err := w.S.StartJail(bg, "alpha_"+name); err != nil {
		w.t.Fatal(err)
	}
}

// state captures the pool, the jail runtime and the files inside datasets
// that still exist; a failed operation must restore all of it.
func (w *world) state() string {
	var fs []string
	for _, p := range w.Files.Paths() {
		if strings.HasSuffix(p, ".previous") || !strings.HasPrefix(p, "/jailops/projects/alpha/jails/") {
			continue
		}
		jail := strings.Split(strings.TrimPrefix(p, "/jailops/projects/alpha/jails/"), "/")[0]
		if ok, _ := w.Z.Exists(bg, "tank/jailops/projects/alpha/jails/"+jail); !ok {
			continue
		}
		b, _ := w.Files.ReadFile(bg, p)
		fs = append(fs, p+"="+string(b))
	}
	var up []string
	for n := range w.Jails.Up {
		up = append(up, n)
	}
	return w.Z.Dump() + "\nFILES\n" + strings.Join(fs, "\n") + fmt.Sprintf("\nUP %v", up)
}

// sweep fails each mutating step of op in turn and requires the state to be
// restored exactly. setup builds the same fresh world every time.
func sweep(t *testing.T, setup func(t *testing.T) *world, op func(w *world) error) int {
	t.Helper()
	w := setup(t)
	w.F.Reset(0)
	if err := op(w); err != nil {
		t.Fatalf("baseline run failed: %v", err)
	}
	n := w.F.Count()
	if n == 0 {
		t.Fatal("no mutating operations")
	}
	failed := 0
	for k := 1; k <= n; k++ {
		w := setup(t)
		before := w.state()
		w.F.Reset(k)
		err := op(w)
		if err == nil {
			continue // the failure hit best-effort cleanup that is reported as a warning
		}
		failed++
		if !errors.Is(err, fault.ErrInjected) {
			t.Fatalf("op %d (%s): unexpected error %v", k, w.F.Log[k-1], err)
		}
		if after := w.state(); after != before {
			t.Fatalf("failing op %d/%d (%s) left the pool changed\nerr: %v\n--- before\n%s\n--- after\n%s", k, n, w.F.Log[k-1], err, before, after)
		}
		if len(w.J.Recs) != 0 {
			t.Fatalf("op %d: journal not cleaned: %v", k, w.J.Recs)
		}
	}
	if failed == 0 {
		t.Fatalf("none of %d injected failures surfaced as an error", n)
	}
	t.Logf("%d mutating operations, %d injected failures surfaced as errors; the rest hit best-effort cleanup", n, failed)
	return n
}

func wantCode(t *testing.T, err error, code api.Code) {
	t.Helper()
	if !api.IsCode(err, code) {
		t.Fatalf("want code %s, got %v", code, err)
	}
}

// crash simulates a daemon crash while step k (1-based) was in flight: steps
// 1..k have run to completion but the journal says step k was not finished.
func crash(t *testing.T, w *world, id string, p *plan.Plan, k int) {
	t.Helper()
	for i := 0; i < k; i++ {
		if err := p.Steps[i].Do(bg); err != nil {
			t.Fatalf("setup step %s: %v", p.Steps[i].Name, err)
		}
	}
	w.J.Put(bg, plan.Record{ID: id, Plan: p.Name, Steps: p.Names(), Begun: k, Done: k - 1, State: plan.StateRunning})
}
