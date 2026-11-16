package lifecycle

import (
	"encoding/json"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestCreateThin(t *testing.T) {
	w := newWorld(t)
	w.Files.Dirs["/jailops/projects/alpha/jails/web/root/etc"] = true // the image ships /etc but not /usr/local
	res, err := w.S.CreateJail(bg, w.jail("web"), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Jail.Status.Generation != "fb#g1" || res.Jail.Spec.Layout != api.LayoutThin {
		t.Fatalf("%+v", res.Jail)
	}
	c := "tank/jailops/projects/alpha/jails/web"
	if o, _ := w.Z.Origin(bg, c+"/root"); o != "tank/jailops/images/fb/g1@ro" {
		t.Fatalf("root origin %q", o)
	}
	want := []string{c, c + "/etc", c + "/home", c + "/local", c + "/rootdir", c + "/root", c + "/var-db", c + "/var-log", c + "/var-mail", c + "/var-spool"}
	have := map[string]bool{}
	for _, n := range w.Z.Names() {
		have[n] = true
	}
	// a jail owns no volume dataset: the volume it attaches is the project's
	if have[c+"/data"] || have[c+"/data/db"] {
		t.Error("the jail has volume datasets of its own")
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("missing dataset %s", n)
		}
	}
	checks := map[[2]string]string{
		{c, PropManaged}: "on", {c, PropID}: "uuid-web", {c, PropComplete}: "on", {c, PropKind}: KindContainer,
		{c + "/root", PropGen}: "1", {c, "quota"}: "10G", {c + "/root", "quota"}: "", {c + "/root", "mountpoint"}: "/jailops/projects/alpha/jails/web/root",
		{c + "/etc", "mountpoint"}: "/jailops/projects/alpha/jails/web/root/etc", {c + "/etc", PropClass}: "system", {c + "/etc", PropMerge}: "on",
		{c + "/home", PropClass}: "data",
	}
	for k, v := range checks {
		if got := w.Z.PropOrEmpty(k[0], k[1]); got != v {
			t.Errorf("%s %s = %q want %q", k[0], k[1], got, v)
		}
	}
	// persistent datasets were seeded from the image before being mounted over it
	seeded := false
	for _, l := range w.F.Log {
		if strings.HasPrefix(l, "copytree /jailops/projects/alpha/jails/web/root/etc ") {
			seeded = true
		}
	}
	if !seeded {
		t.Fatal("etc not seeded", w.F.Log)
	}
	for _, l := range w.F.Log {
		if strings.HasPrefix(l, "copytree /jailops/projects/alpha/jails/web/root/usr/local ") {
			t.Fatalf("a directory the image does not ship must not be copied: %s", l)
		}
	}
	var rec Record
	b, _ := w.Files.ReadFile(bg, "/jailops/projects/alpha/jails/web/spec.json")
	if err := json.Unmarshal(b, &rec); err != nil || rec.Metadata.Name != "web" || rec.Spec.Image != "fb@stable" {
		t.Fatal(err, rec)
	}
	var bd Bundle
	b, _ = w.Files.ReadFile(bg, "/jailops/projects/alpha/jails/web/bundle.json")
	if err := json.Unmarshal(b, &bd); err != nil || bd.Image.Name != "fb#g1" || bd.Image.Manifest != "sha256:m1" {
		t.Fatal(err, bd)
	}
	if _, err := w.S.CreateJail(bg, w.jail("web"), false); !api.IsCode(err, api.CodeAlreadyExists) {
		t.Fatal(err)
	}
}

func TestCreateThickLinux(t *testing.T) {
	w := newWorld(t)
	j := w.jail("deb")
	j.Spec.Image = "alp@stable"
	j.Spec.Volumes = nil
	if _, err := w.S.CreateJail(bg, j, false); err != nil {
		t.Fatal(err)
	}
	c := "tank/jailops/projects/alpha/jails/deb"
	if o, _ := w.Z.Origin(bg, c+"/root"); o != "" {
		t.Fatalf("thick root must be independent, origin %q", o)
	}
	if s, _ := w.Z.Snapshots(bg, c+"/root"); len(s) != 0 {
		t.Fatalf("copied @ro left on the root: %v", s)
	}
	if ok, _ := w.Z.Exists(bg, c+"/etc"); ok {
		t.Fatal("thick jails have no persistent datasets")
	}
	if got := w.Z.PropOrEmpty(c, PropLayout); got != "thick" {
		t.Fatal(got)
	}
	// The emulation directory exists in the real root before the first start.
	if !w.Files.Dirs["/jailops/projects/alpha/jails/deb/root/dev/shm"] {
		t.Fatalf("dev/shm was not created: %v", w.Files.Dirs)
	}
	// the generation can be destroyed from under no clone: it has no dependent
	if cl, _ := w.Z.Clones(bg, "tank/jailops/images/alp/g1@ro"); len(cl) != 0 {
		t.Fatal(cl)
	}
	j2 := w.jail("x")
	j2.Spec.Layout = api.LayoutThin
	j2.Spec.Image = "alp@stable"
	if _, err := w.S.CreateJail(bg, j2, false); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("thin Linux jail accepted: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		name string
		mut  func(j *api.Jail)
		code api.Code
	}{
		{"bad name", func(j *api.Jail) { j.Metadata.Name = "Web/1" }, api.CodeInvalid},
		{"no uuid", func(j *api.Jail) { j.Metadata.UUID = "" }, api.CodeInvalid},
		{"no image", func(j *api.Jail) { j.Spec.Image = "" }, api.CodeInvalid},
		{"unknown image", func(j *api.Jail) { j.Spec.Image = "nope@stable" }, api.CodeNotFound},
		{"encrypted", func(j *api.Jail) { j.Spec.Encrypted = true }, api.CodeUnsupported},
		{"packages", func(j *api.Jail) { j.Spec.Packages = []string{"nginx"} }, api.CodeUnsupported},
		{"bad quota", func(j *api.Jail) { j.Spec.Resources.Disk = "lots" }, api.CodeInvalid},
		{"relative mount", func(j *api.Jail) { j.Spec.Volumes[0].Mount = "srv/db" }, api.CodeInvalid},
		{"dotdot mount", func(j *api.Jail) { j.Spec.Volumes[0].Mount = "/srv/../etc" }, api.CodeInvalid},
		{"mount over persistent", func(j *api.Jail) { j.Spec.Volumes[0].Mount = "/etc" }, api.CodeInvalid},
		{"dup volume", func(j *api.Jail) { j.Spec.Volumes = append(j.Spec.Volumes, j.Spec.Volumes[0]) }, api.CodeInvalid},
		{"bad volume name", func(j *api.Jail) { j.Spec.Volumes[0].Name = "a/b" }, api.CodeInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			before := w.state()
			j := w.jail("web")
			j.Spec.Volumes = append([]api.VolumeAttach(nil), j.Spec.Volumes...)
			tc.mut(&j)
			if _, err := w.S.CreateJail(bg, j, false); !api.IsCode(err, tc.code) {
				t.Fatalf("got %v", err)
			}
			if w.state() != before {
				t.Fatal("state changed")
			}
		})
	}
}

func TestCreateDryRun(t *testing.T) {
	w := newWorld(t)
	before := w.state()
	w.F.Reset(0)
	r, err := w.S.CreateJail(bg, w.jail("web"), true)
	if err != nil || w.F.Count() != 0 || w.state() != before || len(r.Plan) < 10 {
		t.Fatal(err, w.F.Count(), len(r.Plan))
	}
}

func TestCreateFailureSweep(t *testing.T) {
	for name, img := range map[string]string{"thin": "fb@stable", "thick": "alp@stable"} {
		t.Run(name, func(t *testing.T) {
			sweep(t, newWorld, func(w *world) error {
				j := w.jail("web")
				j.Spec.Image = img
				_, err := w.S.CreateJail(bg, j, false)
				return err
			})
		})
	}
}

func TestCreateNeverTouchesForeignDataset(t *testing.T) {
	w := newWorld(t)
	// a foreign dataset appears at the container name while the plan is built
	p, _, err := w.S.PlanCreate(bg, w.jail("web"), false)
	if err != nil {
		t.Fatal(err)
	}
	w.Z.Create(bg, "tank/jailops/projects/alpha/jails/web", map[string]string{"foreign": "yes"})
	if err := w.S.executor().Run(bg, "create/web", p); err == nil {
		t.Fatal("create over a foreign dataset succeeded")
	}
	if ok, _ := w.Z.Exists(bg, "tank/jailops/projects/alpha/jails/web"); !ok {
		t.Fatal("foreign dataset destroyed by undo")
	}
}

func TestCreateCrashRecovery(t *testing.T) {
	w := newWorld(t)
	p, _, err := w.S.PlanCreate(bg, w.jail("web"), false)
	if err != nil {
		t.Fatal(err)
	}
	steps := len(p.Steps)
	for k := 1; k <= steps; k++ {
		w := newWorld(t)
		before := w.state()
		p, _, _ := w.S.PlanCreate(bg, w.jail("web"), false)
		crash(t, w, "create/alpha_web", p, k)
		rp, _, err := w.S.PlanCreate(bg, w.jail("web"), true)
		if err != nil {
			t.Fatal(err)
		}
		if found, err := w.S.RecoverRun(bg, "create", "alpha_web", rp); !found || err != nil {
			t.Fatal(found, err)
		}
		if w.state() != before {
			t.Fatalf("crash after %d steps: not restored\n%s", k, w.Z.Dump())
		}
	}
}

func TestAJailBelongsToANamedProject(t *testing.T) {
	w := newWorld(t)
	j := w.jail("web")
	j.Metadata.Project = ""
	if _, err := w.S.CreateJail(bg, j, false); err == nil {
		t.Fatal("a jail without a project was created")
	}
	if _, err := KeyOf(j); err == nil {
		t.Fatal("a key without a project")
	}
	if p, n := splitKey("web"); p != "" || n != "" {
		t.Fatalf("a plain key split into %q %q", p, n)
	}
	if k, err := qualify("default", "web"); err != nil || k != "default_web" {
		t.Fatalf("%q %v: default is only a name", k, err)
	}
}

// The disk limit and the reservation of a jail are properties of its container, which cover everything below it; the
// root clone carries neither.
func TestDiskLimitIsOnTheContainer(t *testing.T) {
	w := newWorld(t)
	w.Files.Dirs["/jailops/projects/alpha/jails/web/root/etc"] = true
	j := w.jail("web")
	j.Spec.Resources.DiskReservation = "3G"
	if _, err := w.S.CreateJail(bg, j, false); err != nil {
		t.Fatal(err)
	}
	c := "tank/jailops/projects/alpha/jails/web"
	for _, k := range [][3]string{{c, "quota", "10G"}, {c, "reservation", "3G"}, {c + "/root", "quota", ""}, {c + "/root", "reservation", ""}, {c + "/var-db", "quota", ""}} {
		if got := w.Z.PropOrEmpty(k[0], k[1]); got != k[2] {
			t.Errorf("%s %s = %q want %q", k[0], k[1], got, k[2])
		}
	}
}
