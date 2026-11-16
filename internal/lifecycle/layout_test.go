package lifecycle

import (
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestLayoutListsEveryDatasetWithItsKind(t *testing.T) {
	w := runningSetup(t)
	lay, err := w.S.Layout(bg, "alpha_web")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, d := range lay.Datasets {
		kinds[strings.TrimPrefix(d.Name, lay.Container)] = d.Kind
	}
	for rel, kind := range map[string]string{"": KindContainer, "/root": KindBackupRoot, "/etc": KindPersistent} {
		if kinds[rel] != kind {
			t.Errorf("%q is %q, want %q (%v)", rel, kinds[rel], kind, kinds)
		}
	}
	if lay.Layout != api.LayoutThin || lay.Image != "fb" || lay.Generation != 1 {
		t.Fatalf("%+v", lay)
	}
	for _, d := range lay.Datasets {
		if d.Kind == KindVolume || d.Kind == KindVolumes {
			t.Errorf("a jail's layout lists a volume: %v", d)
		}
		if d.Kind == KindContainer && (d.Props[PropLayout] != string(api.LayoutThin) || d.Props[PropImage] != "fb") {
			t.Errorf("the container must record layout and image, or a restored jail cannot be observed: %v", d.Props)
		}
		if d.Kind == KindPersistent && d.Props[PropPath] == "" {
			t.Errorf("%s has no recorded path", d.Name)
		}
	}
	if _, err := w.S.Layout(bg, "alpha_ghost"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
}

func TestWriteRecordsMakesTheJailRebuildable(t *testing.T) {
	w := runningSetup(t)
	j := w.jail("web")
	j.Metadata.Project = "default"
	j.Spec.Image = "fb@stable"
	gen, _ := w.Images.Resolve(bg, "tank/jailops", "fb#g1")
	delete(w.Files.Data, "/jailops/projects/alpha/jails/web/spec.json")
	if err := w.S.WriteRecords(bg, "alpha_web", j, gen); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"spec.json", "bundle.json"} {
		if len(w.Files.Data["/jailops/projects/alpha/jails/web/"+f]) == 0 {
			t.Errorf("%s not written", f)
		}
	}
	r, err := w.S.Rebuild(bg, "alpha_web")
	if err != nil || r.FromBundle || r.Jail.Spec.Image != "fb@stable" {
		t.Fatalf("%+v %v", r, err)
	}
}
