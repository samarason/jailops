package api_test

import (
	"reflect"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func bj(project, name string, auto bool, prio int, deps ...string) api.BootJail {
	b := api.BootJail{Key: project + "_" + name, Project: project, Name: name, Boot: api.BootPolicy{Autostart: auto, Priority: prio}}
	for _, d := range deps {
		b.Boot.Depends = append(b.Boot.Depends, project+"_"+d)
	}
	return b
}

func names(p api.BootPlan) []string {
	var out []string
	for _, e := range p.Order {
		out = append(out, e.Project+"/"+e.Jail)
	}
	return out
}

func TestPlanBootOrder(t *testing.T) {
	p := api.PlanBoot([]api.BootJail{
		bj("a", "web", true, 1, "db"), bj("a", "db", false, 9), bj("a", "cache", true, 0), bj("a", "idle", false, 0), bj("b", "edge", true, -1),
	})
	if got, want := names(p), []string{"b/edge", "a/cache", "a/db", "a/web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v want %v", got, want)
	}
	if p.Order[2].Reason != "dependency of web" || p.Order[3].Reason != "autostart" || p.Order[3].Position != 4 || !reflect.DeepEqual(p.Order[3].Depends, []string{"db"}) {
		t.Fatalf("%+v", p.Order)
	}
	if len(p.NotStarted) != 0 {
		t.Fatalf("%+v", p.NotStarted)
	}
}

func TestPlanBootDependencyOfADependency(t *testing.T) {
	p := api.PlanBoot([]api.BootJail{bj("a", "web", true, 0, "app"), bj("a", "app", false, 0, "db"), bj("a", "db", false, 0)})
	if got, want := names(p), []string{"a/db", "a/app", "a/web"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order %v want %v", got, want)
	}
	if p.Order[0].Reason != "dependency of web" || p.Order[1].Reason != "dependency of web" {
		t.Fatalf("%+v", p.Order)
	}
}

func TestPlanBootCycleAndMissingDependency(t *testing.T) {
	p := api.PlanBoot([]api.BootJail{bj("a", "x", true, 0, "y"), bj("a", "y", true, 0, "x"), bj("a", "lost", true, 0, "ghost"), bj("a", "ok", true, 0)})
	if got := names(p); !reflect.DeepEqual(got, []string{"a/ok"}) {
		t.Fatalf("order %v", got)
	}
	why := map[string]string{}
	for _, s := range p.NotStarted {
		why[s.Jail] = s.Reason
	}
	if !strings.Contains(why["x"], "cycle") || !strings.Contains(why["y"], "cycle") || !strings.Contains(why["lost"], "ghost") {
		t.Fatalf("%+v", p.NotStarted)
	}
	// the reasons name the jails, not their keys
	if strings.Contains(why["x"], "a_") || strings.Contains(why["lost"], "a_") {
		t.Fatalf("keys in %+v", why)
	}
}

func TestPlanBootLockedJailAndItsDependents(t *testing.T) {
	vault := bj("a", "vault", true, 0)
	vault.Encrypted = true
	p := api.PlanBoot([]api.BootJail{vault, bj("a", "report", true, 0, "vault"), bj("a", "web", true, 1)})
	if got := names(p); !reflect.DeepEqual(got, []string{"a/web"}) {
		t.Fatalf("order %v", got)
	}
	why := map[string]string{}
	for _, s := range p.NotStarted {
		why[s.Jail] = s.Reason
	}
	if !strings.Contains(why["vault"], "jailops volume unlock VOLUME") || !strings.Contains(why["report"], "depends on vault") {
		t.Fatalf("%+v", p.NotStarted)
	}
}

func TestPlanBootIsThePlanOfABootWhatEverRuns(t *testing.T) {
	web := bj("a", "web", true, 0)
	web.Running = true
	p := api.PlanBoot([]api.BootJail{web})
	if len(p.Order) != 1 || !p.Order[0].Running {
		t.Fatalf("%+v", p)
	}
}

func TestBootPlanVisible(t *testing.T) {
	p := api.PlanBoot([]api.BootJail{bj("a", "one", true, 0), bj("b", "two", true, 1), bj("a", "three", true, 2)})
	v := p.Visible(func(project string) bool { return project == "a" })
	if got := names(v); !reflect.DeepEqual(got, []string{"a/one", "a/three"}) || v.Order[1].Position != 2 {
		t.Fatalf("%v %+v", got, v.Order)
	}
	if v.Order == nil || v.NotStarted == nil {
		t.Fatal("empty lists are not nil")
	}
}

func TestStopOrderIsTheReverseOfTheStartOrder(t *testing.T) {
	node := func(key string, prio int, deps ...string) api.BootNode {
		return api.BootNode{Key: key, Boot: api.BootPolicy{Priority: prio, Depends: deps}}
	}
	for name, tc := range map[string]struct {
		running []api.BootNode
		want    []string
	}{
		"dependents first": {[]api.BootNode{node("a/db", 0), node("a/web", 0, "a/db"), node("a/cache", 0)}, []string{"a/web", "a/db", "a/cache"}},
		// start order a/cache, a/db, a/web (a/web needs a/db; a/cache sorts first): the reverse
		"a chain": {[]api.BootNode{node("a/app", 0, "a/web"), node("a/web", 0, "a/db"), node("a/db", 0)}, []string{"a/app", "a/web", "a/db"}},
		// higher priority starts later, so it stops first
		"priority": {[]api.BootNode{node("a/x", 1), node("a/y", 5), node("a/z", 3)}, []string{"a/y", "a/z", "a/x"}},
		// a dependency that is not running is ignored, and a jail that needs only it stops like any other
		"stopped dependency": {[]api.BootNode{node("a/web", 0, "a/gone"), node("a/db", 0)}, []string{"a/web", "a/db"}},
		// across projects the host decides: keys sort by project, the dependency order still holds inside one
		"two projects": {[]api.BootNode{node("b/web", 0, "b/db"), node("a/web", 0, "a/db"), node("b/db", 0), node("a/db", 0)}, []string{"b/web", "b/db", "a/web", "a/db"}},
		"cycle last":   {[]api.BootNode{node("a/p", 0, "a/q"), node("a/q", 0, "a/p"), node("a/solo", 0)}, []string{"a/solo", "a/p", "a/q"}},
		"empty":        {nil, nil},
	} {
		got := api.StopOrder(tc.running)
		if !reflect.DeepEqual(got, tc.want) && (len(got) != 0 || len(tc.want) != 0) {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
	// whatever the order of the input, a jail stops before everything it needs
	in := []api.BootNode{node("a/db", 0), node("a/web", 0, "a/db"), node("a/app", 0, "a/web", "a/db")}
	got := api.StopOrder(in)
	pos := map[string]int{}
	for i, k := range got {
		pos[k] = i
	}
	if len(got) != 3 || pos["a/app"] > pos["a/web"] || pos["a/web"] > pos["a/db"] {
		t.Fatalf("%q", got)
	}
}
