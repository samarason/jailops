package reconcile_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/internal/reconcile"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/internal/sys/pfctl"
	"jailops.net/jailops/sdk/api"
)

// recordingPF logs loads in order and can swallow the rules of an anchor, as
// a pfctl that accepted a load which did not take effect would.
type recordingPF struct {
	pfctl.Client
	loads []string
	drop  string
}

func (r *recordingPF) Load(ctx context.Context, anchor, rs string) error {
	r.loads = append(r.loads, anchor)
	if anchor == r.drop {
		return nil // accepted, but nothing is there
	}
	return r.Client.Load(ctx, anchor, rs)
}

func TestProjectAnchorIsLoadedBeforeTheJailAnchorAndVerified(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	pf := &recordingPF{Client: w.PF}
	w.R = reconcile.New(reconcile.Config{}, reconcile.Env{Source: w, Sink: w, Actions: w, Net: w.Net, PF: pf, Jails: w.Jails, Run: privateRunner(), Sysctl: sysctl, Clock: w.clock})
	j := jailDesired("web_nginx")
	j.Project = "web"
	j.AnchorName = render.JailAnchor("web_nginx")
	j.ParentAnchors = map[string]string{render.ProjectAnchor("web"): render.ProjectAnchorRules()}
	w.des = reconcile.Desired{Networks: []reconcile.NetworkDesired{lan()}, Jails: []reconcile.JailDesired{j}}
	w.R.Pass(bg)
	_ = w.Jails.Create(bg, "/etc/jailops/jails/web_nginx/jail.conf", "web_nginx")
	h := j.Epairs[0]
	_, _, _ = w.Net.EpairCreate(bg, h[:len(h)-1])
	_ = w.Net.SetDescription(bg, h, "jailops:"+jailID)
	rep := w.R.Pass(bg)
	if len(rep.Drift["web_nginx"]) != 0 {
		t.Fatalf("%+v", rep.Drift)
	}
	if strings.Join(pf.loads, ",") != "jailops/web,jailops/web/nginx" {
		t.Fatalf("load order: %v", pf.loads)
	}
	// Rules that were accepted but are not there afterwards are drift, not success.
	_ = w.PF.Flush(bg, "jailops/web/nginx")
	pf.loads, pf.drop = nil, "jailops/web/nginx"
	rep = w.R.Pass(bg)
	d := strings.Join(rep.Drift["web_nginx"], ";")
	if !strings.Contains(d, "jailops/web/nginx") || !strings.Contains(d, "after loading") {
		t.Fatalf("a load that did not take effect was reported as success: %v", rep.Drift)
	}
}

func TestStatesOfRemovedRulesAreEnded(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	pf, r := w.PF, w.R
	v1 := "pass quick on e inet proto tcp to 10.0.0.2 port 80 label \"jo-aaaaaaaaaaaa\"\npass quick on e inet proto tcp to 10.0.0.2 port 22 label \"jo-bbbbbbbbbbbb\"\n"
	v2 := "pass quick on e inet proto tcp to 10.0.0.2 port 80 label \"jo-aaaaaaaaaaaa\"\n"
	if err := r.LoadAnchorForTest(bg, "jailops/p/j", v1); err != nil {
		t.Fatal(err)
	}
	if len(pf.Killed) != 0 {
		t.Fatalf("first load killed %v", pf.Killed)
	}
	if err := r.LoadAnchorForTest(bg, "jailops/p/j", v2); err != nil {
		t.Fatal(err)
	}
	if len(pf.Killed) != 1 || pf.Killed[0] != "jo-bbbbbbbbbbbb" {
		t.Fatalf("killed %v, want only the removed rule's label", pf.Killed)
	}
	// an unchanged ruleset ends nothing
	if err := r.LoadAnchorForTest(bg, "jailops/p/j", v2); err != nil || len(pf.Killed) != 1 {
		t.Fatalf("%v %v", err, pf.Killed)
	}
}

// A rule inserted above unchanged ones gives them new labels (the renderer hashes what is above a rule into its
// label), and the flows of the old labels end; nothing else is touched.
func TestAnInsertedDenyEndsTheFlowsBelowIt(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	v1 := "pass out quick on e all label \"jo-aaaaaaaaaaaa\"\npass in quick on e all label \"jo-bbbbbbbbbbbb\"\n"
	v2 := "pass out quick on e all label \"jo-aaaaaaaaaaaa\"\nblock drop out quick on e to 10.0.0.0/8\npass in quick on e all label \"jo-cccccccccccc\"\n"
	if err := w.R.LoadAnchorForTest(bg, "jailops/p/j", v1); err != nil {
		t.Fatal(err)
	}
	if err := w.R.LoadAnchorForTest(bg, "jailops/p/j", v2); err != nil {
		t.Fatal(err)
	}
	if len(w.PF.Killed) != 1 || w.PF.Killed[0] != "jo-bbbbbbbbbbbb" {
		t.Fatalf("killed %v", w.PF.Killed)
	}
}

// When the loaded rules cannot be read, nothing is replaced: the flows of a removed rule would never be ended, as the
// next pass would find nothing to compare with.
func TestAnAnchorThatCannotBeReadIsNotReplaced(t *testing.T) {
	w := newWorld(t, reconcile.Config{})
	v1 := "pass quick on e all label \"jo-aaaaaaaaaaaa\"\n"
	if err := w.R.LoadAnchorForTest(bg, "jailops/p/j", v1); err != nil {
		t.Fatal(err)
	}
	w.PF.ReadErr = errors.New("pfctl: the helper did not answer")
	loads := w.PF.LoadCalls["jailops/p/j"]
	err := w.R.LoadAnchorForTest(bg, "jailops/p/j", "pass quick on e inet all label \"jo-dddddddddddd\"\n")
	if err == nil || !strings.Contains(err.Error(), "before replacing") {
		t.Fatalf("%v", err)
	}
	if w.PF.LoadCalls["jailops/p/j"] != loads {
		t.Fatal("the anchor was replaced although its old content is unknown")
	}
	// an anchor that does not exist yet is not an error
	w.PF.ReadErr = api.Errorf(api.CodeNotFound, "pfctl read: Anchor does not exist.")
	if err := w.R.LoadAnchorForTest(bg, "jailops/p/new", v1); err != nil {
		t.Fatalf("%v", err)
	}
}
