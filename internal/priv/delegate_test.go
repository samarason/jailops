package priv

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

const delegatedDS = "tank/jailops/projects/alpha/jails/web/delegated"

// delegationLocal is a helper whose priv.conf allows delegation.
func delegationLocal(t *testing.T, e *env, allowed bool) *Local {
	t.Helper()
	cfg := e.cfg
	cfg.Admin = AdminPolicy{ZFSDelegation: allowed}
	l, err := NewLocal(cfg, Deps{ZFS: e.zfs, Jails: e.jails, PF: e.pf, Net: e.net, Runner: e.runner}, WithoutChown())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func delegatedConf(e *env, dataset string) string {
	return strings.Replace(e.goodConf(), "\tenforce_statfs = 2;\n",
		"\tenforce_statfs = 1;\n\tallow.mount;\n\tallow.mount.zfs;\n\tzfs.dataset = \""+dataset+"\";\n", 1)
}

func writeConf(l *Local, ctx context.Context, e *env, conf string) error {
	return l.WriteFile(ctx, WriteFileReq{Path: filepath.Join(e.cfg.ConfDir, "alpha_web.conf"), Data: []byte(conf), Mode: 0o644})
}

// The jail.conf lines that hand a jail its dataset need the operator's consent in priv.conf, the admin assertion, and the
// jail's own delegated dataset; an unchanged rewrite (every start) keeps them without the assertion.
func TestDelegationJailConf(t *testing.T) {
	e := newEnv(t)
	bg := context.Background()
	adm := WithAdmin(bg, "alice")
	conf := delegatedConf(e, delegatedDS)

	l := delegationLocal(t, e, true)
	if err := writeConf(l, bg, e, conf); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the admin assertion: %v", err)
	}
	if err := writeConf(l, adm, e, conf); err != nil {
		t.Fatalf("admin, allowed in priv.conf: %v", err)
	}
	if err := writeConf(l, bg, e, conf); err != nil {
		t.Errorf("an unchanged rewrite without the assertion: %v", err)
	}
	if err := writeConf(l, bg, e, delegatedConf(e, "tank/jailops/projects/alpha/jails/other/delegated")); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("a changed dataset without the assertion: %v", err)
	}
	for _, ds := range []string{"tank/jailops/projects/alpha/jails/other/delegated", "tank/other", "tank/jailops/projects/alpha/jails/web",
		"tank/jailops/projects/alpha/jails/web/data/x", "tank/jailops/projects/alpha/jails/web/delegated/x", "tank/jailops/projects/beta/jails/web/delegated"} {
		if err := writeConf(l, adm, e, delegatedConf(e, ds)); !api.IsCode(err, api.CodeForbidden) {
			t.Errorf("zfs.dataset %q: %v", ds, err)
		}
	}
	// the operator did not allow delegation: an administrator cannot either
	off := delegationLocal(t, e, false)
	mustRemove(t, filepath.Join(e.cfg.ConfDir, "alpha_web.conf"))
	if err := writeConf(off, adm, e, conf); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("admin without admin-zfs-delegation: %v", err)
	}
	// no delegation lines, no consent needed
	if err := writeConf(off, bg, e, e.goodConf()); err != nil {
		t.Errorf("a plain jail.conf: %v", err)
	}
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := removeAll(p); err != nil {
		t.Fatal(err)
	}
}

// jailed can be set on the delegated dataset of a managed jail by an administrator, and on nothing else.
func TestSetJailedOnlyOnADelegatedDataset(t *testing.T) {
	e := newEnv(t)
	bg := context.Background()
	adm := WithAdmin(bg, "alice")
	e.managedDS(delegatedDS)
	e.managedDS("tank/jailops/projects/alpha/jails/web/data/vol")
	l := delegationLocal(t, e, true)
	jailed := func(ds string) string {
		p, err := e.zfs.Get(bg, ds, "jailed")
		if err != nil {
			t.Fatal(err)
		}
		return p["jailed"].Value
	}
	on := map[string]string{"jailed": "on"}
	if err := l.ZFS().Set(bg, delegatedDS, on); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without the assertion: %v", err)
	}
	if err := delegationLocal(t, e, false).ZFS().Set(adm, delegatedDS, on); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("without admin-zfs-delegation: %v", err)
	}
	for name, c := range map[string]struct {
		ds    string
		props map[string]string
		code  api.Code
	}{
		"a volume":          {"tank/jailops/projects/alpha/jails/web/data/vol", on, api.CodeForbidden},
		"the container":     {"tank/jailops/projects/alpha/jails/web", on, api.CodeForbidden},
		"the storage root":  {"tank/jailops", on, api.CodeForbidden},
		"another pool":      {"other/projects/alpha/jails/web/delegated", on, api.CodeForbidden},
		"a deeper dataset":  {delegatedDS + "/x", on, api.CodeForbidden},
		"with another prop": {delegatedDS, map[string]string{"jailed": "on", "compression": "lz4"}, api.CodeForbidden},
		"a value":           {delegatedDS, map[string]string{"jailed": "maybe"}, api.CodeInvalid},
	} {
		err := l.ZFS().Set(adm, c.ds, c.props)
		if err == nil || !api.IsCode(err, c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	if v := jailed(delegatedDS); v == "on" {
		t.Fatal("a refused request set jailed")
	}
	if err := l.ZFS().Set(adm, delegatedDS, on); err != nil {
		t.Fatalf("the delegated dataset: %v", err)
	}
	if jailed(delegatedDS) != "on" {
		t.Error("jailed was not set")
	}
	if err := l.ZFS().Set(adm, delegatedDS, map[string]string{"jailed": "off"}); err != nil || jailed(delegatedDS) != "off" {
		t.Errorf("clearing jailed: %v %q", err, jailed(delegatedDS))
	}
	// an unmanaged dataset of that name is not the helper's to hand over
	e.zfs.Create(bg, zfs.CreateOpts{Name: "tank/jailops/projects/alpha/jails/db/delegated", Parents: true})
	if err := l.ZFS().Set(adm, "tank/jailops/projects/alpha/jails/db/delegated", on); !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("an unmanaged dataset: %v", err)
	}
}

// The create call cannot set jailed: handing a dataset over is a separate, narrow operation.
func TestCreateStillRefusesJailed(t *testing.T) {
	e := newEnv(t)
	l := delegationLocal(t, e, true)
	err := l.ZFS().Create(WithAdmin(context.Background(), "alice"), zfs.CreateOpts{Name: delegatedDS, Parents: true,
		Props: map[string]string{"jailops:managed": "on", "jailed": "on"}})
	if !api.IsCode(err, api.CodeForbidden) {
		t.Errorf("create with jailed: %v", err)
	}
}
