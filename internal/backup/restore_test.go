package backup

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

var ctx = context.Background()

func wantCode(t *testing.T, err error, c api.Code) {
	t.Helper()
	if err == nil || !api.IsCode(err, c) {
		t.Fatalf("want code %s, got %v", c, err)
	}
}

type objs struct {
	nets map[string]api.NetworkSpec
	pols map[string]api.FirewallPolicySpec
	sets map[string]api.AddressSetSpec
}

func (o objs) Network(n string) (api.NetworkSpec, bool) { v, ok := o.nets[n]; return v, ok }
func (o objs) Policy(n string) (api.FirewallPolicySpec, bool) {
	v, ok := o.pols[n]
	return v, ok
}
func (o objs) AddressSet(n string) (api.AddressSetSpec, bool) { v, ok := o.sets[n]; return v, ok }

func srcNet(subnet, gw string) api.NetworkSpec {
	return api.NetworkSpec{IPv4: &api.IPv4Net{Subnet: subnet, Gateway: gw, Range: "x-y"}}
}

func sourceObjects() objs {
	return objs{
		nets: map[string]api.NetworkSpec{"lan": srcNet("10.20.0.0/24", "10.20.0.1"), "dmz": srcNet("10.30.0.0/24", "10.30.0.1")},
		pols: map[string]api.FirewallPolicySpec{"web": {DefaultIn: "deny", DefaultOut: "allow", Rules: []api.FirewallRule{
			{Action: "allow", Direction: "in", From: []string{"set:office"}, Ports: []string{"443"}}}}},
		sets: map[string]api.AddressSetSpec{"office": {Addresses: api.Entries("192.0.2.0/24", "set:vpn")},
			"vpn": {Addresses: api.Entries("198.51.100.7")}, "unused": {Addresses: api.Entries("1.1.1.1")}},
	}
}

func jailSpec() api.JailSpec {
	return api.JailSpec{Image: "freebsd-15-0@stable",
		Network:  []api.NetworkAttach{{Network: "lan", IPv4: "10.20.0.5", MAC: "02:aa"}, {Network: "dmz", IPv4: "auto"}, {Network: "lan", IPv4: "none"}},
		Firewall: api.FirewallAttach{Policies: []string{"web"}, Tags: []string{"tag:x"}},
		Volumes:  []api.VolumeAttach{{Name: "db", Mount: "/var/db/app"}}, Encrypted: true}
}

var gen3 = api.ImageGeneration{Number: 3, Name: "freebsd-15-0#g3", Manifest: "mf3"}

func TestBuildBundle(t *testing.T) {
	o := sourceObjects()
	b, err := BuildBundle(jailSpec(), gen3, o, []string{"s2", "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if b.ImageGeneration != "freebsd-15-0#g3" || b.ImageManifest != "mf3" || len(b.Networks) != 2 || len(b.Policies) != 1 {
		t.Fatalf("%+v", b)
	}
	if !reflect.DeepEqual(b.AddressSetNames, []string{"office", "vpn"}) || len(b.AddressSets) != 2 {
		t.Fatalf("transitive closure: %v", b.AddressSetNames)
	}
	if !reflect.DeepEqual(b.NetworkNames, []string{"dmz", "lan"}) || !reflect.DeepEqual(b.PolicyNames, []string{"web"}) {
		t.Fatalf("names: %v %v", b.NetworkNames, b.PolicyNames)
	}
	if !reflect.DeepEqual(b.Volumes, []string{"db"}) || !reflect.DeepEqual(b.SecretRefs, []string{"s1", "s2"}) {
		t.Fatalf("%+v", b)
	}
	// Networks are in sorted-name order: dmz, lan.
	if b.Networks[0].IPv4.Subnet != "10.30.0.0/24" {
		t.Fatalf("order %+v", b.Networks)
	}
	// Frozen: changing the live objects later does not change the bundle.
	o.pols["web"].Rules[0].Ports[0] = "22"
	o.nets["lan"].IPv4.Gateway = "changed"
	o.sets["office"].Addresses[0].Address = "changed"
	if b.Policies[0].Rules[0].Ports[0] != "443" || b.Networks[1].IPv4.Gateway != "10.20.0.1" || b.AddressSets[0].Addresses[0].Address != "192.0.2.0/24" {
		t.Fatal("bundle aliases live objects")
	}
	// Deterministic.
	b2, _ := BuildBundle(jailSpec(), gen3, sourceObjects(), []string{"s1", "s2"})
	b1, _ := BuildBundle(jailSpec(), gen3, sourceObjects(), []string{"s2", "s1"})
	if !reflect.DeepEqual(b1, b2) {
		t.Fatal("not deterministic")
	}
	// Missing references.
	for name, mod := range map[string]func(objs){
		"net": func(o objs) { delete(o.nets, "dmz") }, "policy": func(o objs) { delete(o.pols, "web") },
		"set": func(o objs) { delete(o.sets, "office") },
	} {
		o := sourceObjects()
		mod(o)
		_, err := BuildBundle(jailSpec(), gen3, o, nil)
		if !api.IsCode(err, api.CodeNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, err = BuildBundle(jailSpec(), api.ImageGeneration{}, sourceObjects(), nil)
	wantCode(t, err, api.CodeInvalid)
}

func backupOf(t *testing.T) api.Backup {
	t.Helper()
	b, err := BuildBundle(jailSpec(), gen3, sourceObjects(), []string{"db-pass"})
	if err != nil {
		t.Fatal(err)
	}
	return api.Backup{Spec: api.BackupSpec{Jail: "web", JailUUID: "u-1", HostUUID: "h1", Snapshot: "20250101000000-aabbccdd",
		KeyDomain: "d1", Bundle: b}}
}

func emptyHost() HostState {
	return HostState{Generations: map[string]string{}, Networks: map[string]api.NetworkSpec{}, Policies: map[string]api.FirewallPolicySpec{},
		AddressSets: map[string]api.AddressSetSpec{}, Jails: map[string]JailRef{}, Secrets: map[string]bool{}, KeyDomains: map[string]bool{}}
}

func has(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestPreflightDifferentHostWithNetworkMap(t *testing.T) {
	b := backupOf(t)
	h := emptyHost()
	h.Networks["office-lan"] = srcNet("172.16.0.0/24", "172.16.0.1")
	h.Networks["dmz"] = srcNet("10.30.0.0/24", "10.30.0.1")
	h.Generations["freebsd-15-0#g3"] = "mf3"
	h.Secrets["db-pass"] = true
	h.KeyDomains["d1"] = true
	h.Leases = []api.Lease{{Address: "172.16.0.9", Jail: "other", Network: "office-lan"}}
	before := reflect.ValueOf(h).Interface()

	req := api.RestoreRequest{Backup: "web@20250101000000-aabbccdd", NetworkMap: map[string]string{"lan": "office-lan"}}
	r := Preflight(b, req, h)
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	// Policy and address sets are missing and would be created; the rest exists.
	for _, m := range []string{"firewall policy web", "address set office", "address set vpn"} {
		if !has(r.Missing, m) {
			t.Errorf("missing list lacks %q: %v", m, r.Missing)
		}
	}
	if has(r.Missing, "network") || has(r.Missing, "image") {
		t.Errorf("%v", r.Missing)
	}
	if !has(r.Changes, "create jail \"web\"") || !has(r.Changes, "new uuid") || !has(r.Changes, "re-allocated") {
		t.Errorf("%v", r.Changes)
	}
	if !reflect.DeepEqual(before, h) {
		t.Fatal("preflight mutated the host state")
	}

	// keep_ip into a different subnet is an error; into the same subnet works.
	req.KeepIP = true
	r = Preflight(b, req, h)
	if r.OK || !has(r.Errors, "outside network office-lan") {
		t.Fatalf("%+v", r)
	}
	h.Networks["office-lan"] = srcNet("10.20.0.0/24", "10.20.0.1")
	if r = Preflight(b, req, h); !r.OK || !has(r.Changes, "keep address 10.20.0.5") {
		t.Fatalf("%+v", r)
	}
	// ... unless another jail has the address.
	h.Leases = []api.Lease{{Address: "10.20.0.5", Jail: "other", Network: "office-lan"}}
	r = Preflight(b, req, h)
	if r.OK || !has(r.Errors, string(api.CodeIPConflict)) || !has(r.Errors, "other") {
		t.Fatalf("%+v", r)
	}
	// Replacing the very jail that holds the address is fine.
	h.Leases = []api.Lease{{Address: "10.20.0.5", Jail: "web", Network: "office-lan"}}
	h.Jails["web"] = JailRef{Name: "web", UUID: "u-1"}
	req.Replace = true
	if r = Preflight(b, req, h); !r.OK || !has(r.Changes, "replace jail") {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightErrors(t *testing.T) {
	good := func() HostState {
		h := emptyHost()
		h.Networks["lan"] = srcNet("10.20.0.0/24", "10.20.0.1")
		h.Networks["dmz"] = srcNet("10.30.0.0/24", "10.30.0.1")
		h.Generations["freebsd-15-0#g3"] = "mf3"
		h.Secrets["db-pass"] = true
		h.KeyDomains["d1"] = true
		return h
	}
	b := backupOf(t)
	if r := Preflight(b, api.RestoreRequest{}, good()); !r.OK {
		t.Fatalf("baseline %+v", r)
	}
	tests := []struct {
		name   string
		mod    func(*HostState, *api.RestoreRequest)
		errSub string
		missed string
	}{
		{"name taken", func(h *HostState, r *api.RestoreRequest) { h.Jails["web"] = JailRef{Name: "web", UUID: "u-9"} }, "already exists", ""},
		{"replace other uuid", func(h *HostState, r *api.RestoreRequest) {
			h.Jails["web"] = JailRef{Name: "web", UUID: "u-9"}
			r.Replace = true
		}, "replace needs the same jail", ""},
		{"as renames around the clash", func(h *HostState, r *api.RestoreRequest) {
			h.Jails["web"] = JailRef{Name: "web", UUID: "u-9"}
			r.As = "web2"
		}, "", ""},
		{"manifest differs", func(h *HostState, r *api.RestoreRequest) { h.Generations["freebsd-15-0#g3"] = "other" }, "manifest", ""},
		{"generation missing is creatable", func(h *HostState, r *api.RestoreRequest) { delete(h.Generations, "freebsd-15-0#g3") }, "", "image generation"},
		{"secret missing", func(h *HostState, r *api.RestoreRequest) { delete(h.Secrets, "db-pass") }, "sealed secret", "secret db-pass"},
		{"key missing", func(h *HostState, r *api.RestoreRequest) { delete(h.KeyDomains, "d1") }, "recovery key", "encryption key domain d1"},
		{"network missing is creatable", func(h *HostState, r *api.RestoreRequest) { delete(h.Networks, "dmz") }, "", "network dmz"},
		{"map target absent", func(h *HostState, r *api.RestoreRequest) { r.NetworkMap = map[string]string{"lan": "nope"} }, "does not exist on the target", ""},
		{"map key unknown", func(h *HostState, r *api.RestoreRequest) { r.NetworkMap = map[string]string{"zzz": "lan"} }, "does not use", ""},
		{"bad name", func(h *HostState, r *api.RestoreRequest) { r.As = "a b" }, "invalid jail name", ""},
	}
	for _, tc := range tests {
		h := good()
		req := api.RestoreRequest{}
		tc.mod(&h, &req)
		r := Preflight(b, req, h)
		if tc.errSub == "" && !r.OK {
			t.Errorf("%s: unexpected errors %v", tc.name, r.Errors)
		}
		if tc.errSub != "" && (r.OK || !has(r.Errors, tc.errSub)) {
			t.Errorf("%s: %+v", tc.name, r)
		}
		if tc.missed != "" && !has(r.Missing, tc.missed) {
			t.Errorf("%s: missing %v", tc.name, r.Missing)
		}
	}
	// A backup without a key domain cannot be matched to a key.
	b2 := b
	b2.Spec.KeyDomain = ""
	if r := Preflight(b2, api.RestoreRequest{}, good()); r.OK || !has(r.Errors, "no key domain") {
		t.Fatalf("%+v", r)
	}
	// A failed backup is refused.
	b3 := b
	b3.Status.Failed = true
	if r := Preflight(b3, api.RestoreRequest{}, good()); r.OK || !has(r.Errors, "failed verification") {
		t.Fatalf("%+v", r)
	}
	// A bundle whose names do not match the spec is refused.
	b4 := backupOf(t)
	b4.Spec.Bundle.NetworkNames = []string{"lan"}
	if r := Preflight(b4, api.RestoreRequest{}, good()); r.OK || !has(r.Errors, "bundle has networks") {
		t.Fatalf("%+v", r)
	}
	// Existing different policy: kept, reported.
	h := good()
	h.Policies["web"] = api.FirewallPolicySpec{DefaultIn: "allow", DefaultOut: "allow"}
	r := Preflight(b, api.RestoreRequest{}, h)
	if !r.OK || !has(r.Changes, "existing policy is used") {
		t.Fatalf("%+v", r)
	}
}

// ---- restore tests ----

type drillEnv struct {
	kind     EnvKind
	keys     map[string]bool
	calls    []string
	failAt   string
	cancelFn func()
}

func (d *drillEnv) Kind() EnvKind            { return d.kind }
func (d *drillEnv) HoldsKey(dom string) bool { return d.keys[dom] }
func (d *drillEnv) step(n string) error {
	d.calls = append(d.calls, n)
	if d.failAt == n {
		return errors.New("boom " + n)
	}
	return nil
}
func (d *drillEnv) VerifyChunks(context.Context, DrillPlan) error { return d.step("verify") }
func (d *drillEnv) ExtractScratch(context.Context, DrillPlan) error {
	if d.cancelFn != nil {
		d.cancelFn()
	}
	return d.step("extract")
}
func (d *drillEnv) RemoveScratchDir(context.Context, DrillPlan) error { return d.step("dir-") }
func (d *drillEnv) RestoreScratch(context.Context, DrillPlan) error {
	if d.cancelFn != nil {
		d.cancelFn()
	}
	return d.step("restore")
}
func (d *drillEnv) DestroyScratch(context.Context, DrillPlan) error { return d.step("scratch-") }
func (d *drillEnv) CreateNetwork(context.Context, string, api.NetworkSpec) error {
	return d.step("net+")
}
func (d *drillEnv) DestroyNetwork(context.Context, string) error { return d.step("net-") }
func (d *drillEnv) StartJail(context.Context, DrillPlan) error   { return d.step("start") }
func (d *drillEnv) StopJail(context.Context, DrillPlan) error    { return d.step("stop") }

func TestParseDepth(t *testing.T) {
	for in, want := range map[string]Depth{"": DepthDeep, "deep": DepthDeep, "extract": DepthExtract, "full": DepthFull} {
		if got, err := ParseDepth(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	_, err := ParseDepth("shallow")
	wantCode(t, err, api.CodeInvalid)
}

func TestPlanDrill(t *testing.T) {
	b := backupOf(t)
	deep, err := PlanDrill(b, DepthDeep, "", "d1")
	if err != nil {
		t.Fatal(err)
	}
	if deep.Scratch != "" || deep.Network != "" || deep.KeyDomain != "d1" || deep.Backup != b.Spec.Snapshot {
		t.Fatalf("%+v", deep)
	}
	ext, err := PlanDrill(b, DepthExtract, "/var/scratch", "d1")
	if err != nil || ext.Scratch != "/var/scratch/drill-d1" || ext.Network != "" {
		t.Fatalf("%+v %v", ext, err)
	}
	p, err := PlanDrill(b, DepthFull, "tank/jailops/scratch", "d1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Scratch != "tank/jailops/scratch/drill-d1" || p.Network != "jodrill-d1" {
		t.Fatalf("%+v", p)
	}
	n := p.NetSpec
	if n.Uplink != "" || n.IPv4.NAT || len(n.DNS) != 0 || !strings.HasPrefix(n.IPv4.Subnet, "198.1") {
		t.Fatalf("network is not isolated: %+v", n)
	}
	p2, _ := PlanDrill(b, DepthFull, "tank/jailops/scratch", "d1")
	if !reflect.DeepEqual(p, p2) {
		t.Fatal("not deterministic")
	}
	// Refusals.
	_, err = PlanDrill(b, DepthFull, "r", "bad id")
	wantCode(t, err, api.CodeInvalid)
	_, err = PlanDrill(b, Depth("x"), "r", "d1")
	wantCode(t, err, api.CodeInvalid)
	_, err = PlanDrill(b, DepthExtract, "", "d1")
	wantCode(t, err, api.CodeInvalid)
	nk := b
	nk.Spec.KeyDomain = ""
	_, err = PlanDrill(nk, DepthDeep, "", "d1")
	wantCode(t, err, api.CodeInvalid)
	fb := b
	fb.Status.Failed = true
	_, err = PlanDrill(fb, DepthDeep, "", "d1")
	wantCode(t, err, api.CodeInvalid)

	// Executors: never the backup node; must hold the key domain.
	ex, err := SelectExecutor(p, []Executor{{Name: "node", Kind: EnvBackupNode, Keys: map[string]bool{"d1": true}},
		{Name: "other", Kind: EnvHost}, {Name: "recovery", Kind: EnvRecovery, Keys: map[string]bool{"d1": true}}})
	if err != nil || ex.Name != "recovery" {
		t.Fatalf("%+v %v", ex, err)
	}
	_, err = SelectExecutor(p, []Executor{{Name: "node", Kind: EnvBackupNode, Keys: map[string]bool{"d1": true}}})
	wantCode(t, err, api.CodeNotFound)
}

func TestDrillRefusedOnNodeOrWithoutKey(t *testing.T) {
	ok := func(context.Context, DrillPlan) error { return nil }
	for _, d := range []Depth{DepthDeep, DepthExtract, DepthFull} {
		p, _ := PlanDrill(backupOf(t), d, "r", "d1")
		env := &drillEnv{kind: EnvBackupNode, keys: map[string]bool{"d1": true}}
		_, err := RunDrill(ctx, p, env, ok)
		wantCode(t, err, api.CodeForbidden)
		env = &drillEnv{kind: EnvHost}
		_, err = RunDrill(ctx, p, env, ok)
		wantCode(t, err, api.CodeForbidden)
		if len(env.calls) != 0 {
			t.Fatalf("%s: refused drill did something: %v", d, env.calls)
		}
	}
	p, _ := PlanDrill(backupOf(t), DepthFull, "r", "d1")
	_, err := RunDrill(ctx, p, &drillEnv{kind: EnvHost, keys: map[string]bool{"d1": true}}, nil)
	wantCode(t, err, api.CodeInvalid)
}

func TestDrillDepths(t *testing.T) {
	ok := func(context.Context, DrillPlan) error { return nil }
	for d, want := range map[Depth]string{
		DepthDeep:    "verify",
		DepthExtract: "extract,dir-",
		DepthFull:    "net+,restore,start,stop,scratch-,net-",
	} {
		p, _ := PlanDrill(backupOf(t), d, "r", "d1")
		env := &drillEnv{kind: EnvRecovery, keys: map[string]bool{"d1": true}}
		r, err := RunDrill(ctx, p, env, ok)
		if err != nil || !r.OK || r.Depth != d {
			t.Fatalf("%s: %v %+v", d, err, r)
		}
		if got := strings.Join(env.calls, ","); got != want {
			t.Errorf("%s: calls %s want %s", d, got, want)
		}
	}
}

func TestDrillAlwaysCleansUp(t *testing.T) {
	ok := func(context.Context, DrillPlan) error { return nil }
	run := func(d Depth, failAt string, check HealthCheck, cancel bool) (*drillEnv, DrillResult, error) {
		p, _ := PlanDrill(backupOf(t), d, "r", "d1")
		env := &drillEnv{kind: EnvRecovery, keys: map[string]bool{"d1": true}, failAt: failAt}
		c, cf := context.WithCancel(ctx)
		defer cf()
		if cancel {
			env.cancelFn = cf
		}
		r, err := RunDrill(c, p, env, check)
		return env, r, err
	}
	// Health check failure.
	env, r, err := run(DepthFull, "", func(context.Context, DrillPlan) error { return errors.New("down") }, false)
	if err == nil || r.OK || !strings.HasSuffix(strings.Join(env.calls, ","), "stop,scratch-,net-") {
		t.Fatalf("%v %v", err, env.calls)
	}
	// Failure at every full step still undoes what was done.
	for _, at := range []string{"net+", "restore", "start"} {
		env, r, err = run(DepthFull, at, ok, false)
		if err == nil || r.OK {
			t.Fatalf("%s: no error", at)
		}
		c := strings.Join(env.calls, ",")
		if strings.Contains(c, "net+") && !strings.Contains(c, "net-") {
			t.Fatalf("%s leaked network: %s", at, c)
		}
		if strings.Contains(c, "restore") && !strings.Contains(c, "scratch-") {
			t.Fatalf("%s leaked scratch: %s", at, c)
		}
	}
	// A failed extraction still removes the partial directory.
	env, _, err = run(DepthExtract, "extract", ok, false)
	if err == nil || strings.Join(env.calls, ",") != "extract,dir-" {
		t.Fatalf("%v %v", err, env.calls)
	}
	// Cancellation mid-restore: cleanup still runs.
	env, _, _ = run(DepthFull, "", ok, true)
	if c := strings.Join(env.calls, ","); !strings.HasSuffix(c, "scratch-,net-") {
		t.Fatalf("cancel: %s", c)
	}
	env, _, _ = run(DepthExtract, "", ok, true)
	if c := strings.Join(env.calls, ","); !strings.HasSuffix(c, "dir-") {
		t.Fatalf("cancel: %s", c)
	}
	// Cleanup errors are reported, also when the test itself passed.
	p, _ := PlanDrill(backupOf(t), DepthFull, "r", "d1")
	env2 := &drillEnv{kind: EnvHost, keys: map[string]bool{"d1": true}, failAt: "net-"}
	res, err := RunDrill(ctx, p, env2, ok)
	if err == nil || res.CleanupErr == nil {
		t.Fatal("cleanup failure swallowed")
	}
}

func TestReverter(t *testing.T) {
	var r reverter
	var order []int
	for i := 1; i <= 3; i++ {
		r.add(func() error { order = append(order, i); return nil })
	}
	r.add(func() error { return errors.New("x") })
	if err := r.revert(); err == nil {
		t.Fatal("error lost")
	}
	if !reflect.DeepEqual(order, []int{3, 2, 1}) {
		t.Fatal(order)
	}
	if err := r.revert(); err != nil || len(order) != 3 {
		t.Fatal("steps ran twice")
	}
}

func TestPreflightSaysAnAttachedVolumeIsNotInTheBackup(t *testing.T) {
	bd, err := BuildBundle(jailSpec(), gen3, sourceObjects(), []string{"db-pass"})
	if err != nil {
		t.Fatal(err)
	}
	b := api.Backup{Spec: api.BackupSpec{Jail: "web", JailUUID: "u-1", HostUUID: "h1", Snapshot: "20250101000000-aabbccdd", KeyDomain: "d1", Bundle: bd}}
	req := api.RestoreRequest{Backup: "web@20250101000000-aabbccdd"}
	h := emptyHost()
	if r := Preflight(b, req, h); !has(r.Missing, "volume db (attached at /var/db/app)") {
		t.Fatalf("missing: %v", r.Missing)
	}
	h.Volumes = map[string]bool{"db": true}
	if r := Preflight(b, req, h); has(r.Missing, "volume db (attached at /var/db/app)") {
		t.Fatalf("a volume that exists is reported missing: %v", r.Missing)
	}
}
