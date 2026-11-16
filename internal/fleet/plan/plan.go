// Package plan compares the fleet repository with the live hosts and decides
// what a sync would do. Planning only reads: it lists objects through the SDK
// and never writes.
//
// Rules baked in:
//
//   - Only objects marked managed_by: sync:<fleet-id> are ever changed or
//     deleted. An object that exists under the same name but is not owned
//     is a refusal, never an update.
//   - Objects on a host that the repository does not declare are reported
//     as owned-but-absent (deletable with --prune) or unmanaged (never
//     touched).
//   - Every object sync writes carries a spec hash label, so a declaration
//     that changed is applied even when the change is a removed field that
//     the live object has already defaulted.
package plan

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"jailops.net/jailops/internal/fleet/config"
	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/internal/fleet/secrets"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// HashLabel records the hash of the declared spec on every object sync writes.
const HashLabel = config.SyncLabelPrefix + "hash"

// Action is what the plan does with one object.
type Action string

// Plan actions.
const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionMatch  Action = "match"
	// ActionDelete: owned by this fleet, no longer declared. Applied with --prune.
	ActionDelete Action = "delete"
	// ActionRefuse: declared, but a live object of that name is not owned by this fleet.
	ActionRefuse Action = "refuse"
	// ActionUnmanaged: live, not declared, not owned. Never touched.
	ActionUnmanaged Action = "unmanaged"
	// ActionBlocked: owned and undeclared, but cannot be deleted (a project
	// that still holds objects this plan does not delete).
	ActionBlocked Action = "blocked"
	// ActionError: the object cannot be planned (unsupported kind, secret missing).
	ActionError Action = "error"
)

// Item is one decision about one object on one host.
type Item struct {
	Host    string
	Kind    api.Kind
	Project string // "" for host-level kinds
	Name    string
	Action  Action
	// Details are human-readable differences, or the reason of a refusal.
	Details []string
	// Dangers make `sync --apply` refuse without --force.
	Dangers []string
	// Owner is the live object's managed_by.
	Owner string

	// Desired is the declaration (nil for delete and unmanaged).
	Desired *config.Object
	// Spec is the spec to send: Desired's spec with secret references sealed. A
	// SOPS secret is still a stand-in here; apply calls SealSops just before sending.
	Spec any
	// Meta is the metadata to send (name, labels, managed_by, hash label).
	Meta api.ObjectMeta
	// Build, set for a declared image with `build: true`, builds its first generation after the image is created
	// (or when the host has none yet).
	Build bool
	// Post, when set, is a second write after every other item of the host:
	// a project's mandatory firewall policy can only be set once the policy
	// exists, and the policy lives in the project.
	Post *api.ProjectSpec
}

// Ref is "Kind/name", or "Kind/project/name" for a project-level kind.
func (i Item) Ref() string {
	if i.Project != "" {
		return fmt.Sprintf("%s/%s/%s", i.Kind, i.Project, i.Name)
	}
	return fmt.Sprintf("%s/%s", i.Kind, i.Name)
}

// ProjectHost is one host's state of a project the repository defines.
type ProjectHost struct {
	Project string
	Host    string
	State   string
	Offline bool
}

// HostError is a host that could not be planned.
type HostError struct {
	Host string
	Err  error
}

// Plan is the result of comparing the repository with the hosts.
type Plan struct {
	FleetID string
	Hosts   []string
	Items   []Item
	Errors  []HostError
	// ProjectHosts shows, per fleet project and host, what the plan does.
	ProjectHosts []ProjectHost
}

// Options select what to plan.
type Options struct {
	// Hosts limits the plan to these hosts; empty means every host.
	Hosts []string
}

// Compute reads the live state of the selected hosts and diffs it with the
// repository.
func Compute(ctx context.Context, s *Session, opt Options) *Plan {
	hosts := opt.Hosts
	if len(hosts) == 0 {
		hosts = s.Fleet.HostNames()
	}
	p := &Plan{FleetID: s.Fleet.Meta.ID, Hosts: hosts}
	for _, h := range hosts {
		items, err := planHost(ctx, s, h)
		if err != nil {
			p.Errors = append(p.Errors, HostError{h, err})
			continue
		}
		p.Items = append(p.Items, items...)
	}
	p.ProjectHosts = projectHosts(s.Fleet, p)
	return p
}

func projectHosts(f *config.Fleet, p *Plan) []ProjectHost {
	inPlan := map[string]bool{}
	for _, h := range p.Hosts {
		inPlan[h] = true
	}
	bad := map[string]string{}
	for _, e := range p.Errors {
		bad[e.Host] = e.Err.Error()
	}
	var out []ProjectHost
	for _, name := range f.ProjectNames() {
		for _, h := range f.Projects[name].Hosts {
			if !inPlan[h] {
				continue
			}
			ph := ProjectHost{Project: name, Host: h, State: "unknown"}
			if why, off := bad[h]; off {
				ph.State, ph.Offline = "OFFLINE: "+why, true
			}
			for _, it := range p.Items {
				if it.Host == h && it.Kind == api.KindProject && it.Name == name {
					switch it.Action {
					case ActionMatch:
						ph.State = "in sync"
					case ActionCreate:
						ph.State = "will be created"
					case ActionUpdate:
						ph.State = "will be updated"
					case ActionRefuse:
						ph.State = "exists but is not owned by this fleet"
					case ActionError:
						ph.State = "error: " + strings.Join(it.Details, "; ")
					}
				}
			}
			out = append(out, ph)
		}
	}
	return out
}

func planHost(ctx context.Context, s *Session, host string) ([]Item, error) {
	c, err := s.Client(ctx, host)
	if err != nil {
		return nil, err
	}
	desired := map[config.Key]*config.Object{}
	for _, o := range s.Fleet.ObjectsFor(host) {
		desired[o.Key()] = o
	}
	me := s.Fleet.ManagedBy()

	// Read everything first: host-level kinds, the projects, then the
	// project-level kinds of every live project.
	live := map[config.Key]Live{}
	listed := map[api.Kind]bool{}
	var items []Item
	var projects []string
	listKind := func(ki model.KindInfo, project string) error {
		cl := ScopeClient(c, ki.Kind, project)
		ls, err := adapters[ki.Kind].List(ctx, cl)
		if err != nil {
			return fmt.Errorf("list %s: %w", ki.Dir, err)
		}
		for _, l := range ls {
			p := ""
			if ki.ProjectLevel {
				p = project
			}
			live[config.Key{Kind: ki.Kind, Project: p, Name: l.Meta.Name}] = l
		}
		return nil
	}
	for _, ki := range model.Kinds {
		if !c.Has(ki.Extension) {
			continue
		}
		if ki.ProjectLevel {
			names := projects
			if !c.Has("projects") {
				continue // a host without projects has no project-level objects
			}
			for _, p := range names {
				if err := listKind(ki, p); err != nil {
					return nil, err
				}
			}
		} else if err := listKind(ki, ""); err != nil {
			return nil, err
		}
		listed[ki.Kind] = true
		if ki.Kind == api.KindProject {
			for k := range live {
				if k.Kind == api.KindProject {
					projects = append(projects, k.Name)
				}
			}
			sort.Strings(projects)
		}
	}

	var work, deletes []Item
	installed := appJails(s.Fleet, host)
	for _, ki := range model.Kinds {
		var want []*config.Object
		for _, o := range s.Fleet.ObjectsFor(host) {
			if o.Kind == ki.Kind {
				want = append(want, o)
			}
		}
		if !listed[ki.Kind] {
			for _, o := range want {
				items = append(items, Item{Host: host, Kind: ki.Kind, Project: o.Project, Name: o.Name, Action: ActionError,
					Details: []string{fmt.Sprintf("the server does not advertise %q", ki.Extension)}, Desired: o})
			}
			continue
		}
		for _, o := range want {
			it := Item{Host: host, Kind: ki.Kind, Project: o.Project, Name: o.Name, Desired: o}
			l, found := live[o.Key()]
			it = decide(s, c, it, o, l, found, me, live, desired)
			work = append(work, it)
		}
		// Live objects the repository does not declare.
		var keys []config.Key
		for k := range live {
			if k.Kind == ki.Kind {
				if _, declared := desired[k]; !declared {
					keys = append(keys, k)
				}
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].Project != keys[j].Project {
				return keys[i].Project < keys[j].Project
			}
			return keys[i].Name < keys[j].Name
		})
		for _, k := range keys {
			l := live[k]
			if installed[k] {
				continue // declared as an App: its own item says what it is
			}
			if isBuiltin(k) && l.Meta.ManagedBy != me {
				// The daemon creates the storage named "default" at its
				// first start. They belong to the host: sync neither claims
				// nor reports them unless the repository declares them.
				continue
			}
			it := Item{Host: host, Kind: ki.Kind, Project: k.Project, Name: k.Name, Owner: l.Meta.ManagedBy}
			if l.Meta.ManagedBy == me {
				it.Action = ActionDelete
				it.Details = []string{"owned by this fleet, no longer declared"}
				it.Dangers = dangers(ki.Kind, l.Spec, nil)
			} else {
				it.Action = ActionUnmanaged
				it.Details = []string{ownerReason(l.Meta.ManagedBy, me)}
			}
			deletes = append(deletes, it)
		}
	}
	appWork, appDeletes := planApps(ctx, s, c, host, live)
	items = append(append(items, work...), appWork...)
	deletes = append(deletes, appDeletes...)
	protectProjects(deletes, live, me)
	// Deletes run last and in reverse dependency order.
	sort.SliceStable(deletes, func(i, j int) bool {
		return model.Order(deletes[i].Kind) > model.Order(deletes[j].Kind)
	})
	return append(items, deletes...), nil
}

// isBuiltin reports the host-owned built-in storage (the dataset the host was set up with).
func isBuiltin(k config.Key) bool {
	return k.Name == "default" && k.Kind == api.KindStorage
}

// protectProjects turns the deletion of a project into a block when it
// still holds an object this plan does not
// delete (a project is deleted only when it is empty and owned).
func protectProjects(deletes []Item, live map[config.Key]Live, me string) {
	deleting := map[config.Key]bool{}
	for _, d := range deletes {
		if d.Action == ActionDelete {
			deleting[config.Key{Kind: d.Kind, Project: d.Project, Name: d.Name}] = true
		}
	}
	for i, d := range deletes {
		if d.Kind == api.KindStorage && d.Name == "default" && d.Action == ActionDelete {
			deletes[i].Action, deletes[i].Details, deletes[i].Dangers = ActionUnmanaged, []string{"the default storage is never deleted"}, nil
		}
		if d.Kind != api.KindProject || d.Action != ActionDelete {
			continue
		}
		var rest []string
		for k := range live {
			if k.Project == d.Name && k.Kind != api.KindProject && !deleting[k] {
				rest = append(rest, fmt.Sprintf("%s/%s", k.Kind, k.Name))
			}
		}
		if len(rest) > 0 {
			sort.Strings(rest)
			deletes[i].Action = ActionBlocked
			deletes[i].Details = []string{"project is not empty; sync deletes only empty projects. Remaining: " + strings.Join(rest, ", ")}
			deletes[i].Dangers = nil
		}
	}
}

// decide compares one declared object with its live counterpart.
func decide(s *Session, c *sdk.Client, it Item, o *config.Object, l Live, found bool, me string, live map[config.Key]Live, desired map[config.Key]*config.Object) Item {
	fail := func(err error) Item {
		it.Action, it.Details = ActionError, []string{err.Error()}
		return it
	}
	spec, err := resolveSpec(s, c, o)
	if err != nil {
		return fail(err)
	}
	hash, labels, err := specHash(spec, o.Labels)
	if err != nil {
		return fail(err)
	}
	it.Spec = spec
	it.Build = o.Build && o.Kind == api.KindImage
	it.Meta = api.ObjectMeta{Name: o.Name, Labels: labels, ManagedBy: me}
	if ps, ok := spec.(api.ProjectSpec); ok {
		if msg := missingGrants(ps, it.Host, live, desired); msg != "" {
			return fail(errors.New(msg))
		}
		// The mandatory policies are a project-level object: a policy can be named only after it exists. Send the
		// project without the ones that do not exist yet first and set them in a second write.
		var present []string
		for _, pn := range ps.FirewallPolicies {
			if _, ok := live[config.Key{Kind: api.KindFirewallPolicy, Project: o.Name, Name: pn}]; ok {
				present = append(present, pn)
			}
		}
		if len(present) != len(ps.FirewallPolicies) {
			full := ps
			ps.FirewallPolicies = present
			it.Spec, it.Post = ps, &full
		}
		if !found {
			it.Meta.UUID = ProjectUUID(s.Fleet.Meta.ID, o.Name)
		}
	}
	if !found {
		it.Action = ActionCreate
		return it
	}
	it.Owner = l.Meta.ManagedBy
	if l.Meta.ManagedBy != me {
		it.Action = ActionRefuse
		it.Details = []string{ownerReason(l.Meta.ManagedBy, me)}
		return it
	}
	diffs, err := diffSpec(liveSops(spec, l.Spec), l.Spec)
	if err != nil {
		return fail(err)
	}
	if it.Post != nil {
		// Compare the full declaration, not the stripped first write.
		if diffs, err = diffSpec(*it.Post, l.Spec); err != nil {
			return fail(err)
		}
	}
	diffs = append(diffs, labelDiff(o.Labels, l.Meta.Labels)...)
	if len(diffs) == 0 && l.Meta.Labels[HashLabel] == hash {
		if it.Build && !l.Built {
			// Created earlier, but the build failed or never ran: a jail cannot start from it.
			it.Action = ActionUpdate
			it.Details = []string{"no generation built yet: build the first one"}
			return it
		}
		it.Action = ActionMatch
		it.Post = nil
		return it
	}
	it.Action = ActionUpdate
	it.Build = it.Build && !l.Built // an image that already has a generation is never rebuilt by sync
	if len(diffs) == 0 {
		diffs = []string{"the declaration changed since the last sync"}
	}
	it.Details = diffs
	full := spec
	if it.Post != nil {
		full = *it.Post
	}
	it.Dangers = dangers(o.Kind, l.Spec, full)
	if it.Post != nil {
		if lp, ok := l.Spec.(api.ProjectSpec); ok && len(lp.FirewallPolicies) > 0 {
			it.Dangers = append(it.Dangers, "the mandatory firewall policy is cleared until the new policy exists")
		}
	}
	return it
}

// missingGrants reports a network or storage grant the host cannot satisfy:
// it neither exists on the host nor is declared for it in the repository.
func missingGrants(ps api.ProjectSpec, host string, live map[config.Key]Live, desired map[config.Key]*config.Object) string {
	has := func(kind api.Kind, name string) bool {
		k := config.Key{Kind: kind, Name: name}
		_, l := live[k]
		_, d := desired[k]
		return l || d
	}
	var miss []string
	for _, g := range ps.Networks {
		if g.Network != "*" && !has(api.KindNetwork, g.Network) {
			miss = append(miss, fmt.Sprintf("network %q", g.Network))
		}
	}
	for _, g := range ps.Storage {
		if g.Storage != "*" && !has(api.KindStorage, g.Storage) {
			miss = append(miss, fmt.Sprintf("storage %q", g.Storage))
		}
	}
	if len(miss) == 0 {
		return ""
	}
	return fmt.Sprintf("host %s lacks %s that the project names; create or declare them before the project", host, strings.Join(miss, " and "))
}

// ProjectUUID is the identity every host's copy of a fleet project carries:
// derived from the fleet id and project name, so the same project has the
// same UUID on every host it spans.
func ProjectUUID(fleetID, project string) string {
	sum := sha1.Sum([]byte("jailops-sync/" + fleetID + "/project/" + project))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func ownerReason(owner, me string) string {
	switch owner {
	case "":
		return "not managed by jailops-sync"
	case me:
		return "owned by this fleet"
	}
	return fmt.Sprintf("managed_by %q, this fleet is %q", owner, me)
}

func sortedNames(m map[string]*config.Object) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sopsRefPrefix starts the stand-in of a SOPS secret in a resolved spec: it
// holds the path and a digest of the stored value, and is replaced by a fresh
// sealed value only in the spec that is sent (see sealSops).
const sopsRefPrefix = "sopsref:"

// resolveSpec returns the spec used to hash and compare. For jails, env values
// "secret:<name>" become sealed values of secrets/<name>.age, which only a
// server that advertises sealed_secrets accepts; "secret:<dotted.path>" (a
// value of the SOPS secrets file) becomes a stable stand-in, because sealing it
// is randomised and could neither be hashed nor compared. Nothing is decrypted
// here.
func resolveSpec(s *Session, c *sdk.Client, o *config.Object) (any, error) {
	js, ok := o.Spec.(api.JailSpec)
	if !ok || len(o.SecretRefs) == 0 {
		return o.Spec, nil
	}
	if !c.Has(secrets.ExtSealedSecrets) {
		return nil, fmt.Errorf("jail %s uses secrets (%s) but the server does not advertise %q; sync never sends secrets in the clear",
			o.Name, strings.Join(o.SecretRefs, ", "), secrets.ExtSealedSecrets)
	}
	env := make(map[string]string, len(js.Env))
	for k, v := range js.Env {
		if name, ok := strings.CutPrefix(v, config.SecretPrefix); ok {
			if config.IsSopsRef(name) {
				d, err := s.Store.SopsStable(name)
				if err != nil {
					return nil, err
				}
				v = sopsRefPrefix + name + ":" + d
			} else {
				sealed, err := s.Store.Sealed(name)
				if err != nil {
					return nil, err
				}
				v = sealed
			}
		}
		env[k] = v
	}
	js.Env = env
	return js, nil
}

// liveSops returns want with every SOPS stand-in replaced by the value the host
// holds for that variable. A stand-in says "the stored secret is unchanged",
// which the hash label decides; the sealed value on the host cannot be compared.
func liveSops(want, have any) any {
	w, ok := want.(api.JailSpec)
	if !ok {
		return want
	}
	h, _ := have.(api.JailSpec)
	env := make(map[string]string, len(w.Env))
	for k, v := range w.Env {
		if strings.HasPrefix(v, sopsRefPrefix) {
			v = h.Env[k]
		}
		env[k] = v
	}
	w.Env = env
	return w
}

// SealSops replaces the SOPS stand-ins of a spec that is about to be sent by
// freshly sealed values. The plaintext exists only in memory, and only a real
// apply gets here: planning never needs the key.
func SealSops(s *Session, spec any) (any, error) {
	js, ok := spec.(api.JailSpec)
	if !ok {
		return spec, nil
	}
	env := make(map[string]string, len(js.Env))
	for k, v := range js.Env {
		if rest, ok := strings.CutPrefix(v, sopsRefPrefix); ok {
			path, _, _ := strings.Cut(rest, ":")
			sealed, err := s.Store.SopsSealed(path)
			if err != nil {
				return nil, err
			}
			v = sealed
		}
		env[k] = v
	}
	js.Env = env
	return js, nil
}

// specHash returns the hash label value and the full label set to write.
func specHash(spec any, user map[string]string) (string, map[string]string, error) {
	m, err := model.ToMap(spec)
	if err != nil {
		return "", nil, err
	}
	b, err := jsonCanon(map[string]any{"spec": m, "labels": user})
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])[:16]
	labels := make(map[string]string, len(user)+1)
	for k, v := range user {
		labels[k] = v
	}
	labels[HashLabel] = h
	return h, labels, nil
}

// SpecHash returns the hash sync would record for a declaration.
func SpecHash(spec any, user map[string]string) (string, map[string]string, error) {
	return specHash(spec, user)
}

func diffSpec(want, have any) ([]string, error) {
	w, err := model.ToMap(want)
	if err != nil {
		return nil, err
	}
	h, err := model.ToMap(have)
	if err != nil {
		return nil, err
	}
	var out []string
	subsetDiff("spec", w, h, &out)
	return out, nil
}

// Counts returns the number of items per action.
func (p *Plan) Counts() map[Action]int {
	m := map[Action]int{}
	for _, i := range p.Items {
		m[i.Action]++
	}
	return m
}

// Summary is a one-line count.
func (p *Plan) Summary() string {
	c := p.Counts()
	s := fmt.Sprintf("%d create, %d update, %d delete, %d unchanged, %d unmanaged", c[ActionCreate], c[ActionUpdate], c[ActionDelete], c[ActionMatch], c[ActionUnmanaged])
	if c[ActionRefuse] > 0 {
		s += fmt.Sprintf(", %d refused", c[ActionRefuse])
	}
	if c[ActionBlocked] > 0 {
		s += fmt.Sprintf(", %d blocked", c[ActionBlocked])
	}
	if c[ActionError] > 0 {
		s += fmt.Sprintf(", %d error", c[ActionError])
	}
	if len(p.Errors) > 0 {
		s += fmt.Sprintf(", %d host(s) unreachable", len(p.Errors))
	}
	return s
}

// Drifted reports whether the live fleet differs from the repository: any
// create, update, delete of an owned object, or a refusal. Unmanaged objects
// are not drift.
func (p *Plan) Drifted() bool {
	for _, i := range p.Items {
		switch i.Action {
		case ActionCreate, ActionUpdate, ActionDelete, ActionRefuse, ActionBlocked, ActionError:
			return true
		}
	}
	return false
}

// Err joins host and item errors that make the plan unusable.
func (p *Plan) Err() error {
	var errs []error
	for _, e := range p.Errors {
		errs = append(errs, fmt.Errorf("host %s: %w", e.Host, e.Err))
	}
	for _, i := range p.Items {
		if i.Action == ActionError {
			errs = append(errs, fmt.Errorf("%s %s on %s: %s", i.Kind, i.Name, i.Host, strings.Join(i.Details, "; ")))
		}
	}
	return errors.Join(errs...)
}

// Refusals returns the items refused for ownership.
func (p *Plan) Refusals() []Item {
	var out []Item
	for _, i := range p.Items {
		if i.Action == ActionRefuse {
			out = append(out, i)
		}
	}
	return out
}

// Dangerous returns the items that need --force. Deletes count only when
// prune is set, because otherwise they are not executed.
func (p *Plan) Dangerous(prune bool) []Item {
	var out []Item
	for _, i := range p.Items {
		if len(i.Dangers) == 0 || (i.Action == ActionDelete && !prune) {
			continue
		}
		out = append(out, i)
	}
	return out
}
