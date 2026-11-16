package service

import (
	"context"
	"encoding/json"
	"jailops.net/jailops/internal/validate"
	"time"

	"jailops.net/jailops/internal/state"
	"jailops.net/jailops/sdk/api"
)

// AnyGeneration disables the If-Match check.
const AnyGeneration = state.AnyGeneration

// object is a stored object with its typed spec.
type object[S any] struct {
	Meta api.ObjectMeta
	Spec S
}

// kindStore is the typed access to one kind of state object.
type kindStore[S any] struct {
	s      *Service
	kind   api.Kind
	scope  api.Scope
	action string // "network" in "network-created"
	path   string // "/api/v1/networks"
	// projectLevel kinds (firewall policies, address sets, backup policies)
	// are unique per project: names are scoped by project.
	projectLevel bool
	project      string
}

func newKindStore[S any](s *Service, kind api.Kind, scope api.Scope, action, path string) kindStore[S] {
	return kindStore[S]{s: s, kind: kind, scope: scope, action: action, path: path}
}

func newProjectKindStore[S any](s *Service, kind api.Kind, scope api.Scope, action, path string) kindStore[S] {
	k := newKindStore[S](s, kind, scope, action, path)
	k.projectLevel = true
	return k
}

// p returns the store scoped to one project. Host-level kinds ignore it.
func (k kindStore[S]) p(project string) kindStore[S] {
	k.project = project
	return k
}

// proj is the project of the objects this store reads and writes: "" for
// host-level kinds, the selected project otherwise (empty when none was selected: there is no default project).
func (k kindStore[S]) proj() string {
	if !k.projectLevel {
		return ""
	}
	return k.project
}

func decodeObject[S any](o *state.Object) (object[S], error) {
	var out object[S]
	out.Meta = o.Metadata
	if len(o.Spec) > 0 {
		if err := json.Unmarshal(o.Spec, &out.Spec); err != nil {
			return out, api.Errorf(api.CodeInternal, "stored %s %q is unreadable: %v", o.Kind, o.Metadata.Name, err)
		}
	}
	return out, nil
}

func (k kindStore[S]) list() ([]object[S], error) {
	var objs []*state.Object
	var err error
	if k.projectLevel {
		objs, err = k.s.d.State.ListIn(k.kind, k.proj(), "")
	} else {
		objs, err = k.s.d.State.List(k.kind, "")
	}
	if err != nil {
		return nil, internal(err)
	}
	out := make([]object[S], 0, len(objs))
	for _, o := range objs {
		if o.Metadata.Scope != "" && o.Metadata.Scope != k.scope {
			continue
		}
		d, err := decodeObject[S](o)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// listAll lists the objects of every project.
func (k kindStore[S]) listAll() ([]object[S], error) {
	objs, err := k.s.d.State.List(k.kind, "")
	if err != nil {
		return nil, internal(err)
	}
	out := make([]object[S], 0, len(objs))
	for _, o := range objs {
		if o.Metadata.Scope != "" && o.Metadata.Scope != k.scope {
			continue
		}
		d, err := decodeObject[S](o)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (k kindStore[S]) getObj(name string) (*state.Object, error) {
	return k.s.d.State.GetByNameIn(k.kind, k.scope, k.proj(), name)
}

func (k kindStore[S]) get(name string) (object[S], error) {
	o, err := k.getObj(name)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return object[S]{}, notFound(k.action, name)
		}
		return object[S]{}, internal(err)
	}
	return decodeObject[S](o)
}

func (k kindStore[S]) exists(name string) bool {
	_, err := k.getObj(name)
	return err == nil
}

// notTaken fails with already_exists when the name is in use.
func (k kindStore[S]) notTaken(name string) error {
	if name != "" && k.exists(name) {
		return api.Errorf(api.CodeAlreadyExists, "%s %q already exists", k.action, name)
	}
	return nil
}

func (k kindStore[S]) host() string {
	if k.scope == api.ScopeHost {
		return k.s.d.HostUUID
	}
	return ""
}

// create stores a new object. The caller validated the spec.
func (k kindStore[S]) create(ctx context.Context, meta api.ObjectMeta, spec S) (object[S], error) {
	if k.projectLevel && k.project == "" {
		return object[S]{}, ErrProjectRequired()
	}
	if err := api.ValidLabels(meta.Labels); err != nil {
		return object[S]{}, err
	}
	if err := api.CheckComment(spec); err != nil {
		return object[S]{}, err
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return object[S]{}, internal(err)
	}
	now := k.s.now().UTC()
	id := state.NewUUID()
	if meta.UUID != "" && k.scope == api.ScopeHost {
		// A fleet hub applies a definition under the UUID it holds.
		id = meta.UUID
	}
	res, err := k.s.d.State.Apply(state.Command{
		Version: state.CommandVersion, ID: state.NewUUID(), Time: now, Op: state.OpPut,
		Kind: k.kind, UUID: id, Name: meta.Name, Scope: k.scope, Host: k.host(), Project: k.proj(),
		Labels: meta.Labels, ManagedBy: meta.ManagedBy, Spec: raw, ExpectGeneration: 0,
	})
	if err != nil {
		return object[S]{}, mapStateErr(err, k.action, meta.Name)
	}
	k.s.emitIn(ctx, k.proj(), k.action+"-created", k.path+"/"+meta.Name)
	return decodeObject[S](res.Object)
}

// update replaces labels and spec. An update that changes nothing keeps the
// generation. expect is the If-Match generation or AnyGeneration.
func (k kindStore[S]) update(ctx context.Context, name string, expect int64, labels map[string]string, managedBy *string, spec S) (object[S], error) {
	old, err := k.getObj(name)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return object[S]{}, notFound(k.action, name)
		}
		return object[S]{}, internal(err)
	}
	if expect != AnyGeneration && expect != old.Metadata.Generation {
		return object[S]{}, api.Errorf(api.CodeConflict, "%s %q changed: current generation is %d", k.action, name, old.Metadata.Generation).
			WithHint("read it again and re-apply your change").WithDetail("generation", itoa64(old.Metadata.Generation))
	}
	if err := api.CheckComment(spec); err != nil {
		return object[S]{}, err
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return object[S]{}, internal(err)
	}
	mb := old.Metadata.ManagedBy
	if managedBy != nil {
		mb = *managedBy
	}
	if equalJSON(raw, old.Spec) && labelsEqual(labels, old.Metadata.Labels) && mb == old.Metadata.ManagedBy {
		return decodeObject[S](old)
	}
	if !labelsEqual(labels, old.Metadata.Labels) {
		// labels stored before the rules existed stay until they are changed
		if err := api.ValidLabels(labels); err != nil {
			return object[S]{}, err
		}
	}
	res, err := k.s.d.State.Apply(state.Command{
		Version: state.CommandVersion, ID: state.NewUUID(), Time: k.s.now().UTC(), Op: state.OpPut,
		Kind: k.kind, UUID: old.Metadata.UUID, Name: name, Scope: k.scope, Host: k.host(), Project: k.proj(),
		Labels: labels, ManagedBy: mb, Spec: raw, ExpectGeneration: old.Metadata.Generation,
	})
	if err != nil {
		return object[S]{}, mapStateErr(err, k.action, name)
	}
	k.s.emitIn(ctx, k.proj(), k.action+"-updated", k.path+"/"+name)
	return decodeObject[S](res.Object)
}

func (k kindStore[S]) delete(ctx context.Context, name string, expect int64) error {
	old, err := k.getObj(name)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return notFound(k.action, name)
		}
		return internal(err)
	}
	if expect != AnyGeneration && expect != old.Metadata.Generation {
		return api.Errorf(api.CodeConflict, "%s %q changed: current generation is %d", k.action, name, old.Metadata.Generation)
	}
	_, err = k.s.d.State.Apply(state.Command{
		Version: state.CommandVersion, ID: state.NewUUID(), Time: k.s.now().UTC(), Op: state.OpDelete,
		Kind: k.kind, UUID: old.Metadata.UUID, Name: name, Scope: k.scope, Project: k.proj(), ExpectGeneration: old.Metadata.Generation,
	})
	if err != nil {
		return mapStateErr(err, k.action, name)
	}
	k.s.emitIn(ctx, k.proj(), k.action+"-deleted", k.path+"/"+name)
	return nil
}

func mapStateErr(err error, what, name string) error {
	var ae *api.Error
	if asAPI(err, &ae) {
		return ae
	}
	return internal(err)
}

func equalJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jo, _ := json.Marshal(y)
	return string(ja) == string(jo)
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// MatchLabels reports whether labels carry every wanted key=value.
func MatchLabels(labels, want map[string]string) bool {
	for k, v := range want {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	return true
}

// ValidObjectName is the name rule for kinds without a stricter validator: the one rule for every name a user
// chooses, api.NamePattern, at most 63 characters.
func ValidObjectName(n string) error { return validate.Name("name", n) }

// MergePatch applies an RFC 7386 merge patch to the JSON form of v and
// decodes the result into out.
func MergePatch(v any, patch map[string]any, out any) error {
	var cur map[string]any
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &cur); err != nil {
		return err
	}
	b, err = json.Marshal(mergePatch(cur, patch))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return invalid("patched object is invalid: %v", err)
	}
	return nil
}

func mergePatch(dst, patch map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for key, v := range patch {
		switch pv := v.(type) {
		case nil:
			delete(dst, key)
		case map[string]any:
			dm, _ := dst[key].(map[string]any)
			dst[key] = mergePatch(dm, pv)
		default:
			dst[key] = v
		}
	}
	return dst
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func timeOr(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}
