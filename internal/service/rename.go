package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/state"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/wireguard"
	"jailops.net/jailops/sdk/api"
)

// A rename gives an object a new name and rewrites every reference to it in one operation (design section 8.8).
// Each kind has a planner that reads the current state and lists the changes as renameStep values: data, not
// closures, so the request of the operation records them before the first one runs and a restart rebuilds the plan
// from them and undoes what was done (recoverInterrupted). The plan executor runs the steps in order and undoes the
// completed ones in reverse when one fails.

// renameStep is one change of a rename.
type renameStep struct {
	Op string `json:"op"`
	// Change is what the step reports; a step without one (moving a mountpoint out of the way) is not listed.
	Change api.RenameChange `json:"change"`
	// state: an object of the state store, before and after.
	Obj *renameObj `json:"obj,omitempty"`
	// file (through the lifecycle's files: spec.json, bundle.json) and state-file (the state directory): the
	// content of From before and of To after; a nil New removes To's content (nothing is written).
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	Old  []byte `json:"old,omitempty"`
	New  []byte `json:"new,omitempty"`
	// zfs-set: property Prop of dataset From, from OldValue to NewValue.
	Prop     string `json:"prop,omitempty"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
	// anchor: the ruleset moves from anchor From (OldRules) to anchor To (NewRules).
	OldRules string `json:"old_rules,omitempty"`
	NewRules string `json:"new_rules,omitempty"`
	// ifdesc: the description of Iface, inside the vnet of the jail Jail when set, from OldValue to NewValue.
	Iface string `json:"iface,omitempty"`
	Jail  string `json:"jail,omitempty"`
	// identities: the users, tokens and trust tokens whose project lists name From, to name To.
	Refs *store.ProjectRefs `json:"refs,omitempty"`
}

// renameObj is an object of the state store before and after a rename.
type renameObj struct {
	Kind   api.Kind  `json:"kind"`
	UUID   string    `json:"uuid"`
	Before renameDoc `json:"before"`
	After  renameDoc `json:"after"`
}

type renameDoc struct {
	Name      string            `json:"name"`
	Project   string            `json:"project,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	ManagedBy string            `json:"managed_by,omitempty"`
	Spec      json.RawMessage   `json:"spec"`
}

// renameRequest is what the journal keeps of a rename.
type renameRequest struct {
	Steps []renameStep `json:"steps"`
}

// renamePlan is what a planner found: the steps and the locks they need.
type renamePlan struct {
	steps     []renameStep
	locks     []string
	resources map[string][]string
	// after runs once the steps succeeded (events, kicks, in-memory state); it must not fail.
	after func(ctx context.Context)
	// warnings go into the result.
	warnings []string
}

func (p *renamePlan) add(st ...renameStep) { p.steps = append(p.steps, st...) }

func (p *renamePlan) lock(keys ...string) { p.locks = append(p.locks, keys...) }

// renameJob is one rename request.
type renameJob struct {
	kind    api.Kind
	noun    string // "network": the action of the events and the word of the messages
	path    string // "/api/v1/networks": the base of the object's URL
	project string // the project of a project-level object, "" for a host-level one
	from    string
	to      string
	// plan reads the state and lists the changes. It runs once before the locks are taken (to learn them) and again
	// under them; it fails for a rename that cannot go ahead.
	plan func(ctx context.Context) (*renamePlan, error)
}

// runRename answers a dry run with the plan, or runs the rename as an operation.
func (s *Service) runRename(ctx context.Context, j renameJob, dry bool) (api.Operation, *api.RenameResult, error) {
	if j.from == j.to {
		return api.Operation{}, nil, invalid("the new name is the old name")
	}
	p, err := j.plan(ctx)
	if err != nil {
		return api.Operation{}, nil, err
	}
	if dry {
		res := s.renameResult(j, p.steps)
		res.DryRun, res.Warnings = true, p.warnings
		return api.Operation{}, &res, nil
	}
	locks := uniqStrings(append(slices.Clone(p.locks), renameLock(j.kind, j.project, j.from), renameLock(j.kind, j.project, j.to)))
	res := p.resources
	if res == nil {
		res = map[string][]string{}
	}
	desc := fmt.Sprintf("rename %s %s to %s", j.noun, j.from, j.to)
	op, err := s.Submit(ctx, OpSpec{Description: desc, Project: j.project, Resources: res, Locks: locks,
		Run: func(ctx context.Context, h *OpHandle) (any, error) {
			// again under the locks: what changed in the meantime is seen now
			p, err := j.plan(ctx)
			if err != nil {
				return nil, err
			}
			for _, l := range p.locks {
				if !slices.Contains(locks, l) {
					return nil, api.Errorf(api.CodeConflict, "what refers to %s %q changed while the rename was prepared", j.noun, j.from).
						WithHint("run the rename again")
				}
			}
			runID := "rename/" + strings.ToLower(string(j.kind)) + "/" + j.project + "/" + j.from
			if err := s.journalIdle(ctx, runID); err != nil {
				return nil, err
			}
			if err := h.Bind(runID, &opRequest{Kind: "rename", Rename: &renameRequest{Steps: p.steps}}); err != nil {
				return nil, internal(err)
			}
			err = s.planExec.Run(ctx, runID, s.renameExecPlan(p.steps))
			// the registry is read again from the pool whatever happened: jail records and datasets may have moved
			_ = s.RefreshJails(context.WithoutCancel(ctx))
			if err != nil {
				return nil, err
			}
			if p.after != nil {
				p.after(ctx)
			}
			s.emitIn(ctx, j.project, j.noun+"-renamed", j.path+"/"+j.to)
			s.kick()
			out := s.renameResult(j, p.steps)
			out.Warnings = p.warnings
			return out, nil
		}})
	return op, nil, err
}

// journalIdle refuses a rename while an interrupted run of the same rename waits for the operator.
func (s *Service) journalIdle(ctx context.Context, runID string) error {
	if _, ok, _ := s.journal.Get(ctx, runID); ok {
		return api.Errorf(api.CodeBusy, "an earlier run of this rename did not finish (%s)", runID).
			WithHint("run `jailops doctor`: the journal record must be resolved first")
	}
	return nil
}

func renameLock(kind api.Kind, project, name string) string {
	return "rename/" + string(kind) + "/" + project + "/" + name
}

func (s *Service) renameResult(j renameJob, steps []renameStep) api.RenameResult {
	res := api.RenameResult{Kind: j.kind, Project: j.project, From: j.from, To: j.to, Changes: []api.RenameChange{}, Counts: map[string]int{}}
	for _, st := range steps {
		if st.Change.Kind == "" {
			continue
		}
		res.Changes = append(res.Changes, st.Change)
		res.Counts[st.Change.Kind]++
	}
	res.Steps = s.renameExecPlan(steps).Describe()
	return res
}

// renameExecPlan turns the steps into a plan. It is deterministic: recovery rebuilds the same plan from the
// recorded steps.
func (s *Service) renameExecPlan(steps []renameStep) *plan.Plan {
	p := plan.New("rename")
	for i, st := range steps {
		st := st
		p.Add(plan.Step{Name: st.Op, Describe: st.describe(),
			Do: func(ctx context.Context) error {
				if s.renameCrashAt == i+1 {
					runtime.Goexit() // tests: the daemon dies here, leaving the journal as a crash would
				}
				return s.renameDo(ctx, st, false)
			},
			Undo: func(ctx context.Context) error { return s.renameDo(ctx, st, true) },
			// a step that fails may have done part of its work (a state put, a file write): undo it as well
			UndoOnFail: true})
	}
	return p
}

func (st renameStep) describe() string {
	switch st.Op {
	case "state":
		return fmt.Sprintf("%s %s: %s", strings.ToLower(string(st.Obj.Kind)), st.Obj.Before.Name, st.Change.Detail)
	case "file", "state-file":
		if st.From == st.To {
			return "write " + st.To
		}
		return fmt.Sprintf("move %s to %s", st.From, st.To)
	case "zfs-rename":
		return fmt.Sprintf("zfs rename %s %s", st.From, st.To)
	case "zfs-set":
		return fmt.Sprintf("zfs set %s=%s %s", st.Prop, st.NewValue, st.From)
	case "anchor":
		return fmt.Sprintf("pfctl -a %s -f -; pfctl -a %s -F all", st.To, st.From)
	case "dir":
		return fmt.Sprintf("mv %s %s", st.From, st.To)
	case "storage-registry":
		return fmt.Sprintf("the daemon registers storage %s as %s", st.From, st.To)
	case "user-name":
		return fmt.Sprintf("rename user %s to %s", st.From, st.To)
	case "wg-keys":
		return fmt.Sprintf("move the keys of tunnel %s to %s", st.From, st.To)
	case "identities":
		return fmt.Sprintf("replace project %s by %s in the scopes of %d identities", st.From, st.To, st.Refs.Count())
	case "ifdesc":
		if st.Jail != "" {
			return fmt.Sprintf("ifconfig -j %s %s description %q", st.Jail, st.Iface, st.NewValue)
		}
		return fmt.Sprintf("ifconfig %s description %q", st.Iface, st.NewValue)
	}
	return st.Op
}

// renameDo does one step, or undoes it. Both directions are idempotent: a crash can interrupt either at any point.
func (s *Service) renameDo(ctx context.Context, st renameStep, undo bool) error {
	switch st.Op {
	case "state":
		d := st.Obj.After
		if undo {
			d = st.Obj.Before
		}
		return s.putRenameDoc(st.Obj, d)
	case "file":
		path, data := st.To, st.New
		if undo {
			path, data = st.From, st.Old
		}
		if data == nil {
			return nil
		}
		return s.d.Files.WriteAtomic(ctx, path, data)
	case "state-file":
		from, to, data := st.From, st.To, st.New
		if undo {
			from, to, data = st.To, st.From, st.Old
		}
		if data != nil {
			if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
				return err
			}
			if err := writeFileAtomic(to, data); err != nil {
				return err
			}
		}
		if from != to {
			if err := os.Remove(from); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return nil
	case "zfs-rename":
		from, to := st.From, st.To
		if undo {
			from, to = to, from
		}
		have, err := s.d.ZFS.Exists(ctx, from)
		if err != nil {
			return err
		}
		if !have {
			if done, _ := s.d.ZFS.Exists(ctx, to); done {
				return nil
			}
			if undo {
				return nil // never done
			}
			return api.Errorf(api.CodeNotFound, "dataset %s not found", from)
		}
		return s.d.ZFS.Rename(ctx, from, to)
	case "zfs-set":
		v := st.NewValue
		if undo {
			v = st.OldValue
		}
		ok, err := s.d.ZFS.Exists(ctx, st.From)
		if err != nil {
			return err
		}
		if !ok {
			if undo {
				return nil // the dataset was never renamed to this name
			}
			return api.Errorf(api.CodeNotFound, "dataset %s not found", st.From)
		}
		if cur, err := s.d.ZFS.Get(ctx, st.From, st.Prop); err == nil && cur == v {
			return nil
		}
		return s.d.ZFS.Set(ctx, st.From, map[string]string{st.Prop: v})
	case "anchor":
		from, to, rules := st.From, st.To, st.NewRules
		if undo {
			from, to, rules = st.To, st.From, st.OldRules
		}
		if s.d.PF == nil {
			return nil
		}
		if rules != "" {
			if err := s.d.PF.Load(ctx, to, rules); err != nil {
				return err
			}
		}
		if err := s.d.PF.Flush(ctx, from); err != nil && !api.IsCode(err, api.CodeNotFound) {
			return err
		}
		return nil
	case "dir":
		if undo {
			return renameDir(st.To, st.From)
		}
		return renameDir(st.From, st.To)
	case "identities":
		if undo {
			return s.replaceProject(ctx, *st.Refs, st.To, st.From)
		}
		return s.replaceProject(ctx, *st.Refs, st.From, st.To)
	case "storage-registry":
		from, to := st.From, st.To
		if undo {
			from, to = to, from
		}
		return s.renameStorageRegistry(from, to)
	case "user-name":
		from, to := st.From, st.To
		if undo {
			from, to = to, from
		}
		return s.renameUserName(ctx, st.Prop, from, to)
	case "wg-keys":
		from, to := st.From, st.To
		if undo {
			from, to = to, from
		}
		if s.d.WG == nil {
			return nil
		}
		return s.d.WG.WGRename(ctx, wireguard.RenameReq{From: from, To: to})
	case "ifdesc":
		v := st.NewValue
		if undo {
			v = st.OldValue
		}
		err := s.setIfaceDesc(ctx, st.Jail, st.Iface, v)
		if undo && err != nil {
			// an interface that went away with its jail needs no description
			s.log.Warn("rename: restoring an interface description failed", "iface", st.Iface, "jail", st.Jail, "err", err)
			return nil
		}
		return err
	}
	return fmt.Errorf("unknown rename step %q", st.Op)
}

// setIfaceDesc sets the description of a host interface, or of one in the vnet of a running jail.
func (s *Service) setIfaceDesc(ctx context.Context, jail, iface, desc string) error {
	if jail == "" {
		if s.d.Net == nil {
			return nil
		}
		return s.d.Net.SetDescription(ctx, iface, desc)
	}
	if s.d.Run == nil {
		return nil
	}
	args := []string{"-j", jail, iface, "description", desc}
	if desc == "" {
		args = []string{"-j", jail, iface, "-description"}
	}
	_, err := s.d.Run.Run(ctx, run.Cmd{Name: "ifconfig", Args: args, Timeout: 10 * time.Second})
	return err
}

// putRenameDoc writes one side of a state object; a put that changes nothing is skipped.
func (s *Service) putRenameDoc(o *renameObj, d renameDoc) error {
	cur, err := s.d.State.Get(o.Kind, o.UUID)
	if err != nil {
		return internal(err)
	}
	m := cur.Metadata
	if m.Name == d.Name && m.Project == d.Project && m.ManagedBy == d.ManagedBy && labelsEqual(m.Labels, d.Labels) && equalJSON(cur.Spec, d.Spec) {
		return nil
	}
	_, err = s.d.State.Apply(state.Command{Version: state.CommandVersion, ID: state.NewUUID(), Time: s.now().UTC(), Op: state.OpPut,
		Kind: o.Kind, UUID: o.UUID, Name: d.Name, Scope: m.Scope, Host: m.Host, Project: d.Project, Labels: d.Labels,
		ManagedBy: d.ManagedBy, Spec: d.Spec, ExpectGeneration: AnyGeneration, MoveProject: d.Project != m.Project})
	return mapStateErr(err, strings.ToLower(string(o.Kind)), d.Name)
}

// ---- helpers the planners share ----

// stateStep renames, moves or rewrites one state object. change says what; spec is the spec after (nil keeps it).
func stateStep(kind api.Kind, o *state.Object, name, project string, spec any, change api.RenameChange) (renameStep, error) {
	after := renameDoc{Name: name, Project: project, Labels: o.Metadata.Labels, ManagedBy: o.Metadata.ManagedBy, Spec: o.Spec}
	if spec != nil {
		b, err := json.Marshal(spec)
		if err != nil {
			return renameStep{}, internal(err)
		}
		after.Spec = b
	}
	before := renameDoc{Name: o.Metadata.Name, Project: o.Metadata.Project, Labels: o.Metadata.Labels, ManagedBy: o.Metadata.ManagedBy, Spec: o.Spec}
	return renameStep{Op: "state", Change: change, Obj: &renameObj{Kind: kind, UUID: o.Metadata.UUID, Before: before, After: after}}, nil
}

// objectChange is the change of the renamed object itself.
func objectChange(noun, from, to string) api.RenameChange {
	return api.RenameChange{Kind: api.RenameObject, Object: noun + " " + from, Detail: "renamed to " + to}
}

// jailObject names a jail in a change.
func jailObject(project, name string) string {
	return fmt.Sprintf("jail %s (project %s)", name, project)
}

// jailRecordSteps rewrites the records of a jail (spec.json and bundle.json in its container) for the jail after,
// at the key the container has once the steps before ran. edit changes the bundle beyond the spec (an image
// rename); it may be nil.
func (s *Service) jailRecordSteps(ctx context.Context, key string, before, after api.Jail, change api.RenameChange, edit func(b map[string]any)) ([]renameStep, error) {
	return s.jailRecordStepsAt(ctx, s.jailMount(key), s.jailMount(key), before, after, change, edit)
}

// jailRecordStepsAt is jailRecordSteps for a jail whose container is mounted at dir now and at newDir when the
// records are written (a jail rename moves the container first).
func (s *Service) jailRecordStepsAt(ctx context.Context, dir, newDir string, before, after api.Jail, change api.RenameChange, edit func(b map[string]any)) ([]renameStep, error) {
	spec, bundle := filepath.Join(dir, "spec.json"), filepath.Join(dir, "bundle.json")
	nspec, nbundle := filepath.Join(newDir, "spec.json"), filepath.Join(newDir, "bundle.json")
	oldSpec, err := s.d.Files.ReadFile(ctx, spec)
	if err != nil {
		return nil, api.Errorf(api.CodeConflict, "the record of jail %q cannot be read: %v", jailDisplay(before.Metadata.Project, before.Metadata.Name), err).
			WithHint("start or repair the jail first (`jailops doctor`)")
	}
	after.Status = api.JailStatus{}
	after.Metadata.Generation = before.Metadata.Generation + 1
	after.Metadata.UpdatedAt = s.now().UTC()
	rec := map[string]any{}
	if err := json.Unmarshal(oldSpec, &rec); err != nil {
		return nil, internal(fmt.Errorf("%s: %w", spec, err))
	}
	rec["metadata"], rec["spec"] = after.Metadata, after.Spec
	newSpec, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, internal(err)
	}
	steps := []renameStep{{Op: "file", Change: change, From: nspec, To: nspec, Old: oldSpec, New: append(newSpec, '\n')}}
	if oldBundle, err := s.d.Files.ReadFile(ctx, bundle); err == nil {
		bd := map[string]any{}
		if err := json.Unmarshal(oldBundle, &bd); err == nil {
			bd["metadata"], bd["spec"] = after.Metadata, after.Spec
			if edit != nil {
				edit(bd)
			}
			if nb, err := json.MarshalIndent(bd, "", "  "); err == nil {
				steps = append(steps, renameStep{Op: "file", From: nbundle, To: nbundle, Old: oldBundle, New: append(nb, '\n')})
			}
		}
	}
	return steps, nil
}

// datasetMoveSteps renames the dataset tree from to to and moves every local mountpoint below it from the
// directory oldMP to newMP: the mountpoints are taken away (deepest first, which unmounts the tree), the tree is
// renamed and the new mountpoints are set (parents first, which mounts what may be mounted).
func (s *Service) datasetMoveSteps(ctx context.Context, from, to, oldMP, newMP string) ([]renameStep, error) {
	kids, err := s.d.ZFS.Descendants(ctx, from)
	if err != nil {
		return nil, err
	}
	all := append([]string{from}, kids...)
	type mp struct{ ds, val string }
	var local []mp
	for _, d := range all {
		v, err := s.d.ZFS.Get(ctx, d, "mountpoint")
		if err != nil {
			return nil, err
		}
		if v == "" || v == "none" || v == "legacy" {
			continue
		}
		local = append(local, mp{d, v})
	}
	var out []renameStep
	for i := len(local) - 1; i >= 0; i-- {
		out = append(out, renameStep{Op: "zfs-set", From: local[i].ds, Prop: "mountpoint", OldValue: local[i].val, NewValue: "none"})
	}
	out = append(out, renameStep{Op: "zfs-rename", From: from, To: to,
		Change: api.RenameChange{Kind: api.RenameDataset, Object: "dataset " + from, Detail: "renamed to " + to}})
	for _, m := range local {
		nd := to + strings.TrimPrefix(m.ds, from)
		nv := m.val
		if rest, ok := strings.CutPrefix(m.val, oldMP); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			nv = newMP + rest
		}
		st := renameStep{Op: "zfs-set", From: nd, Prop: "mountpoint", OldValue: "none", NewValue: nv}
		if nv != m.val {
			st.Change = api.RenameChange{Kind: api.RenameDataset, Object: "mountpoint of " + nd, Detail: m.val + " -> " + nv}
		}
		out = append(out, st)
	}
	return out, nil
}

// stateFileStep moves a file of the state directory (update history, upgrade runs) to its new name, with its
// content rewritten by edit (nil keeps it). A file that does not exist gives no step.
func (s *Service) stateFileStep(from, to string, edit func([]byte) []byte, change api.RenameChange) (renameStep, bool) {
	if s.d.StateDir == "" {
		return renameStep{}, false
	}
	old, err := os.ReadFile(from)
	if err != nil {
		return renameStep{}, false
	}
	nb := old
	if edit != nil {
		nb = edit(old)
	}
	// a file left under the new name by an earlier object of that name (a deleted jail's history) is replaced
	return renameStep{Op: "state-file", Change: change, From: from, To: to, Old: old, New: nb}, true
}

// refuseManaged refuses to rename an object another system owns: the next pass of that system would bring the old
// name back.
func refuseManaged(noun, name, managedBy string) error {
	switch {
	case managedBy == "":
		return nil
	case managedBy == api.AppAccessManagedBy:
		return api.Errorf(api.CodeForbidden, "%s %q is managed by app access and keeps its name", noun, name).
			WithHint("jailops app allow and jailops app deny manage it")
	case strings.HasPrefix(managedBy, "hub:"):
		return api.Errorf(api.CodeForbidden, "%s %q is managed by a hub (%s)", noun, name, managedBy).
			WithHint("rename it on the hub, which applies the new name to its hosts")
	}
	return api.Errorf(api.CodeForbidden, "%s %q is managed by %s", noun, name, managedBy).
		WithHint("rename it in the repository that defines it; the next sync applies the new name")
}

// RenameOptions are the parts of a rename request the service needs.
type RenameOptions struct {
	NewName string
	DryRun  bool
	// Expect is the If-Match generation of the object, or AnyGeneration.
	Expect int64
}

// checkGeneration fails when the object moved on since the caller read it.
func checkGeneration(noun, name string, expect, cur int64) error {
	if expect != AnyGeneration && expect != cur {
		return api.Errorf(api.CodeConflict, "%s %q changed: current generation is %d", noun, name, cur).
			WithHint("read it again and repeat the rename").WithDetail("generation", itoa64(cur))
	}
	return nil
}

// renameByAction answers an update that changes the name of a kind that has a rename: the update keeps the name.
func renameByAction(cmd, path string) *api.Error {
	return invalid("an update does not change the name").
		WithHint(fmt.Sprintf("rename with jailops %s rename OLD NEW, or POST /api/v1/%s/{name}/rename", cmd, path))
}
func uniqStrings(in []string) []string {
	var out []string
	for _, x := range in {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
