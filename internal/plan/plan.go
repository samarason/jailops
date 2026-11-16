// Package plan is a small step engine. A Plan is an ordered list of steps. The
// Executor runs them in order; when a step fails it runs the Undo of the steps
// that completed, in reverse order (the reverter pattern). Progress goes to a
// callback, and a journal makes an interrupted run recoverable after a crash.
package plan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Step is one unit of work.
//
// Undo contract: Undo must be idempotent and must be safe to call when Do did
// not complete (a crash can interrupt Do at any point). A nil Undo means the
// step has no effect that needs reverting, or cannot be reverted; such a step
// should be placed as late in the plan as possible.
type Step struct {
	Name string
	// Describe is the exact command or effect, shown by dry runs.
	Describe string
	Do       func(ctx context.Context) error
	Undo     func(ctx context.Context) error
	// UndoOnFail runs this step's own Undo when its Do fails, for steps that
	// can fail half-way. Without it a failed step is assumed to have no effect.
	UndoOnFail bool
}

// Plan is an ordered list of steps.
type Plan struct {
	Name  string
	Steps []Step
}

// New builds a plan.
func New(name string, steps ...Step) *Plan { return &Plan{Name: name, Steps: steps} }

// Add appends steps and returns the plan.
func (p *Plan) Add(steps ...Step) *Plan { p.Steps = append(p.Steps, steps...); return p }

// Describe returns the exact list of effects without executing anything.
func (p *Plan) Describe() []string {
	out := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		d := s.Describe
		if d == "" {
			d = s.Name
		}
		out[i] = fmt.Sprintf("%02d %s: %s", i+1, s.Name, d)
	}
	return out
}

// Names returns the step names.
func (p *Plan) Names() []string {
	out := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		out[i] = s.Name
	}
	return out
}

// State is the journal state of a run.
type State string

const (
	StateRunning     State = "running"
	StateRollingBack State = "rolling_back"
	// StateFailed means the rollback itself failed; an operator must look.
	StateFailed State = "failed"
)

// Record is what the journal persists for one run.
type Record struct {
	ID    string   `json:"id"`
	Plan  string   `json:"plan"`
	Steps []string `json:"steps"`
	// Begun counts steps whose Do was started, Done those that finished.
	Begun int    `json:"begun"`
	Done  int    `json:"done"`
	State State  `json:"state"`
	Err   string `json:"err,omitempty"`
}

// Journal persists run records so a crashed daemon can roll an interrupted
// plan back.
type Journal interface {
	Put(ctx context.Context, r Record) error
	Get(ctx context.Context, id string) (Record, bool, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]Record, error)
}

// Phase is a progress phase.
type Phase string

const (
	PhaseStart      Phase = "start"
	PhaseDone       Phase = "done"
	PhaseFailed     Phase = "failed"
	PhaseUndo       Phase = "undo"
	PhaseUndone     Phase = "undone"
	PhaseUndoFailed Phase = "undo_failed"
)

// Event is reported to the progress callback (the operations resource).
type Event struct {
	Plan, ID, Step string
	Index, Total   int
	Phase          Phase
	Err            error
}

// Error is returned when a plan fails. It unwraps to the failing step's error,
// so errors.As and api.IsCode see through it.
type Error struct {
	Plan, Step string
	Err        error
	// UndoErrs holds failures of the rollback. Non-empty means the system may
	// not be back in its original state.
	UndoErrs []error
}

func (e *Error) Error() string {
	s := fmt.Sprintf("plan %s: step %s: %v", e.Plan, e.Step, e.Err)
	if len(e.UndoErrs) > 0 {
		parts := make([]string, len(e.UndoErrs))
		for i, u := range e.UndoErrs {
			parts[i] = u.Error()
		}
		s += "; rollback incomplete: " + strings.Join(parts, "; ")
	}
	return s
}
func (e *Error) Unwrap() error { return e.Err }

// Executor runs plans.
type Executor struct {
	Journal Journal // optional
	OnEvent func(Event)
}

func (e *Executor) emit(ev Event) {
	if e.OnEvent != nil {
		e.OnEvent(ev)
	}
}

func (e *Executor) put(ctx context.Context, r Record) error {
	if e.Journal == nil {
		return nil
	}
	return e.Journal.Put(ctx, r)
}

// Run executes the plan. id identifies the run in the journal.
func (e *Executor) Run(ctx context.Context, id string, p *Plan) error {
	rec := Record{ID: id, Plan: p.Name, Steps: p.Names(), State: StateRunning}
	if err := e.put(ctx, rec); err != nil {
		return fmt.Errorf("plan %s: journal: %w", p.Name, err)
	}
	for i, s := range p.Steps {
		var err error
		if err = ctx.Err(); err == nil {
			rec.Begun = i + 1
			err = e.put(ctx, rec)
		}
		if err == nil {
			e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: i, Total: len(p.Steps), Phase: PhaseStart})
			err = s.Do(ctx)
		}
		if err != nil {
			e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: i, Total: len(p.Steps), Phase: PhaseFailed, Err: err})
			from := i - 1
			if s.UndoOnFail {
				from = i
			}
			return e.rollback(ctx, id, p, rec, from, s.Name, err)
		}
		rec.Done = i + 1
		e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: i, Total: len(p.Steps), Phase: PhaseDone})
	}
	if e.Journal != nil {
		// The last step's Done is recorded before the record goes: a record that survives the cleanup (the daemon dies
		// in the gap, or the delete fails) says the plan completed, and a recovery drops it instead of undoing it.
		dctx := context.WithoutCancel(ctx)
		_ = e.put(dctx, rec)
		var derr error
		for try := 0; try < 3; try++ {
			if derr = e.Journal.Delete(dctx, id); derr == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if derr != nil {
			return fmt.Errorf("plan %s: journal cleanup: %w", p.Name, derr)
		}
	}
	return nil
}

type begunKey struct{}

// BegunSteps tells an Undo how many steps of its plan had begun when the rollback started (the step that failed or was
// interrupted included): an undo that depends on whether a later step ever ran, such as whether a jail was started, asks
// it, and it gets the same answer after a crash, from the journal.
func BegunSteps(ctx context.Context) int {
	n, _ := ctx.Value(begunKey{}).(int)
	return n
}

// rollback undoes steps from..0 in reverse. It ignores cancellation of ctx:
// a cancelled operation must still leave the system consistent.
func (e *Executor) rollback(ctx context.Context, id string, p *Plan, rec Record, from int, failed string, cause error) error {
	uctx := context.WithValue(context.WithoutCancel(ctx), begunKey{}, rec.Begun)
	rec.State = StateRollingBack
	rec.Err = cause.Error()
	_ = e.put(uctx, rec)
	var undoErrs []error
	for j := from; j >= 0; j-- {
		s := p.Steps[j]
		if s.Undo == nil {
			continue
		}
		e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: j, Total: len(p.Steps), Phase: PhaseUndo})
		if err := s.Undo(uctx); err != nil {
			undoErrs = append(undoErrs, fmt.Errorf("undo %s: %w", s.Name, err))
			e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: j, Total: len(p.Steps), Phase: PhaseUndoFailed, Err: err})
			continue
		}
		e.emit(Event{Plan: p.Name, ID: id, Step: s.Name, Index: j, Total: len(p.Steps), Phase: PhaseUndone})
	}
	if e.Journal != nil {
		if len(undoErrs) > 0 {
			rec.State = StateFailed
			_ = e.put(uctx, rec)
		} else {
			_ = e.Journal.Delete(uctx, id)
		}
	}
	return &Error{Plan: p.Name, Step: failed, Err: cause, UndoErrs: undoErrs}
}

// Recover rolls back a run that a crash interrupted. p must be rebuilt from
// the same inputs as the original run (builders are deterministic: ids and
// names are generated before the plan is built). The in-flight step is undone
// too, because its effect is unknown.
func (e *Executor) Recover(ctx context.Context, id string, p *Plan) (found bool, err error) {
	if e.Journal == nil {
		return false, errors.New("plan: no journal")
	}
	rec, ok, err := e.Journal.Get(ctx, id)
	if err != nil || !ok {
		return false, err
	}
	if rec.Plan != p.Name || strings.Join(rec.Steps, "\x00") != strings.Join(p.Names(), "\x00") {
		return true, fmt.Errorf("plan: journal record %s does not match plan %s", id, p.Name)
	}
	if rec.State == StateRunning && len(rec.Steps) > 0 && rec.Done >= len(rec.Steps) {
		// every step finished; only the removal of the record was left
		_ = e.Journal.Delete(ctx, id)
		return true, nil
	}
	rerr := e.rollback(ctx, id, p, rec, rec.Begun-1, "interrupted", errors.New("interrupted by daemon restart"))
	var pe *Error
	if errors.As(rerr, &pe) && len(pe.UndoErrs) == 0 {
		return true, nil
	}
	return true, rerr
}

// MemJournal is an in-memory Journal, used by tests and by callers that do not
// need crash recovery.
type MemJournal struct {
	Recs map[string]Record
}

func (m *MemJournal) Put(_ context.Context, r Record) error {
	if m.Recs == nil {
		m.Recs = map[string]Record{}
	}
	m.Recs[r.ID] = r
	return nil
}
func (m *MemJournal) Get(_ context.Context, id string) (Record, bool, error) {
	r, ok := m.Recs[id]
	return r, ok, nil
}
func (m *MemJournal) Delete(_ context.Context, id string) error { delete(m.Recs, id); return nil }
func (m *MemJournal) List(context.Context) ([]Record, error) {
	var out []Record
	for _, r := range m.Recs {
		out = append(out, r)
	}
	return out, nil
}
