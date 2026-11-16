package plan

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func rec(log *[]string, name string, failDo, failUndo bool) Step {
	return Step{
		Name: name, Describe: "do " + name,
		Do: func(context.Context) error {
			*log = append(*log, "do:"+name)
			if failDo {
				return errors.New("boom " + name)
			}
			return nil
		},
		Undo: func(context.Context) error {
			*log = append(*log, "undo:"+name)
			if failUndo {
				return errors.New("undofail " + name)
			}
			return nil
		},
	}
}

func TestRunReverts(t *testing.T) {
	tests := []struct {
		name string
		mk   func(l *[]string) []Step
		want []string
		undo int
	}{
		{"ok", func(l *[]string) []Step { return []Step{rec(l, "a", false, false), rec(l, "b", false, false)} }, []string{"do:a", "do:b"}, 0},
		{"fail middle", func(l *[]string) []Step {
			return []Step{rec(l, "a", false, false), rec(l, "b", true, false), rec(l, "c", false, false)}
		}, []string{"do:a", "do:b", "undo:a"}, 0},
		{"undo failure continues", func(l *[]string) []Step {
			return []Step{rec(l, "a", false, false), rec(l, "b", false, true), rec(l, "c", true, false)}
		}, []string{"do:a", "do:b", "do:c", "undo:b", "undo:a"}, 1},
		{"undo on fail", func(l *[]string) []Step {
			s := rec(l, "b", true, false)
			s.UndoOnFail = true
			return []Step{rec(l, "a", false, false), s}
		}, []string{"do:a", "do:b", "undo:b", "undo:a"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var l []string
			j := &MemJournal{}
			ex := &Executor{Journal: j}
			err := ex.Run(context.Background(), "x", New("p", tc.mk(&l)...))
			if !reflect.DeepEqual(l, tc.want) {
				t.Fatalf("log %v want %v", l, tc.want)
			}
			var pe *Error
			if len(tc.want) > 0 && tc.name != "ok" {
				if !errors.As(err, &pe) || len(pe.UndoErrs) != tc.undo {
					t.Fatalf("err %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, kept := j.Recs["x"]
			if kept != (tc.undo > 0) {
				t.Fatalf("journal kept=%v", kept)
			}
		})
	}
}

func TestCancelRollsBack(t *testing.T) {
	var l []string
	ctx, cancel := context.WithCancel(context.Background())
	a := rec(&l, "a", false, false)
	do := a.Do
	a.Do = func(c context.Context) error { err := do(c); cancel(); return err }
	err := (&Executor{}).Run(ctx, "x", New("p", a, rec(&l, "b", false, false)))
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(l, []string{"do:a", "undo:a"}) {
		t.Fatalf("%v %v", err, l)
	}
}

func TestDescribeDoesNotRun(t *testing.T) {
	var l []string
	p := New("p", rec(&l, "a", false, false))
	if d := p.Describe(); len(d) != 1 || d[0] != "01 a: do a" || len(l) != 0 {
		t.Fatal(d, l)
	}
}

func TestRecoverAfterCrash(t *testing.T) {
	var l []string
	j := &MemJournal{}
	steps := func() []Step {
		return []Step{rec(&l, "a", false, false), rec(&l, "b", false, false), rec(&l, "c", false, false)}
	}
	// crash while b in flight
	j.Put(context.Background(), Record{ID: "x", Plan: "p", Steps: New("p", steps()...).Names(), Begun: 2, Done: 1, State: StateRunning})
	ex := &Executor{Journal: j}
	found, err := ex.Recover(context.Background(), "x", New("p", steps()...))
	if !found || err != nil || !reflect.DeepEqual(l, []string{"undo:b", "undo:a"}) {
		t.Fatal(found, err, l)
	}
	if len(j.Recs) != 0 {
		t.Fatal("journal not cleaned")
	}
	j.Put(context.Background(), Record{ID: "y", Plan: "other", Steps: []string{"z"}})
	if _, err := ex.Recover(context.Background(), "y", New("p", steps()...)); err == nil {
		t.Fatal("mismatch accepted")
	}
}

func TestEvents(t *testing.T) {
	var ev []Phase
	ex := &Executor{OnEvent: func(e Event) { ev = append(ev, e.Phase) }}
	var l []string
	ex.Run(context.Background(), "x", New("p", rec(&l, "a", false, false), rec(&l, "b", true, false)))
	want := []Phase{PhaseStart, PhaseDone, PhaseStart, PhaseFailed, PhaseUndo, PhaseUndone}
	if !reflect.DeepEqual(ev, want) {
		t.Fatal(ev)
	}
}

// A record that outlived a completed plan (the daemon died between the last step and the removal of the record, or the
// removal failed) is dropped by the recovery: undoing it would destroy what the plan made.
func TestRecoverOfACompletedPlanUndoesNothing(t *testing.T) {
	j := &MemJournal{}
	ex := &Executor{Journal: &failingDelete{MemJournal: j}}
	undone := false
	p := New("make")
	p.Add(Step{Name: "one", Do: func(context.Context) error { return nil }, Undo: func(context.Context) error { undone = true; return nil }})
	p.Add(Step{Name: "two", Do: func(context.Context) error { return nil }, Undo: func(context.Context) error { undone = true; return nil }})
	if err := ex.Run(context.Background(), "make/x", p); err == nil {
		t.Fatal("the failed cleanup was not reported")
	}
	if _, ok := j.Recs["make/x"]; !ok {
		t.Fatal("the record is gone although the delete failed")
	}
	found, err := (&Executor{Journal: j}).Recover(context.Background(), "make/x", p)
	if !found || err != nil {
		t.Fatalf("%v %v", found, err)
	}
	if undone {
		t.Fatal("a completed plan was undone")
	}
	if _, ok := j.Recs["make/x"]; ok {
		t.Fatal("the record of a completed plan stays")
	}
}

type failingDelete struct{ *MemJournal }

func (f *failingDelete) Delete(context.Context, string) error { return errors.New("EIO") }
