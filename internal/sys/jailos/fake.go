package jailos

import (
	"context"
	"sort"
	"sync"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// FakeCall records one Controller call.
type FakeCall struct {
	Op, ConfPath, Name string
	Argv               []string
}

// Fake is an in-memory Jails. Create adds a running jail, Remove deletes it.
type Fake struct {
	mu    sync.Mutex
	jails map[string]Jail
	next  int
	calls []FakeCall
	// ExecFn, when set, answers Exec; otherwise Exec succeeds with no output
	// for a running jail.
	ExecFn func(name string, o ExecOpts) (run.Result, error)
	// FailCreate makes Create fail with this error.
	FailCreate error
}

var _ Jails = (*Fake)(nil)

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{jails: map[string]Jail{}, next: 1} }

// SetExecFn replaces ExecFn while the runtime may be in use.
func (f *Fake) SetExecFn(fn func(name string, o ExecOpts) (run.Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ExecFn = fn
}

// Calls returns the recorded calls.
func (f *Fake) Calls() []FakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FakeCall(nil), f.calls...)
}

// Put adds or replaces a running jail as it is given (a path, parameters), for tests of what depends on them.
func (f *Fake) Put(j Jail) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j.JID == 0 {
		j.JID = f.next
		f.next++
	}
	f.jails[j.Name] = j
}

// Create implements Controller.
func (f *Fake) Create(_ context.Context, confPath, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := validateConf(confPath); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, FakeCall{Op: "create", ConfPath: confPath, Name: name})
	if f.FailCreate != nil {
		return f.FailCreate
	}
	if _, ok := f.jails[name]; ok {
		return api.Errorf(api.CodeAlreadyExists, "jail %s already exists", name)
	}
	f.jails[name] = Jail{JID: f.next, Name: name, Params: map[string]string{}}
	f.next++
	return nil
}

// Remove implements Controller.
func (f *Fake) Remove(_ context.Context, confPath, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := validateConf(confPath); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, FakeCall{Op: "remove", ConfPath: confPath, Name: name})
	if _, ok := f.jails[name]; !ok {
		return api.Errorf(api.CodeNotFound, "jail %s not found", name)
	}
	delete(f.jails, name)
	return nil
}

// Exec implements Controller.
func (f *Fake) Exec(_ context.Context, name string, o ExecOpts) (run.Result, error) {
	if err := ValidateName(name); err != nil {
		return run.Result{}, err
	}
	if err := validateUser(o.User); err != nil {
		return run.Result{}, err
	}
	if len(o.Argv) == 0 || o.Argv[0] == "" || o.Argv[0][0] == '-' {
		return run.Result{}, api.Errorf(api.CodeInvalid, "exec needs a command")
	}
	f.mu.Lock()
	f.calls = append(f.calls, FakeCall{Op: "exec", Name: name, Argv: append([]string(nil), o.Argv...)})
	_, ok := f.jails[name]
	fn := f.ExecFn
	f.mu.Unlock()
	if !ok {
		return run.Result{}, api.Errorf(api.CodeNotFound, "jail %s not found", name)
	}
	if fn != nil {
		return fn(name, o)
	}
	return run.Result{}, nil
}

// List implements Observer.
func (f *Fake) List(context.Context) ([]Jail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Jail, 0, len(f.jails))
	for _, j := range f.jails {
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].JID < out[k].JID })
	return out, nil
}

// Get implements Observer.
func (f *Fake) Get(_ context.Context, name string) (Jail, bool, error) {
	if err := ValidateName(name); err != nil {
		return Jail{}, false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jails[name]
	return j, ok, nil
}
