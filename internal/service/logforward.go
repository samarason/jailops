package service

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/internal/logfwd"
	"jailops.net/jailops/internal/store"
	"jailops.net/jailops/sdk/api"
)

// Log forwarding. The sink list is logging.forward of jailopsd.yaml
// (Deps.LogForward) unless an administrator stored a LogForward object
// (state kind LogForward, the single object "default"), which replaces it
// until it is deleted. The forwarder reads the same files as the unified
// view, through the same reader, and the audit log from the database.

// logForwardName is the name of the single stored object.
const logForwardName = "default"

// logFailWarn is how long a sink may fail before doctor warns.
const logFailWarn = 5 * time.Minute

// metaOffsets keeps the forwarder's offsets in the meta table, one JSON
// object per sink.
type metaOffsets struct{ db *store.Store }

func offsetsKey(sink string) string { return "logforward.offsets." + sink }

func (m metaOffsets) Load(ctx context.Context, sink string) (map[string]int64, error) {
	v, err := m.db.Meta.Get(ctx, offsetsKey(sink))
	if api.IsCode(err, api.CodeNotFound) {
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return map[string]int64{}, nil // unreadable offsets: start over at the ends
	}
	return out, nil
}

func (m metaOffsets) Save(ctx context.Context, sink string, offsets map[string]int64) error {
	b, err := json.Marshal(offsets)
	if err != nil {
		return err
	}
	return m.db.Meta.Set(ctx, offsetsKey(sink), string(b))
}

func (m metaOffsets) Delete(ctx context.Context, sink string) error {
	return m.db.Meta.Delete(ctx, offsetsKey(sink))
}

// newForwarder builds the forwarder of the service; Start runs it.
func (s *Service) newForwarder() *logfwd.Forwarder {
	env := logfwd.Env{
		Hostname: s.d.Hostname, Reader: s.d.Logs, Offsets: metaOffsets{s.d.DB}, Log: s.log,
		Jails: s.forwardJails, AuditAfter: s.auditAfter, AuditLast: s.auditLast,
		SecretsDir: s.d.LogSecretsDir, OwnPorts: s.d.LogOwnPorts,
	}
	if s.d.Logs == nil {
		env.Reader = noLogs{}
	}
	if s.d.LogForwardTune != nil {
		s.d.LogForwardTune(&env)
	}
	s.fwdCheck = env.CheckFile
	if s.fwdCheck == nil {
		s.fwdCheck = logfwd.CheckFile
	}
	return logfwd.New(env)
}

// noLogs is the reader of a daemon without the helper: every jail is unreadable.
type noLogs struct{}

func (noLogs) TailFile(context.Context, string, int64, int64) ([]byte, int64, int64, error) {
	return nil, 0, 0, api.Errorf(api.CodeUnsupported, "this daemon has no way to read jail logs")
}

func (s *Service) forwardJails(ctx context.Context) ([]logfwd.Jail, error) {
	var out []logfwd.Jail
	for _, j := range s.logJails(func(string) bool { return true }) {
		lj := logfwd.Jail{Project: j.project, Name: j.name, Labels: j.labels, App: j.app, LogDir: JailLogDir(s.rootMount(j.key))}
		if j.app != "" && s.d.Logs != nil {
			lj.AppFiles = s.appLogFiles(ctx, j.key, j.app)
		}
		out = append(out, lj)
	}
	return out, nil
}

// auditLine renders an audit entry as the line a sink receives.
func auditLine(e store.AuditEntry) string {
	l := fmt.Sprintf("actor=%s kind=%s action=%q object=%s result=%s status=%d", e.Actor, e.ActorKind, e.Method+" "+e.Route, e.Object, e.Result, e.Status)
	if e.Project != "" {
		l += " project=" + e.Project
	}
	if e.Remote != "" {
		l += " remote=" + e.Remote
	}
	if e.Detail != "" {
		l += fmt.Sprintf(" detail=%q", e.Detail)
	}
	return l
}

func (s *Service) auditAfter(ctx context.Context, after int64, limit int) ([]logfwd.AuditRecord, error) {
	f := store.AuditFilter{AfterID: after, Limit: limit}
	es, err := s.d.DB.Audit.List(ctx, f)
	if err != nil {
		return nil, err
	}
	if after <= 0 {
		slices.Reverse(es) // without a cursor the list is newest first
	}
	out := make([]logfwd.AuditRecord, 0, len(es))
	for _, e := range es {
		out = append(out, logfwd.AuditRecord{ID: e.ID, Time: e.Time, Project: e.Project, Line: auditLine(e)})
	}
	return out, nil
}

func (s *Service) auditLast(ctx context.Context) (int64, error) {
	es, err := s.d.DB.Audit.List(ctx, store.AuditFilter{Limit: 1})
	if err != nil || len(es) == 0 {
		return 0, err
	}
	return es[0].ID, nil
}

// startLogForward applies the effective sink list and runs the forwarder.
func (s *Service) startLogForward() {
	spec, o, err := s.logForwardSpec()
	if err != nil {
		s.log.Error("log forwarding: the stored sink list is unreadable; using logging.forward of jailopsd.yaml", "err", err)
		spec, o = api.LogForwardSpec{Sinks: s.d.LogForward}, nil
	}
	s.fwd.ApplyFrom(spec.Sinks, o != nil)
	s.fwd.Start(s.baseCtx)
}

// logForwardSpec is the stored list when there is one, else the file's.
func (s *Service) logForwardSpec() (api.LogForwardSpec, *object[api.LogForwardSpec], error) {
	o, err := s.fwdKind.get(logForwardName)
	if err != nil {
		if api.IsCode(err, api.CodeNotFound) {
			return api.LogForwardSpec{Sinks: slices.Clone(s.d.LogForward)}, nil, nil
		}
		return api.LogForwardSpec{}, nil, err
	}
	return o.Spec, &o, nil
}

// requireLogAdmin is the check of every forwarding route: the sink list
// names hosts and files of the host, so it belongs to a global administrator.
func requireLogAdmin(ctx context.Context, what string) error {
	if err := requireGlobal(ctx, what); err != nil {
		return err
	}
	if ActorFrom(ctx).Perm != api.PermAdmin {
		return api.Errorf(api.CodeForbidden, "%s needs the admin role", what)
	}
	return nil
}

// LogForward returns the sink list in force and the state of each sink.
func (s *Service) LogForward(ctx context.Context) (api.LogForward, error) {
	if err := requireLogAdmin(ctx, "reading the log forwarding"); err != nil {
		return api.LogForward{}, err
	}
	return s.logForwardView()
}

func (s *Service) logForwardView() (api.LogForward, error) {
	spec, o, err := s.logForwardSpec()
	if err != nil {
		return api.LogForward{}, err
	}
	if spec.Sinks == nil {
		spec.Sinks = []api.LogSink{}
	}
	out := api.LogForward{Kind: api.KindLogForward, Spec: spec, Status: api.LogForwardStatus{Origin: api.LogForwardFromConfig, Sinks: s.fwd.Status()}}
	if o != nil {
		out.Status.Origin, out.Status.Generation = api.LogForwardFromAPI, o.Meta.Generation
		if !o.Meta.UpdatedAt.IsZero() {
			t := o.Meta.UpdatedAt.UTC()
			out.Status.UpdatedAt = &t
		}
	}
	return out, nil
}

// checkSinkFiles checks the sinks of a list set through the API: their CA and token files lie directly in
// logging.secrets_dir and pass the file check, and a literal destination is not one the dial would refuse
// (loopback, link-local, this daemon's ports).
func (s *Service) checkSinkFiles(spec api.LogForwardSpec) error {
	check := s.fwdCheck
	for _, k := range spec.Sinks {
		if err := s.fwd.Env().CheckAPISink(k); err != nil {
			return err
		}
		for _, f := range []struct {
			path, what string
			secret     bool
		}{{k.CAFile, "ca_file", false}, {k.TokenFile, "token_file", true}} {
			if f.path == "" {
				continue
			}
			if err := check(f.path, f.secret); err != nil {
				hint := "the file must be a regular file owned by root and not writable by others"
				if f.secret {
					hint = "write the token into a file of logging.secrets_dir owned by root, mode 0640 and group jailops (or 0600 when the daemon runs as root); the token never goes into the configuration"
				}
				return api.Errorf(api.CodeInvalid, "sink %q: %s: %v", k.Name, f.what, err).WithHint(hint)
			}
		}
	}
	return nil
}

// SetLogForward stores the sink list, which then replaces the file's.
// expect is the generation read before (0 while the file's list is in force).
func (s *Service) SetLogForward(ctx context.Context, spec api.LogForwardSpec, expect int64) (api.LogForward, error) {
	if err := requireLogAdmin(ctx, "changing the log forwarding"); err != nil {
		return api.LogForward{}, err
	}
	if spec.Sinks == nil {
		spec.Sinks = []api.LogSink{}
	}
	if err := spec.Validate(); err != nil {
		return api.LogForward{}, err
	}
	if err := s.checkSinkFiles(spec); err != nil {
		return api.LogForward{}, err
	}
	s.fwdMu.Lock()
	defer s.fwdMu.Unlock()
	_, o, err := s.logForwardSpec()
	if err != nil {
		return api.LogForward{}, err
	}
	if o == nil {
		if expect > 0 {
			return api.LogForward{}, api.Errorf(api.CodeConflict, "the log forwarding changed: the list of jailopsd.yaml is in force (generation 0)").
				WithHint("read it again and re-apply your change")
		}
		if _, err := s.fwdKind.create(ctx, api.ObjectMeta{Name: logForwardName}, spec); err != nil {
			return api.LogForward{}, err
		}
	} else {
		if expect == 0 {
			return api.LogForward{}, api.Errorf(api.CodeConflict, "the log forwarding changed: a stored list is in force (generation %d)", o.Meta.Generation).
				WithHint("read it again and re-apply your change")
		}
		if _, err := s.fwdKind.update(ctx, logForwardName, expect, nil, nil, spec); err != nil {
			return api.LogForward{}, err
		}
	}
	s.fwd.ApplyFrom(spec.Sinks, true)
	return s.logForwardView()
}

// ResetLogForward deletes the stored list: logging.forward of jailopsd.yaml is in force again.
func (s *Service) ResetLogForward(ctx context.Context) (api.LogForward, error) {
	if err := requireLogAdmin(ctx, "changing the log forwarding"); err != nil {
		return api.LogForward{}, err
	}
	s.fwdMu.Lock()
	defer s.fwdMu.Unlock()
	if _, o, err := s.logForwardSpec(); err != nil {
		return api.LogForward{}, err
	} else if o != nil {
		if err := s.fwdKind.delete(ctx, logForwardName, AnyGeneration); err != nil {
			return api.LogForward{}, err
		}
	}
	s.fwd.Apply(s.d.LogForward)
	return s.logForwardView()
}

// TestLogForward sends one tagged line to a sink of the list in force.
func (s *Service) TestLogForward(ctx context.Context, name string) (api.LogForwardTestResult, error) {
	if err := requireLogAdmin(ctx, "testing the log forwarding"); err != nil {
		return api.LogForwardTestResult{}, err
	}
	spec, o, err := s.logForwardSpec()
	if err != nil {
		return api.LogForwardTestResult{}, err
	}
	for _, k := range spec.Sinks {
		if k.Name == name {
			return s.fwd.Test(ctx, k, o != nil), nil
		}
	}
	return api.LogForwardTestResult{}, api.Errorf(api.CodeNotFound, "sink %q not found", name).WithHint("list them with: jailops logs forward list")
}

// doctorLogForward warns about a sink that has failed for more than five minutes.
func (s *Service) doctorLogForward(c *checkSet) {
	st := s.fwd.Status()
	if len(st) == 0 {
		return
	}
	now := s.now()
	var failing, warned []string
	for _, k := range st {
		if k.FailingSince != nil && now.Sub(*k.FailingSince) > logFailWarn {
			failing = append(failing, fmt.Sprintf("%s (since %s)", k.Name, k.FailingSince.Format(time.RFC3339)))
		}
		if k.Warning != "" {
			warned = append(warned, k.Name+": "+k.Warning)
		}
	}
	switch {
	case len(failing) > 0:
		c.add("logs.forward", api.DoctorWarn, "log forwarding fails: "+strings.Join(failing, "; "),
			"jailops logs forward status shows the last error (global admin); check the receiver and the network, then: jailops logs forward test NAME. Lines are queued meanwhile and the oldest dropped when the queue is full")
	case len(warned) > 0:
		c.add("logs.forward", api.DoctorInfo, strings.Join(warned, "; "), "use a tls:// sink for a receiver that is not on this host")
	default:
		c.add("logs.forward", api.DoctorOK, fmt.Sprintf("%d sink(s) deliver", len(st)), "")
	}
}
