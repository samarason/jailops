package service

import (
	"context"
	"time"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// SetRenameCrash makes the next renames stop at step n as if the daemon died there (0 never).
func SetRenameCrash(s *Service, n int) { s.renameCrashAt = n }

// SetPolicyRaw stores the spec of a firewall policy as it is, without the validation of the API: what a policy that was
// stored without its defaults looks like.
func SetPolicyRaw(s *Service, project, name string, spec api.FirewallPolicySpec) error {
	_, err := s.polKind.p(project).update(context.Background(), name, AnyGeneration, nil, nil, spec)
	return err
}

// RenderJail renders the anchor of a jail the way the reconcile loop and the start hooks do.
func RenderJail(s *Service, project, name string) error {
	key, err := validate.QualifiedName(project, name)
	if err != nil {
		return err
	}
	j, err := s.jailSnapshot(key)
	if err != nil {
		return err
	}
	refs, err := s.allRefs(project)
	if err != nil {
		return err
	}
	_, err = s.buildJail(context.Background(), j, refs)
	return err
}

// SetManagedPolicy stores a firewall policy that something else manages, as app access does for app-JAIL.
func SetManagedPolicy(s *Service, project, name, managedBy string, spec api.FirewallPolicySpec) error {
	_, err := s.polKind.p(project).create(context.Background(), api.ObjectMeta{Name: name, ManagedBy: managedBy}, spec)
	return err
}

// SeedJailopsRepo runs the copy of the JailOps repository's configuration into a jail root, from the host directory dir.
func SeedJailopsRepo(s *Service, ctx context.Context, dir, root string) error {
	old := hostPkgDir
	hostPkgDir = dir
	defer func() { hostPkgDir = old }()
	return s.seedJailopsRepo(ctx, root)
}

// SetShellSetupDeadline shortens the deadline of the setup after a start; the returned function puts it back.
func SetShellSetupDeadline(d time.Duration) func() {
	old := shellSetupDeadline
	shellSetupDeadline = d
	return func() { shellSetupDeadline = old }
}

func SetBashBeforeStartDeadline(d time.Duration) func() {
	old := bashBeforeStartDeadline
	bashBeforeStartDeadline = d
	return func() { bashBeforeStartDeadline = old }
}

// SetHostDirTimeouts shortens how long a read and a probe wait for a host directory that does not answer, and returns
// what puts them back.
func SetHostDirTimeouts(read, probe time.Duration) func() {
	r, p := hostDirReadTimeout.Load(), hostDirProbeTimeout.Load()
	hostDirReadTimeout.Store(int64(read))
	hostDirProbeTimeout.Store(int64(probe))
	return func() { hostDirReadTimeout.Store(r); hostDirProbeTimeout.Store(p) }
}

// SetShellRetryAfter changes how long a failed setup of bash waits before a start tries it again; the returned
// function puts it back.
func SetShellRetryAfter(d time.Duration) func() {
	old := shellRetryAfter
	shellRetryAfter = d
	return func() { shellRetryAfter = old }
}
