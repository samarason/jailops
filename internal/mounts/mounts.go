// Package mounts holds the plain types of the mounts that a stop which did not finish leaves below the root of a jail.
package mounts

// Stale is one mount of a kind JailOps makes (devfs, nullfs, ...) below the root of a jail that does not run.
type Stale struct{ Jail, Path, Type string }

// Healed says what a cleanup of the mounts of one jail took off and what it could not.
type Healed struct{ Unmounted, Left, Errors []string }

// NetHealed says which interfaces of the earlier network layout were destroyed and which were left, with the reason.
type NetHealed struct{ Destroyed, Skipped []string }

// UnboundState says where the names of the jails stand for the host's unbound (the helper's dns.unbound).
type UnboundState struct {
	Enabled, Current, Changed, Reloaded, Base, Recurse bool
	Path, Control, Sample, Reason, Suffix              string
	Names, Jails, Projects                             int
	Gateways, Forward                                  []string
}
