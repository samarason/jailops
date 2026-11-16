// Package jailos controls and observes FreeBSD jails: jail(8) for start and
// stop, jexec(8) for commands inside, and jls(8) for the running state.
package jailos

import (
	"context"
	"io"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

// Jail is the observed state of one running (or dying) jail.
type Jail struct {
	JID      int
	Name     string
	Path     string
	Hostname string
	VNet     bool
	Dying    bool
	// Params holds every other parameter the source reported.
	Params map[string]string
}

// ExecOpts for Controller.Exec.
type ExecOpts struct {
	// Argv is the command and its arguments; Argv[0] must not start with '-'.
	Argv []string
	// User runs the command as this user inside the jail (jexec -U).
	User string
	// Login uses the user's login class environment (jexec -l).
	Login bool
	Stdin io.Reader
	// Stdout, when set, streams the output instead of capturing it.
	Stdout io.Writer
	// Timeout of zero means run.DefaultTimeout.
	Timeout time.Duration
}

// Observer reads the running state.
type Observer interface {
	// List returns all running jails, ordered by JID.
	List(ctx context.Context) ([]Jail, error)
	// Get returns the running jail with this name; the bool is false when
	// no such jail runs.
	Get(ctx context.Context, name string) (Jail, bool, error)
}

// Controller starts, stops and enters jails.
type Controller interface {
	// Create runs `jail -f conf -c name`.
	Create(ctx context.Context, confPath, name string) error
	// Remove runs `jail -f conf -r name`.
	Remove(ctx context.Context, confPath, name string) error
	// Exec runs a command in the jail.
	Exec(ctx context.Context, name string, o ExecOpts) (run.Result, error)
}

// Jails is the full interface.
type Jails interface {
	Observer
	Controller
}

// ValidateName accepts jail names: letters, digits, '_' and '-', not
// starting with '-', at most 64 bytes. Dots are rejected because jail(8)
// treats them as hierarchy separators.
func ValidateName(name string) error {
	if name == "" || len(name) > 64 || name[0] == '-' {
		return api.Errorf(api.CodeInvalid, "invalid jail name %q", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return api.Errorf(api.CodeInvalid, "invalid jail name %q", name)
		}
	}
	return nil
}

func validateConf(path string) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\n") || len(path) > 4096 {
		return api.Errorf(api.CodeInvalid, "jail configuration path must be absolute: %q", path)
	}
	return nil
}

func validateUser(u string) error {
	if u == "" {
		return nil
	}
	if len(u) > 64 || u[0] == '-' {
		return api.Errorf(api.CodeInvalid, "invalid user %q", u)
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return api.Errorf(api.CodeInvalid, "invalid user %q", u)
		}
	}
	return nil
}
