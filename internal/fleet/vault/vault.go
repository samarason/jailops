// Package vault is the SOPS side of a fleet repository: it finds the age key
// SOPS needs, reads and writes SOPS-encrypted YAML (shared/secrets.sops.yaml,
// hosts/<host>/remote.sops.yaml), and edits the .sops.yaml policy that says who
// can decrypt what.
//
// jailops-sync owns no cryptography here. Decryption, encryption and key
// re-wrapping are done by the SOPS library; this package decides which files
// they apply to and checks, before any of it runs, that a key is configured.
//
// The key comes from exactly three of SOPS's own environment variables:
//
//   - SOPS_AGE_KEY: the key text itself.
//   - SOPS_AGE_KEY_FILE: a file with one or more identities. A line may be an
//     age plugin identity (AGE-PLUGIN-<NAME>-1...), which SOPS resolves by
//     running the matching age-plugin-<name> program, so hardware tokens and
//     agents work without any code here.
//   - SOPS_AGE_KEY_CMD: a command whose output is the key (for a secret
//     manager that has no age plugin).
//
// The SOPS library also reads its own default identity file
// ($XDG_CONFIG_HOME or ~/.config)/sops/age/keys.txt when it exists. This
// package deliberately does not count that file as configured: relying on an
// implicit file alone fails here with a clear message, so set
// SOPS_AGE_KEY_FILE explicitly even when it names that same path.
package vault

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Environment variables SOPS reads.
const (
	EnvKey     = "SOPS_AGE_KEY"
	EnvKeyFile = "SOPS_AGE_KEY_FILE"
	EnvKeyCmd  = "SOPS_AGE_KEY_CMD"
)

// Backend says which of the three variables supplies the key.
type Backend struct {
	// Name is the variable, "" when none is set.
	Name string
	// Detail describes it without revealing the key: the file path or the
	// command. Empty for SOPS_AGE_KEY.
	Detail string
	// Plugin is set when the identity file holds an age plugin identity.
	Plugin bool
}

// Resolve reports which backend is configured, in the order SOPS tries them. It
// reads the files but never runs SOPS_AGE_KEY_CMD.
func Resolve(getenv func(string) string) Backend {
	if getenv == nil {
		getenv = os.Getenv
	}
	switch {
	case getenv(EnvKey) != "":
		return Backend{Name: EnvKey}
	case getenv(EnvKeyFile) != "":
		p := getenv(EnvKeyFile)
		b := Backend{Name: EnvKeyFile, Detail: p}
		if raw, err := os.ReadFile(p); err == nil && bytes.Contains(raw, []byte("AGE-PLUGIN-")) {
			b.Plugin = true
		}
		return b
	case getenv(EnvKeyCmd) != "":
		return Backend{Name: EnvKeyCmd, Detail: getenv(EnvKeyCmd)}
	}
	return Backend{}
}

// Describe is a one-line, secret-free description of the backend.
func (b Backend) Describe() string {
	switch b.Name {
	case "":
		return "none configured"
	case EnvKey:
		return EnvKey + " (key text set directly)"
	case EnvKeyFile:
		s := EnvKeyFile + " " + b.Detail
		if b.Plugin {
			s += " (holds an age plugin identity: the matching age-plugin-* program must be on PATH)"
		}
		return s
	}
	return EnvKeyCmd + " " + fmt.Sprintf("%q", b.Detail)
}

// ErrNoKey explains how to configure a key.
func ErrNoKey() error {
	return fmt.Errorf("no age key is configured for SOPS. Set one of:\n"+
		"  %s       the key text\n"+
		"  %s  a file with an age identity or an age plugin identity\n"+
		"  %s   a command that prints the key", EnvKey, EnvKeyFile, EnvKeyCmd)
}

// EnsureUnlocked fails early, with a clear message, when no key is configured
// or the configured one cannot be read. It checks the file of SOPS_AGE_KEY_FILE
// and runs SOPS_AGE_KEY_CMD once to see that it prints something.
func EnsureUnlocked(getenv func(string) string) error {
	b := Resolve(getenv)
	switch b.Name {
	case "":
		return ErrNoKey()
	case EnvKeyFile:
		if _, err := os.Stat(b.Detail); err != nil {
			return fmt.Errorf("%s=%s: %w", EnvKeyFile, b.Detail, err)
		}
	case EnvKeyCmd:
		ctx, cancel := context.WithTimeout(context.Background(), keyCmdTimeout)
		defer cancel()
		c := exec.CommandContext(ctx, "sh", "-c", b.Detail)
		c.WaitDelay = time.Second
		c.Env = append(os.Environ(), "SOPS_AGE_KEY_RECIPIENT=")
		out, err := c.Output()
		if err != nil {
			return fmt.Errorf("%s command failed: %w", EnvKeyCmd, err)
		}
		if len(strings.TrimSpace(string(out))) == 0 {
			return fmt.Errorf("%s command printed nothing", EnvKeyCmd)
		}
	}
	return nil
}

// keyCmdTimeout bounds the command that prints the key (SOPS_AGE_KEY_CMD).
const keyCmdTimeout = 30 * time.Second
