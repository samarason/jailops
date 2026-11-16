// Package state is the file-backed object store for host configuration and
// fleet objects (design section 7).
//
// Objects live in <dir>/objects/<kind>/<uuid>.json wrapped in the
// api.Document envelope. All mutations go through Store.Apply with a
// deterministic Command, so a later Raft committer can replace the direct
// one without a rewrite.
package state

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"jailops.net/jailops/sdk/api"
)

// CommandVersion is the current wire version of Command.
const CommandVersion = 1

// Op is the operation of a Command.
type Op string

// Command operations.
const (
	OpPut    Op = "put"
	OpDelete Op = "delete"
)

// AnyGeneration in Command.ExpectGeneration disables the compare-and-swap check.
const AnyGeneration int64 = -1

// Command is a versioned, JSON-serialisable state change. The proposer
// supplies ID, Time and UUID so that applying it is deterministic and
// identical on every replica.
//
// Put semantics:
//   - ExpectGeneration 0: create only; AlreadyExists if the object exists.
//   - ExpectGeneration N>0: update; Conflict unless the stored generation is N.
//   - AnyGeneration: create or update unconditionally.
//
// The object is addressed by UUID; if UUID is empty the (Kind, Scope, Name)
// index is consulted, and creating requires the proposer to supply a UUID.
// A put with a different Name than the stored one is a rename. The project of a stored object changes only with
// MoveProject (a project rename moves the objects of the project to its new name).
//
// Delete semantics: ExpectGeneration 0 or AnyGeneration delete unconditionally,
// N>0 requires a matching generation.
type Command struct {
	Version          int               `json:"version"`
	ID               string            `json:"id"`
	Time             time.Time         `json:"time"`
	Op               Op                `json:"op"`
	Kind             api.Kind          `json:"kind"`
	UUID             string            `json:"uuid,omitempty"`
	Name             string            `json:"name,omitempty"`
	Scope            api.Scope         `json:"scope,omitempty"`
	Project          string            `json:"project,omitempty"`
	Host             string            `json:"host,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	ManagedBy        string            `json:"managed_by,omitempty"`
	Spec             json.RawMessage   `json:"spec,omitempty"`
	ExpectGeneration int64             `json:"expect_generation"`
	// MoveProject lets a put addressed by UUID give the object another project.
	MoveProject bool `json:"move_project,omitempty"`
}

// Result is the outcome of an applied Command.
type Result struct {
	CommandID string
	// Object is the stored object after a put, or the deleted object after a delete.
	Object  *Object
	Created bool
	Deleted bool
}

// Object is a stored document. It marshals to the api.Document envelope.
type Object struct {
	APIVersion string          `json:"apiVersion"`
	Kind       api.Kind        `json:"kind"`
	Metadata   api.ObjectMeta  `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
}

// Document converts the object to the api envelope. Spec stays raw JSON.
func (o *Object) Document() api.Document {
	return api.Document{APIVersion: o.APIVersion, Kind: o.Kind, Metadata: o.Metadata, Spec: o.Spec}
}

func (o *Object) clone() *Object {
	c := *o
	c.Spec = append(json.RawMessage(nil), o.Spec...)
	if o.Metadata.Labels != nil {
		c.Metadata.Labels = make(map[string]string, len(o.Metadata.Labels))
		for k, v := range o.Metadata.Labels {
			c.Metadata.Labels[k] = v
		}
	}
	return &c
}

var (
	kindRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,63}$`)
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F][0-9a-fA-F-]{7,63}$`)
)

func validName(n string) error {
	if n == "" || len(n) > 253 {
		return api.Errorf(api.CodeInvalid, "name must be 1 to 253 characters")
	}
	if strings.ContainsRune(n, '/') {
		return api.Errorf(api.CodeInvalid, "name %q must not contain '/'", n)
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return api.Errorf(api.CodeInvalid, "name contains a control character")
		}
	}
	return nil
}

// Validate checks the command independent of store contents.
func (c *Command) Validate() error {
	if c.Version != CommandVersion {
		return api.Errorf(api.CodeVersionSkew, "command version %d not supported (want %d)", c.Version, CommandVersion)
	}
	if c.Op != OpPut && c.Op != OpDelete {
		return api.Errorf(api.CodeInvalid, "unknown command op %q", c.Op)
	}
	if !kindRe.MatchString(string(c.Kind)) {
		return api.Errorf(api.CodeInvalid, "invalid kind %q", c.Kind)
	}
	if c.UUID != "" && !uuidRe.MatchString(c.UUID) {
		return api.Errorf(api.CodeInvalid, "invalid uuid %q", c.UUID)
	}
	if c.ID == "" {
		return api.Errorf(api.CodeInvalid, "command id is required")
	}
	if c.Time.IsZero() {
		return api.Errorf(api.CodeInvalid, "command time is required")
	}
	if c.Op == OpPut {
		if err := validName(c.Name); err != nil {
			return err
		}
		if len(c.Spec) == 0 || !json.Valid(c.Spec) {
			return api.Errorf(api.CodeInvalid, "spec must be valid JSON")
		}
	} else if c.UUID == "" && c.Name == "" {
		return api.Errorf(api.CodeInvalid, "delete needs a uuid or a name")
	}
	return nil
}

// Marshal encodes the command.
func (c Command) Marshal() ([]byte, error) { return json.Marshal(c) }

// UnmarshalCommand decodes and validates a command.
func UnmarshalCommand(b []byte) (Command, error) {
	var c Command
	if err := json.Unmarshal(b, &c); err != nil {
		return c, api.Errorf(api.CodeInvalid, "decode command: %v", err)
	}
	return c, c.Validate()
}

func (c *Command) String() string {
	return fmt.Sprintf("%s %s/%s(%s)", c.Op, c.Kind, c.Name, c.UUID)
}
