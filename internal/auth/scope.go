package auth

import (
	"slices"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Scope is the project scope of an identity. An empty Projects list with
// Global false means no access at all, never "everything".
type Scope struct {
	Projects []string
	Global   bool
}

// Has reports whether the scope grants anything.
func (s Scope) Has() bool { return s.Global || len(s.Projects) > 0 }

// Allows reports whether the scope covers project.
func (s Scope) Allows(project string) bool {
	return s.Global || slices.Contains(s.Projects, project)
}

// Normalize trims, deduplicates and sorts the project list and validates each
// name. Global together with projects is kept as Global with the list.
func (s Scope) Normalize() (Scope, error) {
	var out []string
	for _, p := range s.Projects {
		p = strings.TrimSpace(p)
		if !api.IsName(p, api.MaxName) {
			return Scope{}, api.Errorf(api.CodeInvalid, "invalid project name %q", p)
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return Scope{Projects: slices.Compact(out), Global: s.Global}, nil
}

// Validate refuses a scope that grants nothing.
func (s Scope) Validate() error {
	if !s.Has() {
		return api.Errorf(api.CodeInvalid, "an identity needs a non-empty projects list or global: true; an empty list never means all projects")
	}
	return nil
}
