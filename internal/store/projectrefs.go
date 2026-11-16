package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
)

// ProjectRefs are the identities whose project list names a project, by table: what a project rename rewrites.
type ProjectRefs struct {
	Users       []string `json:"users,omitempty"`
	Tokens      []string `json:"tokens,omitempty"`
	TrustTokens []string `json:"trust_tokens,omitempty"`
}

// Count is the number of identities.
func (r ProjectRefs) Count() int { return len(r.Users) + len(r.Tokens) + len(r.TrustTokens) }

var projectTables = []struct {
	table string
	ids   func(*ProjectRefs) *[]string
}{
	{"users", func(r *ProjectRefs) *[]string { return &r.Users }},
	{"tokens", func(r *ProjectRefs) *[]string { return &r.Tokens }},
	{"trust_tokens", func(r *ProjectRefs) *[]string { return &r.TrustTokens }},
}

// FindProjectRefs lists the users, tokens and trust tokens whose projects name project.
func (s *Store) FindProjectRefs(ctx context.Context, project string) (ProjectRefs, error) {
	var out ProjectRefs
	for _, t := range projectTables {
		rows, err := s.r.QueryContext(ctx, "SELECT id, projects FROM "+t.table)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var id, projs string
			if err := rows.Scan(&id, &projs); err != nil {
				rows.Close()
				return out, err
			}
			var l []string
			if json.Unmarshal([]byte(projs), &l) == nil && slices.Contains(l, project) {
				*t.ids(&out) = append(*t.ids(&out), id)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// ReplaceProject replaces from with to in the project lists of the identities refs names, in one transaction. An
// identity whose list no longer names from is left as it is, so the call can be repeated.
func (s *Store) ReplaceProject(ctx context.Context, refs ProjectRefs, from, to string) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		for _, t := range projectTables {
			for _, id := range *t.ids(&refs) {
				var projs string
				err := tx.QueryRowContext(ctx, "SELECT projects FROM "+t.table+" WHERE id = ?", id).Scan(&projs)
				if err == sql.ErrNoRows {
					continue // deleted since
				}
				if err != nil {
					return err
				}
				var l []string
				if err := json.Unmarshal([]byte(projs), &l); err != nil {
					return err
				}
				if !slices.Contains(l, from) {
					continue
				}
				for i := range l {
					if l[i] == from {
						l[i] = to
					}
				}
				b, _ := json.Marshal(l)
				if _, err := tx.ExecContext(ctx, "UPDATE "+t.table+" SET projects = ? WHERE id = ?", string(b), id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
