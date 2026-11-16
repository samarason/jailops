package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// User is a local human account. PasswordHash is a PHC-style argon2id string
// and TOTPSealed is the TOTP secret encrypted by internal/auth; neither is
// ever returned by the API.
type User struct {
	ID             string
	Name           string
	PasswordHash   string
	Permission     api.Permission
	TOTPSealed     []byte
	TOTPEnabled    bool
	RecoveryHashes []string
	Disabled       bool
	Projects       []string
	Global         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastLoginAt    time.Time
}

// Users is the user repository.
type Users struct{ s *Store }

const userCols = "id, name, password_hash, permission, totp_sealed, totp_enabled, recovery_hashes, disabled, created_at, updated_at, last_login_at, projects, global"

type scanner interface{ Scan(dest ...any) error }

func scanUser(r scanner) (*User, error) {
	var u User
	var perm, rec string
	var totpEn, dis, glob int
	var c, up, ll int64
	var projs string
	if err := r.Scan(&u.ID, &u.Name, &u.PasswordHash, &perm, &u.TOTPSealed, &totpEn, &rec, &dis, &c, &up, &ll, &projs, &glob); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(projs), &u.Projects); err != nil {
		return nil, err
	}
	u.Global = glob != 0
	u.Permission = api.Permission(perm)
	u.TOTPEnabled, u.Disabled = totpEn != 0, dis != 0
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = fromTS(c), fromTS(up), fromTS(ll)
	if err := json.Unmarshal([]byte(rec), &u.RecoveryHashes); err != nil {
		return nil, err
	}
	return &u, nil
}

// Create inserts a user. The name is unique case-insensitively.
func (r *Users) Create(ctx context.Context, u User) error {
	if u.ID == "" || u.Name == "" || u.PasswordHash == "" || u.Permission == "" {
		return api.Errorf(api.CodeInvalid, "user needs id, name, password hash and permission")
	}
	now := r.s.now()
	rec, _ := json.Marshal(nonNil(u.RecoveryHashes))
	projs, _ := json.Marshal(nonNil(u.Projects))
	return mapErr(r.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			u.ID, u.Name, u.PasswordHash, string(u.Permission), u.TOTPSealed, b2i(u.TOTPEnabled), string(rec), b2i(u.Disabled), ts(now), ts(now), 0,
			string(projs), b2i(u.Global))
		return err
	}), "user "+u.Name)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// GetByName finds a user by case-insensitive name.
func (r *Users) GetByName(ctx context.Context, name string) (*User, error) {
	u, err := scanUser(r.s.r.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE name = ?", name))
	if err != nil {
		return nil, mapErr(err, "user "+name)
	}
	return u, nil
}

// GetByID finds a user by id.
func (r *Users) GetByID(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(r.s.r.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id))
	if err != nil {
		return nil, mapErr(err, "user "+id)
	}
	return u, nil
}

// List returns all users ordered by name.
func (r *Users) List(ctx context.Context) ([]*User, error) {
	rows, err := r.s.r.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *Users) update(ctx context.Context, id, set string, args ...any) error {
	args = append(append([]any{}, args...), ts(r.s.now()), id)
	return r.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE users SET "+set+", updated_at = ? WHERE id = ?", args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return api.Errorf(api.CodeNotFound, "user %s not found", id)
		}
		return nil
	})
}

// SetName gives the user a new name; the id, the password, the sessions and the second factor stay.
func (r *Users) SetName(ctx context.Context, id, name string) error {
	err := r.update(ctx, id, "name = ?", name)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return api.Errorf(api.CodeAlreadyExists, "user %q already exists", name)
	}
	return err
}

// SetPasswordHash replaces the password hash and revokes the user's sessions.
func (r *Users) SetPasswordHash(ctx context.Context, id, hash string) error {
	if hash == "" {
		return api.Errorf(api.CodeInvalid, "empty password hash")
	}
	if err := r.update(ctx, id, "password_hash = ?", hash); err != nil {
		return err
	}
	return r.s.Sessions.DeleteForUser(ctx, id)
}

// SetPermission changes the role.
func (r *Users) SetPermission(ctx context.Context, id string, p api.Permission) error {
	return r.update(ctx, id, "permission = ?", string(p))
}

// SetDisabled disables or enables a user; disabling revokes sessions.
func (r *Users) SetDisabled(ctx context.Context, id string, disabled bool) error {
	if err := r.update(ctx, id, "disabled = ?", b2i(disabled)); err != nil {
		return err
	}
	if disabled {
		return r.s.Sessions.DeleteForUser(ctx, id)
	}
	return nil
}

// SetTOTP stores the sealed TOTP secret and whether it is enforced. A nil
// sealed secret with enabled=false removes TOTP.
func (r *Users) SetTOTP(ctx context.Context, id string, sealed []byte, enabled bool) error {
	return r.update(ctx, id, "totp_sealed = ?, totp_enabled = ?", sealed, b2i(enabled))
}

// SetRecoveryHashes replaces the recovery code hashes.
func (r *Users) SetRecoveryHashes(ctx context.Context, id string, hashes []string) error {
	b, _ := json.Marshal(nonNil(hashes))
	return r.update(ctx, id, "recovery_hashes = ?", string(b))
}

// ConsumeRecoveryHash atomically removes one recovery hash. It reports whether
// the hash was present, so a code can be used once.
func (r *Users) ConsumeRecoveryHash(ctx context.Context, id, hash string) (bool, error) {
	found := false
	err := r.s.write(ctx, func(tx *sql.Tx) error {
		var rec string
		if err := tx.QueryRowContext(ctx, "SELECT recovery_hashes FROM users WHERE id = ?", id).Scan(&rec); err != nil {
			return mapErr(err, "user "+id)
		}
		var hs []string
		if err := json.Unmarshal([]byte(rec), &hs); err != nil {
			return err
		}
		i := slices.Index(hs, hash)
		if i < 0 {
			return nil
		}
		found = true
		hs = slices.Delete(hs, i, i+1)
		b, _ := json.Marshal(nonNil(hs))
		_, err := tx.ExecContext(ctx, "UPDATE users SET recovery_hashes = ?, updated_at = ? WHERE id = ?", string(b), ts(r.s.now()), id)
		return err
	})
	return found && err == nil, err
}

// TouchLogin records a successful login.
func (r *Users) TouchLogin(ctx context.Context, id string) error {
	return r.s.write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", ts(r.s.now()), id)
		return err
	})
}

// Delete removes a user and, by cascade, their sessions.
func (r *Users) Delete(ctx context.Context, id string) error {
	return r.s.write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return api.Errorf(api.CodeNotFound, "user %s not found", id)
		}
		return nil
	})
}

// SetScope replaces the project scope of a user.
func (r *Users) SetScope(ctx context.Context, id string, projects []string, global bool) error {
	b, _ := json.Marshal(nonNil(projects))
	return r.update(ctx, id, "projects = ?, global = ?", string(b), b2i(global))
}
