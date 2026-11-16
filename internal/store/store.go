// Package store is the SQLite operational store: users, token hashes,
// sessions, operations, events, the audit log and a key/value meta table.
// It holds nothing required to restore a jail (design section 7).
//
// There is one write connection and a pool of read connections, WAL mode,
// and forward-only embedded migrations. A database whose schema is newer than
// this binary is refused.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
	_ "modernc.org/sqlite" // driver "sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Options configures Open.
type Options struct {
	// Now supplies the clock; tests inject a fake. Default time.Now.
	Now func() time.Time
	// Readers is the size of the read pool. Default 4.
	Readers int
	// EventMaxRows and EventMaxAge bound the event ring. Defaults 10000 and 7 days.
	EventMaxRows int
	EventMaxAge  time.Duration
}

// Store is the operational database.
type Store struct {
	path string
	w    *sql.DB // exactly one connection
	r    *sql.DB // read pool, query_only
	now  func() time.Time

	eventMaxRows int
	eventMaxAge  time.Duration
	eventCount   int

	Users       *Users
	Tokens      *Tokens
	Sessions    *Sessions
	Operations  *Operations
	Events      *Events
	Audit       *Audit
	TrustTokens *TrustTokens
	Meta        *Meta
}

// SchemaVersion is the schema version this binary understands.
func SchemaVersion() int {
	ms, _ := loadMigrations()
	if len(ms) == 0 {
		return 0
	}
	return ms[len(ms)-1].version
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	ents, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range ents {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		if !ok || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("bad migration file name %q", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("bad migration number in %q", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: name, sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migrations are not contiguous at %s", m.name)
		}
	}
	return ms, nil
}

func dsn(path, extra string) string {
	q := "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" + extra
	return "file:" + filepath.ToSlash(path) + "?" + q
}

// Open opens or creates the database at path and migrates it.
func Open(path string, opts Options) (*Store, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Readers <= 0 {
		opts.Readers = 4
	}
	if opts.EventMaxRows <= 0 {
		opts.EventMaxRows = 10000
	}
	if opts.EventMaxAge <= 0 {
		opts.EventMaxAge = 7 * 24 * time.Hour
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	w, err := sql.Open("sqlite", dsn(path, "&_txlock=immediate"))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	s := &Store{path: path, w: w, now: opts.Now, eventMaxRows: opts.EventMaxRows, eventMaxAge: opts.EventMaxAge}
	ctx := context.Background()
	if err := s.migrate(ctx); err != nil {
		w.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	r, err := sql.Open("sqlite", dsn(path, "&_pragma=query_only(1)"))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(opts.Readers)
	r.SetMaxIdleConns(opts.Readers)
	s.r = r
	s.Users = &Users{s}
	s.Tokens = &Tokens{s}
	s.Sessions = &Sessions{s}
	s.Operations = &Operations{s}
	s.Events = &Events{s}
	s.Audit = &Audit{s}
	s.TrustTokens = &TrustTokens{s}
	s.Meta = &Meta{s}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	var cur int
	if err := s.w.QueryRowContext(ctx, "PRAGMA user_version").Scan(&cur); err != nil {
		return err
	}
	if cur > len(ms) {
		return api.Errorf(api.CodeVersionSkew, "database schema version %d is newer than this binary supports (%d)", cur, len(ms)).
			WithHint("upgrade jailopsd; the database is not modified")
	}
	for _, m := range ms[cur:] {
		err := s.write(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
	}
	return nil
}

// Version returns the schema version of the open database.
func (s *Store) Version(ctx context.Context) (int, error) {
	var v int
	err := s.r.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

// Close closes both pools, checkpointing the WAL.
func (s *Store) Close() error {
	_, _ = s.w.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	e1 := s.r.Close()
	e2 := s.w.Close()
	return errors.Join(e1, e2)
}

// write runs fn in an immediate transaction on the single write connection.
func (s *Store) write(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// IntegrityCheck runs PRAGMA integrity_check and foreign_key_check and returns
// the problems found; an empty slice means the database is healthy.
func (s *Store) IntegrityCheck(ctx context.Context) ([]string, error) {
	var problems []string
	rows, err := s.r.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			return nil, err
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	fk, err := s.r.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return nil, err
	}
	defer fk.Close()
	for fk.Next() {
		var table, parent string
		var rowid, id sql.NullInt64
		if err := fk.Scan(&table, &rowid, &parent, &id); err != nil {
			return nil, err
		}
		problems = append(problems, fmt.Sprintf("foreign key violation in %s (row %d) referencing %s", table, rowid.Int64, parent))
	}
	return problems, fk.Err()
}

// VacuumInto writes a consistent compacted copy of the database to path,
// which must not exist. The copy has mode 0600.
func (s *Store) VacuumInto(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return api.Errorf(api.CodeAlreadyExists, "backup target %s already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// Run on a connection of its own that only reads the database: in WAL mode a reader sees a consistent snapshot
	// while the writer goes on, so the copy of a large database does not hold up every write of the daemon (on the
	// writer it took about 7 ms per MiB of database). The readers of the pool are query_only, which SQLite does not
	// allow VACUUM INTO on, and the writer is the connection that must stay free.
	c, err := sql.Open("sqlite", dsn(s.path, ""))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetMaxOpenConns(1)
	if _, err := c.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		os.Remove(path)
		return err
	}
	return os.Chmod(path, 0o600)
}

// OpenReadOnlyCheck opens a database file (for example a VacuumInto copy),
// runs the integrity check and reports its schema version.
func OpenReadOnlyCheck(ctx context.Context, path string) (version int, problems []string, err error) {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return 0, nil, err
	}
	defer db.Close()
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, nil, err
	}
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return version, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return version, nil, err
		}
		if l != "ok" {
			problems = append(problems, l)
		}
	}
	return version, problems, rows.Err()
}

// ---- helpers shared by repositories ----

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMicro()
}

func fromTS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMicro(v).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// mapErr converts driver errors into api errors.
func mapErr(err error, what string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return api.Errorf(api.CodeNotFound, "%s not found", what)
	}
	var coder interface{ Code() int }
	if errors.As(err, &coder) {
		switch coder.Code() {
		case 2067, 1555: // SQLITE_CONSTRAINT_UNIQUE, _PRIMARYKEY
			return api.Errorf(api.CodeAlreadyExists, "%s already exists", what)
		}
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return api.Errorf(api.CodeAlreadyExists, "%s already exists", what)
	}
	return err
}
