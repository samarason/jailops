// Package ctl is the PostgreSQL control plane of the backup node: hosts and
// their pinned certificates, group ownership, session leases, the snapshot
// index with its verify, protection and deletion state, jobs, policies,
// maintenance mode, users, tokens, UI sessions and the audit log.
//
// The repository stays the source of truth for payloads and for the relations
// between groups, snapshots and chunks. Everything here about groups and
// snapshots can be dropped and rebuilt from the repository (reconcile);
// users, tokens, enrolments, policies and the audit log cannot.
package ctl

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// DB is the control plane connection pool.
type DB struct {
	pool  *pgxpool.Pool
	clock func() time.Time // the time of the leases of sessions; nil is the wall clock
}

// SetClock makes the leases of sessions run on f (the clock of the node: a test moves it by hand). It is called once,
// before the DB is used.
func (d *DB) SetClock(f func() time.Time) { d.clock = f }

func (d *DB) now() time.Time {
	if d.clock != nil {
		return d.clock().UTC()
	}
	return time.Now().UTC()
}

// Open connects and pings. dsn is a PostgreSQL connection URL or key/value string.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("ctl: the database DSN is malformed") // never echo it: it may hold a password
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("ctl: connecting to PostgreSQL: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ctl: PostgreSQL is not reachable: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close closes the pool.
func (d *DB) Close() { d.pool.Close() }

// Pool returns the pool, for the few callers that run their own queries.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("ctl: not found")

// ErrConflict is returned when a uniqueness rule refuses a write.
var ErrConflict = errors.New("ctl: conflict")

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// migrationLock serialises two processes migrating at once (a CLI command next to the daemon).
const migrationLock = 0x6a62_6261_636b_7570

// Migrate applies every pending embedded migration, in file name order, each
// in its own transaction together with its version row. Migrations are
// forward only. It refuses to run against a database that a newer release
// migrated.
func (d *DB) Migrate(ctx context.Context) error {
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(migrationLock)); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, int64(migrationLock))
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("ctl: creating the version table: %w", err)
	}
	known, err := migrationNames()
	if err != nil {
		return err
	}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	applied := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for v := range applied {
		if !slicesContains(known, v) {
			return fmt.Errorf("ctl: the database was migrated by a newer release (unknown migration %s); upgrade jailops-backupd instead of running this older binary", v)
		}
	}
	for _, name := range known {
		if applied[name] {
			continue
		}
		sql, err := fs.ReadFile(migrationFiles, path.Join("migrations", name))
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("ctl: applying %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("ctl: committing %s: %w", name, err)
		}
	}
	return nil
}

func migrationNames() ([]string, error) {
	ents, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// SchemaVersion is the newest migration this binary knows.
func SchemaVersion() string {
	n, _ := migrationNames()
	if len(n) == 0 {
		return ""
	}
	return strings.TrimSuffix(n[len(n)-1], ".sql")
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// What a lost database costs. RebuiltTables are rebuilt from the repository by
// reconcile (including group ownership, from the owner markers). The tables of
// NotRecoverableTable hold what the repository cannot: people, credentials,
// enrolments, policies and the audit log; they are backed up separately
// (pg_dump). OperationalTables are transient or history: sessions (leases die
// with the process anyway), job history, settings (maintenance mode; the node
// comes back online), browser sessions.
var (
	RebuiltTables       = []string{"groups", "snapshots"}
	NotRecoverableTable = []string{"users", "tokens", "hosts", "retention_policies", "audit"}
	OperationalTables   = []string{"sessions", "jobs", "settings", "ui_sessions", "schema_migrations"}
)
