// Package backupd is the backup node daemon: configuration, the datastore and
// control plane it opens, the HTTPS listener for backup hosts (mutual TLS, pinned
// fingerprints), the separate local administration socket, the management API
// and web UI, and the scheduler. The service logic is internal/node.
package backupd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/schedule"
	"jailops.net/jailops/sdk/api"
)

// DefaultConfigPath is where the daemon reads its configuration.
const DefaultConfigPath = "/usr/local/etc/jailops/backupd.yaml"

// Config is the configuration file. It is decoded strictly: an unknown key is an error.
type Config struct {
	// ServerID names this node in owner.json. Empty means an id generated once and kept in the database.
	// Set it when the database might be lost: a node that comes back with another id is refused by owner.json.
	ServerID string `yaml:"server_id"`
	Hostname string `yaml:"hostname"`

	// Listen is the address of the host listener (mutual TLS). Default ":39111".
	Listen string `yaml:"listen"`
	// AdminSocket is the unix socket of the administration API. Default /var/run/jailops-backupd.sock.
	AdminSocket string `yaml:"admin_socket"`
	// TLS is the node's server certificate; init generates a self-signed one when the files are missing.
	TLS TLSConfig `yaml:"tls"`
	// Database is the PostgreSQL control plane.
	Database DatabaseConfig `yaml:"database"`
	// Datastore is where the repository lives.
	Datastore DatastoreConfig `yaml:"datastore"`
	// Hosts are trusted backup hosts configured statically; the ones enrolled with `hosts enroll` live in the database.
	Hosts []HostConfig `yaml:"hosts"`
	// Web is the listener of the management API and the web UI.
	Web WebConfig `yaml:"web"`

	// Grace is the garbage collection grace period (default 24h, minimum 12h).
	Grace Duration `yaml:"grace"`
	// Lease is the session lease (default 15m).
	Lease Duration `yaml:"lease"`
	// DeletionDelay is the default delay of a deletion request (default 72h).
	DeletionDelay Duration `yaml:"deletion_delay"`
	// Retention is the default policy for groups without their own.
	Retention RetentionConfig `yaml:"retention"`
	// Schedule says when the node runs its jobs (five-field cron expressions).
	Schedule ScheduleConfig `yaml:"schedule"`
}

// TLSConfig points at the server certificate and key.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// DatabaseConfig is the PostgreSQL connection. Put the password in DSNFile
// (readable by root only), not in this file.
type DatabaseConfig struct {
	DSN     string `yaml:"dsn"`
	DSNFile string `yaml:"dsn_file"`
}

// DatastoreConfig selects the backend.
type DatastoreConfig struct {
	// Kind is "directory" or "s3".
	Kind      string `yaml:"kind"`
	Directory string `yaml:"directory"`
	S3        S3     `yaml:"s3"`
}

// S3 is an S3-compatible bucket.
type S3 struct {
	Endpoint string `yaml:"endpoint"`
	Region   string `yaml:"region"`
	Bucket   string `yaml:"bucket"`
	Prefix   string `yaml:"prefix"`
	// CredentialsFile holds access_key=... and secret_key=... lines; it must be readable by its owner only.
	CredentialsFile string `yaml:"credentials_file"`
	PathStyle       bool   `yaml:"path_style"`
	NoTLS           bool   `yaml:"no_tls"`
	CAFile          string `yaml:"ca_file"`
}

// HostConfig is a statically configured backup host.
type HostConfig struct {
	Name        string   `yaml:"name"`
	Fingerprint string   `yaml:"fingerprint"`
	Scopes      []string `yaml:"scopes"`
}

// WebConfig switches the web console, and nothing else. The console is served on the host listener (Config.Listen), next to
// the host API and the management API that is always there: one port, 39111 by default. It is in the binary and off by
// default.
type WebConfig struct {
	Enabled bool `yaml:"enabled"`
	// Listen was the address of a second listener. It is gone; setting it is an error that says so.
	Listen string `yaml:"listen"`
}

// RetentionConfig mirrors api.RetentionPolicy.
type RetentionConfig struct {
	Last     int    `yaml:"last"`
	Hourly   int    `yaml:"hourly"`
	Daily    int    `yaml:"daily"`
	Weekly   int    `yaml:"weekly"`
	Monthly  int    `yaml:"monthly"`
	Yearly   int    `yaml:"yearly"`
	Timezone string `yaml:"timezone"`
}

// Policy returns the policy.
func (r RetentionConfig) Policy() api.RetentionPolicy {
	return api.RetentionPolicy{Last: r.Last, Hourly: r.Hourly, Daily: r.Daily, Weekly: r.Weekly, Monthly: r.Monthly, Yearly: r.Yearly}
}

// ScheduleConfig lists the cron expressions of the node's jobs; an empty one is off.
type ScheduleConfig struct {
	Timezone  string `yaml:"timezone"`
	Retention string `yaml:"retention"`
	GC        string `yaml:"gc"`
	// VerifyNew verifies snapshots that were never verified; VerifyStale re-verifies old ones;
	// VerifyAll reads every chunk (a scrub).
	VerifyNew   string `yaml:"verify_new"`
	VerifyStale string `yaml:"verify_stale"`
	VerifyAll   string `yaml:"verify_all"`
	// StaleDays is the age for VerifyStale (default 30).
	StaleDays int `yaml:"stale_days"`
}

// Duration is a time.Duration written as "24h" in the file.
type Duration time.Duration

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML writes the duration string.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// ParseConfig decodes a configuration strictly and applies defaults.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("backupd: the configuration is empty")
		}
		return nil, fmt.Errorf("backupd: configuration: %w", err)
	}
	c.defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":39111"
	}
	if c.AdminSocket == "" {
		c.AdminSocket = "/var/run/jailops-backupd.sock"
	}
	if c.TLS.CertFile == "" {
		c.TLS.CertFile = "/usr/local/etc/jailops/backupd.crt"
	}
	if c.TLS.KeyFile == "" {
		c.TLS.KeyFile = "/usr/local/etc/jailops/backupd.key"
	}
	if c.Grace == 0 {
		c.Grace = Duration(24 * time.Hour)
	}
	if c.Lease == 0 {
		c.Lease = Duration(15 * time.Minute)
	}
	if c.DeletionDelay == 0 {
		c.DeletionDelay = Duration(72 * time.Hour)
	}
	if c.Retention.Timezone == "" {
		c.Retention.Timezone = "UTC"
	}
	if c.Schedule.Timezone == "" {
		c.Schedule.Timezone = "UTC"
	}
	if c.Schedule.StaleDays == 0 {
		c.Schedule.StaleDays = 30
	}
}

// Validate checks the configuration without touching the network.
func (c *Config) Validate() error {
	if c.Web.Listen != "" {
		return errors.New("backupd: web.listen was removed: the management API and the console are served on listen (default :39111), next to the host API; delete web.listen")
	}
	switch c.Datastore.Kind {
	case "directory":
		if c.Datastore.Directory == "" {
			return errors.New("backupd: datastore.directory is required")
		}
	case "s3":
		s := c.Datastore.S3
		if s.Bucket == "" || s.CredentialsFile == "" || s.Region == "" && s.Endpoint == "" {
			return errors.New("backupd: datastore.s3 needs bucket, credentials_file and a region or endpoint")
		}
	default:
		return fmt.Errorf("backupd: datastore.kind must be directory or s3, not %q", c.Datastore.Kind)
	}
	if c.Database.DSN == "" && c.Database.DSNFile == "" {
		return errors.New("backupd: database.dsn or database.dsn_file is required")
	}
	if c.Database.DSN != "" && c.Database.DSNFile != "" {
		return errors.New("backupd: set database.dsn or database.dsn_file, not both")
	}
	if time.Duration(c.Grace) < 12*time.Hour {
		return fmt.Errorf("backupd: grace %v is shorter than the 12 hour minimum", time.Duration(c.Grace))
	}
	if time.Duration(c.Lease) < time.Minute {
		return errors.New("backupd: lease must be at least one minute")
	}
	if _, err := time.LoadLocation(c.Retention.Timezone); err != nil {
		return fmt.Errorf("backupd: retention.timezone: %w", err)
	}
	if _, err := time.LoadLocation(c.Schedule.Timezone); err != nil {
		return fmt.Errorf("backupd: schedule.timezone: %w", err)
	}
	for name, expr := range map[string]string{"retention": c.Schedule.Retention, "gc": c.Schedule.GC, "verify_new": c.Schedule.VerifyNew,
		"verify_stale": c.Schedule.VerifyStale, "verify_all": c.Schedule.VerifyAll} {
		if expr == "" {
			continue
		}
		if _, err := schedule.Parse(expr); err != nil {
			return fmt.Errorf("backupd: schedule.%s: %w", name, err)
		}
	}
	seen := map[string]bool{}
	for i, h := range c.Hosts {
		if h.Name == "" {
			return fmt.Errorf("backupd: hosts[%d] has no name", i)
		}
		fp, err := auth.NormalizeFingerprint(h.Fingerprint)
		if err != nil {
			return fmt.Errorf("backupd: hosts[%d] (%s): %w", i, h.Name, err)
		}
		if seen[fp] {
			return fmt.Errorf("backupd: hosts[%d] (%s): duplicate fingerprint", i, h.Name)
		}
		seen[fp] = true
		if err := checkScopes(h.Scopes); err != nil {
			return fmt.Errorf("backupd: hosts[%d] (%s): %w", i, h.Name, err)
		}
	}
	return nil
}

// HostScopes are the scopes a host can hold. Administration is never one of them.
var HostScopes = []string{string(api.PermBackupPush), string(api.PermBackupPull), string(api.PermRestore)}

func checkScopes(scopes []string) error {
	if len(scopes) == 0 {
		return errors.New("at least one scope is required")
	}
	for _, s := range scopes {
		ok := false
		for _, h := range HostScopes {
			ok = ok || s == h
		}
		if !ok {
			return fmt.Errorf("unknown scope %q (backup-push, backup-pull or restore; administration is not a host scope)", s)
		}
	}
	return nil
}

// LoadConfig reads and parses a configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("backupd: %w", err)
	}
	return ParseConfig(data)
}

// ReadSecretFile reads a file that holds a secret and refuses one that group or
// others can read.
func ReadSecretFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("backupd: %s is readable by group or others (mode %o); it holds a secret, make it 0600", path, st.Mode().Perm())
	}
	return os.ReadFile(path)
}

// DSN returns the database connection string.
func (c *Config) DSN() (string, error) {
	if c.Database.DSN != "" {
		return c.Database.DSN, nil
	}
	b, err := ReadSecretFile(c.Database.DSNFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
