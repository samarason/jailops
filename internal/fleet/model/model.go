// Package model defines the typed content of a jailops-sync fleet repository.
//
// Objects that the API owns (Jail, Network, FirewallPolicy, ...) use the wire
// types of package api. Objects that exist only in the repository (Host,
// HostGroup, JailTemplate, Rollout) are defined here. Every file in the repo
// is one document with the same envelope (File); the spec is decoded strictly
// according to its kind, so a misspelled key is an error, never ignored.
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/sdk/api"
)

// KindProfile is a reusable fragment of a jail spec. It exists in the
// repository only: sync expands it into the jails that list it.
const KindProfile api.Kind = "Profile"

// KindInfo describes one API-backed kind in the repository.
type KindInfo struct {
	Kind api.Kind
	// Dir is the directory name under shared/, hosts/<host>/ and projects/<p>/.
	Dir string
	// HostOnly kinds may not appear under shared/.
	HostOnly bool
	// ProjectLevel kinds belong to a named project (metadata.project or the
	// projects/<project>/ directory); the others are host-level.
	ProjectLevel bool
	// NoDir kinds are loaded from their own place (projects/<name>.yaml).
	NoDir bool
	// Extension is the api_extensions name the server must advertise.
	Extension string
}

// Kinds lists the managed API kinds in dependency order: a kind only refers to
// kinds before it. Create and update run in this order, delete in reverse.
// A project's mandatory firewall policy is the one back reference: the apply
// step creates the project first and sets that field after the policies.
var Kinds = []KindInfo{
	{Kind: api.KindImage, Dir: "images", Extension: "images_pkgbase"},
	{Kind: api.KindNetwork, Dir: "networks", Extension: "networks_vnet"},
	// A tunnel's endpoint and keys belong to one host, so it is declared under hosts/<host>/wireguard/ only.
	{Kind: api.KindWireGuard, Dir: "wireguard", HostOnly: true, Extension: "wireguard"},
	{Kind: api.KindStorage, Dir: "storage", HostOnly: true, Extension: "storage"},
	{Kind: api.KindProject, Dir: "projects", HostOnly: true, NoDir: true, Extension: "projects"},
	{Kind: api.KindAddressSet, Dir: "address-sets", ProjectLevel: true, Extension: "firewall_anchors"},
	{Kind: api.KindFirewallPolicy, Dir: "firewall-policies", ProjectLevel: true, Extension: "firewall_anchors"},
	{Kind: api.KindBackupTarget, Dir: "backup-targets", Extension: "backup_policies"},
	{Kind: api.KindBackupPolicy, Dir: "backup-policies", ProjectLevel: true, Extension: "backup_policies"},
	// A volume is a dataset of one host; a jail that attaches it comes after it.
	{Kind: api.KindVolume, Dir: "volumes", HostOnly: true, ProjectLevel: true, Extension: "volumes"},
	{Kind: api.KindJail, Dir: "jails", HostOnly: true, ProjectLevel: true, Extension: "jails"},
}

// KindApp is an app of the catalog installed as a jail (jailops app install).
const KindApp api.Kind = "App"

// AppKinds are the kinds sync manages through the application catalog, not as
// stored objects: an App is installed (never changed or deleted), and an
// AppAccess is the list of sources allowed to reach an installed app. They
// come after every kind of Kinds: an app needs its project, network, storage
// and image, and a grant needs the app and its source jails.
var AppKinds = []KindInfo{
	{Kind: KindApp, Dir: "apps", HostOnly: true, ProjectLevel: true, Extension: "app_install"},
	{Kind: api.KindAppAccess, Dir: "app-access", HostOnly: true, ProjectLevel: true, Extension: "app_access"},
}

// KindOf returns the info of a managed kind.
func KindOf(k api.Kind) (KindInfo, bool) {
	for _, ki := range append(slices.Clone(Kinds), AppKinds...) {
		if ki.Kind == k {
			return ki, true
		}
	}
	return KindInfo{}, false
}

// Order returns the dependency rank of a managed kind (-1 when unmanaged).
func Order(k api.Kind) int {
	for i, ki := range append(slices.Clone(Kinds), AppKinds...) {
		if ki.Kind == k {
			return i
		}
	}
	return -1
}

// AppSpec is the spec of an App document: what `jailops app install` is given.
// The jail is metadata.name; the project is the directory's.
type AppSpec struct {
	// App is the name of the definition in the host's catalog.
	App string `json:"app"`
	// Network and Storage default to the project's only grant of a kind.
	Network string `json:"network,omitempty"`
	Storage string `json:"storage,omitempty"`
	// Image defaults to the FreeBSD image of the highest release the host runs.
	Image string `json:"image,omitempty"`
	// Limits replace the definition's resource hints.
	Limits *api.Resources `json:"limits,omitempty"`
}

// AppAccessSpec is the spec of an AppAccess document: every source allowed to
// reach the installed app named by metadata.name.
type AppAccessSpec struct {
	Grants []AppGrant `json:"grants"`
}

// AppGrant is one source of an AppAccess document.
type AppGrant struct {
	// Source is @jail, @address-set, an address or a prefix, or host.
	Source string `json:"source"`
	// Ports are "N" or "N/proto"; empty means the definition's ports.
	Ports []string `json:"ports,omitempty"`
	// Database names the database and role of a postgresql grant (default: the
	// source jail's name). Its password is made on the host when the grant is
	// applied, printed once, and never written anywhere by sync.
	Database string `json:"database,omitempty"`
}

var (
	dbNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

// CanonicalSource is the form the host stores a grant under, so a declared
// source and a live grant compare: host, jail:NAME, set:NAME, an address, or a masked prefix.
func CanonicalSource(s string) (string, error) {
	switch {
	case s == "host":
		return s, nil
	case strings.HasPrefix(s, "@"):
		n := s[1:]
		return "", fmt.Errorf("source %q: @ is not used: write jail:%s or set:%s", s, n, n)
	case strings.HasPrefix(s, "jail:"):
		if !api.IsName(s[5:], 29) {
			return "", fmt.Errorf("source %q: jail: is followed by the name of a jail of the project", s)
		}
		return s, nil
	case strings.HasPrefix(s, "set:"):
		if !api.IsName(s[4:], 29) {
			return "", fmt.Errorf("source %q: set: is followed by the name of an address set of the project", s)
		}
		return s, nil
	case s == "" || s == "any" || strings.HasPrefix(s, "tag:"):
		return "", fmt.Errorf("source %q: name a jail (jail:web), an address set (set:office), an address or a prefix, or host", s)
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return "", fmt.Errorf("source %q is not an address or a prefix", s)
		}
		p = p.Masked()
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return "", fmt.Errorf("source %q is not an address, a prefix, jail:NAME, set:NAME or host", s)
	}
	return a.String(), nil
}

// NormalizePorts turns "N" and "N/proto" into "N/proto", sorted and without repeats.
func NormalizePorts(in []string) ([]string, error) {
	var out []string
	for _, s := range in {
		num, proto, ok := strings.Cut(s, "/")
		if !ok {
			proto = "tcp"
		}
		n, err := strconv.Atoi(num)
		if err != nil || n < 1 || n > 65535 || (proto != "tcp" && proto != "udp") {
			return nil, fmt.Errorf("port %q must be N or N/tcp or N/udp, with N from 1 to 65535", s)
		}
		out = append(out, strconv.Itoa(n)+"/"+proto)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Validate checks an App spec.
func (s AppSpec) Validate() error {
	if !api.IsName(s.App, 29) {
		return fmt.Errorf("spec.app %q must name an app of the catalog (^[a-z][a-z0-9-]{0,62}$)", s.App)
	}
	return nil
}

// Validate checks an AppAccess spec in a project: sources, ports, databases, no source twice.
func (s AppAccessSpec) Validate() error {
	seen := map[string]bool{}
	for i, g := range s.Grants {
		c, err := CanonicalSource(g.Source)
		if err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		if seen[c] {
			return fmt.Errorf("grants[%d]: source %s is listed twice", i, c)
		}
		seen[c] = true
		if _, err := NormalizePorts(g.Ports); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		if g.Database != "" {
			if !dbNameRe.MatchString(g.Database) || g.Database == "postgres" || g.Database == "public" ||
				g.Database == "template0" || g.Database == "template1" || strings.HasPrefix(g.Database, "pg_") {
				return fmt.Errorf("grants[%d]: database %q must match ^[a-z][a-z0-9_]{0,62}$ and not be a name PostgreSQL reserves", i, g.Database)
			}
		}
	}
	return nil
}

// File is the envelope of every YAML document in the repository.
type File struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       api.Kind       `yaml:"kind"`
	Metadata   api.ObjectMeta `yaml:"metadata"`
	// Hosts selects the hosts a shared object applies to: host names, @group
	// references. Empty means every host. Not allowed outside shared/.
	Hosts []string `yaml:"hosts,omitempty"`
	// Templates lists JailTemplates merged under a Jail's own spec, in order.
	Templates []string `yaml:"templates,omitempty"`
	// Start starts a Jail after the sync creates it. It is never re-applied.
	Start bool `yaml:"start,omitempty"`
	// Build builds the first generation of an Image when the host has none (a fresh host has none, and a jail
	// cannot be created from an image without one). It is never re-applied once a generation exists.
	Build bool `yaml:"build,omitempty"`
	// After lists typed hooks run once after a Jail is created.
	After []Hook         `yaml:"after,omitempty"`
	Spec  map[string]any `yaml:"spec"`
}

// Meta is fleet.yaml.
type Meta struct {
	// ID identifies the fleet. Objects created by sync carry
	// managed_by: sync:<id>, and only those are ever changed or deleted.
	ID string `yaml:"id"`
	// Hub, when set, is the hub through which hosts with via_hub are reached.
	Hub *Endpoint `yaml:"hub,omitempty"`
}

// Endpoint says how to reach a daemon.
type Endpoint struct {
	URL         string `yaml:"url,omitempty" json:"url,omitempty"`
	Socket      string `yaml:"socket,omitempty" json:"socket,omitempty"`
	Fingerprint string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	// TokenSecret names secrets/<name>.age holding the API token.
	TokenSecret string `yaml:"token_secret,omitempty" json:"token_secret,omitempty"`
}

// HostSpec is the spec of a Host document: how to reach one host.
type HostSpec struct {
	Endpoint
	// ViaHub reaches the host through the fleet's hub (?host=<name>).
	ViaHub bool `json:"via_hub,omitempty"`
}

// HostGroupSpec selects hosts by name, by other groups and by label.
type HostGroupSpec struct {
	// Members are host names or @group references. Cycles are rejected.
	Members []string `json:"members,omitempty"`
	// Selector adds every host whose labels contain all of these.
	Selector map[string]string `json:"selector,omitempty"`
}

// Hook is one typed action run after a Jail is created. Hooks are data, not
// shell: each action maps to one SDK call.
type Hook struct {
	// Action is start, restart, snapshot or exec.
	Action string `yaml:"action" json:"action"`
	// Name names the snapshot for action snapshot.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Argv is the command for action exec. It is never passed to a shell.
	Argv []string `yaml:"argv,omitempty" json:"argv,omitempty"`
}

// Hook actions.
const (
	HookStart    = "start"
	HookRestart  = "restart"
	HookSnapshot = "snapshot"
	HookExec     = "exec"
)

// Validate checks a hook.
func (h Hook) Validate() error {
	switch h.Action {
	case HookStart, HookRestart:
		if h.Name != "" || len(h.Argv) > 0 {
			return fmt.Errorf("hook %s takes no name or argv", h.Action)
		}
	case HookSnapshot:
		if len(h.Argv) > 0 {
			return fmt.Errorf("hook snapshot takes no argv")
		}
		if h.Name != "" {
			if err := CheckName(h.Name); err != nil {
				return fmt.Errorf("hook snapshot name: %w", err)
			}
		}
	case HookExec:
		if len(h.Argv) == 0 || h.Argv[0] == "" {
			return fmt.Errorf("hook exec needs a non-empty argv")
		}
		if h.Name != "" {
			return fmt.Errorf("hook exec takes no name")
		}
	default:
		return fmt.Errorf("unknown hook action %q (want start, restart, snapshot or exec)", h.Action)
	}
	return nil
}

// TemplateSpec is the spec of a JailTemplate document.
type TemplateSpec struct {
	Comment string `json:"comment,omitempty"`
	// Jail is a fragment of a JailSpec merged under every jail using the template.
	Jail map[string]any `json:"jail,omitempty"`
	// After hooks run, in order, after a jail using the template is created.
	After []Hook `json:"after,omitempty"`
}

// RolloutSpec is the spec of a Rollout document: a staged operation over jails.
type RolloutSpec struct {
	Comment string `json:"comment,omitempty"`
	// Hosts limits the hosts; empty means every host.
	Hosts []string `json:"hosts,omitempty"`
	// Project is the project whose jails are selected. Required.
	Project string `json:"project,omitempty"`
	// Selector matches jails by label (all must match). Required.
	Selector map[string]string `json:"selector"`
	// Action is "upgrade" (the only action).
	Action string `json:"action,omitempty"`
	// Generation pins the target generation ("g3"); empty means the newest.
	Generation string `json:"generation,omitempty"`
	// Canary is the number of jails upgraded first, alone. Default 1.
	Canary int `json:"canary,omitempty"`
	// BatchSize is the size of every later batch. Default 1.
	BatchSize int `json:"batch_size,omitempty"`
	// Pause waits between batches, e.g. "30s".
	Pause string `json:"pause,omitempty"`
	// HealthGate must pass after every batch before the next one starts.
	HealthGate HealthGate `json:"health_gate,omitempty"`
}

// HealthGate says when a batch counts as healthy.
type HealthGate struct {
	// Timeout is how long to wait for the batch to become healthy. Default 60s.
	Timeout string `json:"timeout,omitempty"`
	// Interval is the poll interval. Default 2s.
	Interval string `json:"interval,omitempty"`
}

// Defaults and parsed durations of a rollout.
func (r RolloutSpec) Durations() (pause, timeout, interval time.Duration, err error) {
	parse := func(s string, def time.Duration, what string) (time.Duration, error) {
		if s == "" {
			return def, nil
		}
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("invalid %s %q", what, s)
		}
		return d, nil
	}
	if pause, err = parse(r.Pause, 0, "pause"); err != nil {
		return
	}
	if timeout, err = parse(r.HealthGate.Timeout, 60*time.Second, "health_gate.timeout"); err != nil {
		return
	}
	interval, err = parse(r.HealthGate.Interval, 2*time.Second, "health_gate.interval")
	if err == nil && interval == 0 {
		interval = 2 * time.Second
	}
	return
}

// Validate checks the rollout spec.
func (r RolloutSpec) Validate() error {
	if len(r.Selector) == 0 {
		return fmt.Errorf("selector is required (a rollout never targets every jail implicitly)")
	}
	if r.Action != "" && r.Action != "upgrade" {
		return fmt.Errorf("unsupported action %q (only upgrade)", r.Action)
	}
	if r.Canary < 0 || r.BatchSize < 0 {
		return fmt.Errorf("canary and batch_size must not be negative")
	}
	if r.Generation != "" && !genRe.MatchString(r.Generation) {
		return fmt.Errorf("generation %q must look like g3", r.Generation)
	}
	_, _, _, err := r.Durations()
	return err
}

var genRe = regexp.MustCompile(`^g[1-9][0-9]*$`)

// CheckName enforces the API's name rule (api.NamePattern): lowercase letters, digits and hyphens, starting with
// a letter.
func CheckName(name string) error {
	if name == "" {
		return fmt.Errorf("name is empty")
	}
	if !api.IsName(name, api.MaxName) {
		return fmt.Errorf("name %q must use lowercase letters, digits and hyphens, start with a letter, not end in a hyphen, at most %d characters", name, api.MaxName)
	}
	return nil
}

// CheckSimpleName is the stricter rule for hosts, groups and templates, which
// appear in references: no dots.
func CheckSimpleName(name string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	for _, c := range name {
		if c == '.' {
			return fmt.Errorf("name %q must not contain '.'", name)
		}
	}
	return nil
}

// DecodeStrict decodes a generic map into v and rejects unknown keys.
func DecodeStrict(raw map[string]any, v any) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("spec is not representable: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// DecodeSpec decodes the spec of an API-backed kind into its typed form.
func DecodeSpec(kind api.Kind, raw map[string]any) (any, error) {
	if raw == nil {
		raw = map[string]any{}
	}
	switch kind {
	case api.KindJail:
		var s api.JailSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindImage:
		var s api.ImageSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindNetwork:
		var s api.NetworkSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindFirewallPolicy:
		var s api.FirewallPolicySpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindAddressSet:
		var s api.AddressSetSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindVolume:
		var s api.VolumeSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindBackupPolicy:
		var s api.BackupPolicySpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindBackupTarget:
		var s api.BackupTargetSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindProject:
		var s api.ProjectSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindStorage:
		var s api.StorageSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case api.KindWireGuard:
		var s api.WireGuardSpec
		err := DecodeStrict(raw, &s)
		return s, err
	case KindApp:
		var s AppSpec
		if err := DecodeStrict(raw, &s); err != nil {
			return s, err
		}
		return s, s.Validate()
	case api.KindAppAccess:
		var s AppAccessSpec
		err := DecodeStrict(raw, &s)
		return s, err
	}
	return nil, fmt.Errorf("kind %q is not managed by jailops-sync", kind)
}

// deviceLists are the jail spec lists whose elements are named devices.
// Merging two specs merges these lists name by name (a later entry overrides
// only the keys it sets) instead of replacing the whole list.
var deviceLists = map[string]bool{"network": true, "volumes": true, "devfs": true, "proxy": true}

// deviceKey is the key an element of a device list is named by: the volumes of a jail by the volume they attach.
func deviceKey(list string) string {
	if list == "volumes" {
		return "volume"
	}
	return "name"
}

// MergeSpec merges a jail spec fragment over a base: maps merge, null
// deletes, device lists (network, volumes, devfs, proxy) merge by device
// name, every other value replaces. Unnamed network devices are named
// eth0, eth1, ... by position first. dst is modified and returned.
func MergeSpec(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		switch sv := v.(type) {
		case nil:
			delete(dst, k)
		case map[string]any:
			dm, _ := dst[k].(map[string]any)
			dst[k] = MergeSpec(cloneMap(dm), sv)
		case []any:
			if deviceLists[k] {
				dst[k] = mergeDevices(k, dst[k], sv)
			} else {
				dst[k] = v
			}
		default:
			dst[k] = v
		}
	}
	return dst
}

func nameDevices(kind string, l []any) []any {
	out := make([]any, 0, len(l))
	n := 0
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			out = append(out, e)
			continue
		}
		m = cloneMap(m)
		if name, _ := m[deviceKey(kind)].(string); name == "" && kind == "network" {
			m["name"] = autoName + "eth" + strconv.Itoa(n)
		}
		if kind == "network" {
			n++
		}
		out = append(out, m)
	}
	return out
}

// autoName marks a device name assigned by position while merging; it is
// stripped again so the server's own naming stays authoritative.
const autoName = "~auto:"

func sameName(a any, b string) bool {
	as, _ := a.(string)
	return strings.TrimPrefix(as, autoName) == strings.TrimPrefix(b, autoName)
}

// StripAutoNames removes device names that MergeSpec only assigned by position.
func StripAutoNames(spec map[string]any) {
	for k := range deviceLists {
		l, _ := spec[k].([]any)
		for _, e := range l {
			if m, ok := e.(map[string]any); ok {
				if n, _ := m["name"].(string); strings.HasPrefix(n, autoName) {
					delete(m, "name")
				}
			}
		}
	}
}

func mergeDevices(kind string, base any, over []any) any {
	b, _ := base.([]any)
	out := nameDevices(kind, b)
	for _, e := range nameDevices(kind, over) {
		m, ok := e.(map[string]any)
		key := deviceKey(kind)
		name, _ := m[key].(string)
		if !ok || name == "" {
			out = append(out, e)
			continue
		}
		found := false
		for i, x := range out {
			if xm, ok := x.(map[string]any); ok && sameName(xm[key], name) {
				merged := Merge(xm, m)
				if xn, _ := xm[key].(string); !strings.HasPrefix(xn, autoName) {
					merged[key] = xn
				}
				out[i] = merged
				found = true
				break
			}
		}
		if !found {
			out = append(out, m)
		}
	}
	return out
}

// Merge applies src over dst as a JSON merge patch (RFC 7386): maps merge,
// everything else replaces, null deletes. dst is modified and returned.
func Merge(dst, src map[string]any) map[string]any {
	if dst == nil {
		dst = map[string]any{}
	}
	for k, v := range src {
		switch sv := v.(type) {
		case nil:
			delete(dst, k)
		case map[string]any:
			dm, _ := dst[k].(map[string]any)
			dst[k] = Merge(cloneMap(dm), sv)
		default:
			dst[k] = v
		}
	}
	return dst
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if mm, ok := v.(map[string]any); ok {
			out[k] = cloneMap(mm)
		} else {
			out[k] = v
		}
	}
	return out
}

// CloneMap deep-copies the map parts of a generic value tree.
func CloneMap(m map[string]any) map[string]any { return cloneMap(m) }

// ToMap converts a typed value into its generic JSON form (snake_case keys, omitempty applied).
func ToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}
