// Package config loads a jailops-sync fleet repository, enforces its naming and
// layout rules, expands host references and templates, and checks the result.
//
// Layout (design section 12):
//
//	fleet.yaml                          fleet id and optional hub
//	hosts/<host>/host.yaml              kind Host: how to reach the host
//	hosts/<host>/<kind-dir>/<name>.yaml host-level objects of that host (storage, ...)
//	shared/<kind-dir>/<name>.yaml       host-level objects for every host, or those in `hosts:`
//	projects/<name>.yaml                kind Project, naming the hosts it spans
//	projects/<name>/<kind-dir>/<n>.yaml jails and the other objects a project owns (a jail names its host)
//	groups/<name>.yaml                  kind HostGroup
//	templates/<name>/manifest.yaml      kind JailTemplate
//	rollouts/<name>.yaml                kind Rollout
//	secrets/<name>.age                  age-encrypted secrets
//
// The file name (without .yaml) must equal metadata.name; a directory that
// holds a manifest must be named after the object. The loader never decrypts
// anything and never contacts a host.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/internal/fleet/vault"
	"jailops.net/jailops/sdk/api"
)

// maxFileSize bounds every file the loader reads.
const maxFileSize = 4 << 20

// Fleet is a loaded repository.
type Fleet struct {
	Path string
	Meta model.Meta

	Hosts     map[string]*Host
	Groups    map[string]*Group
	Templates map[string]*Template
	Rollouts  map[string]*Rollout
	// Projects are the projects the repository defines; a project-level object
	// names one of them.
	Projects map[string]*ProjectDef
	// Profiles are the shared profiles; project profiles are in ProjectDef.
	Profiles map[string]*Profile
	// Secrets are the names of secrets/*.age.
	Secrets map[string]bool
	// SopsSecrets is the key structure of shared/secrets.sops.yaml (values are
	// ciphertext and never read); nil when the file does not exist.
	SopsSecrets map[string]any
	// Remotes are the public fields of hosts/<host>/remote.sops.yaml, by host.
	Remotes map[string]*vault.Remote
	// Objects are all API-backed objects with their target hosts resolved.
	Objects []*Object

	Warnings []string
}

// Host is a Host document.
type Host struct {
	Name   string
	Labels map[string]string
	Spec   model.HostSpec
	Origin string
}

// Group is a HostGroup document.
type Group struct {
	Name   string
	Spec   model.HostGroupSpec
	Origin string
}

// Template is a JailTemplate document.
type Template struct {
	Name   string
	Spec   model.TemplateSpec
	Origin string
}

// Rollout is a Rollout document.
type Rollout struct {
	Name   string
	Labels map[string]string
	Spec   model.RolloutSpec
	Origin string
}

// ProjectDef is a Project document. Its Object (Kind Project) is sent to
// every host in Hosts.
type ProjectDef struct {
	Name string
	Spec api.ProjectSpec
	// Hosts are the expanded hosts of spec.hosts, sorted.
	Hosts    []string
	Labels   map[string]string
	Profiles map[string]*Profile
	Origin   string
}

// Profile is a Profile document: a jail spec fragment that jails list in
// spec.profiles. Sync expands it into the jail before sending.
type Profile struct {
	Name    string
	Project string // "" for a shared profile
	Spec    map[string]any
	Origin  string
}

// Object is one API-backed object declared in the repository.
type Object struct {
	Kind api.Kind
	Name string
	// Project is the project of a project-level kind (a file must name one, by its directory or by
	// metadata.project) and "" for host-level kinds.
	Project string
	// Profiles are the profiles expanded into a jail, in order, and
	// Provenance maps each top-level spec key to where its value came from.
	Profiles   []string
	Provenance map[string]string
	// Labels are the user labels (without sync bookkeeping labels).
	Labels map[string]string
	// Spec is the typed spec (api.JailSpec, api.NetworkSpec, ...). For jails
	// it is the spec after template merging; env values may still be
	// "secret:<name>" references.
	Spec   any
	Origin string
	// Scope is "shared" or the owning host's name.
	Scope string
	// Hosts are the hosts the object applies to, sorted.
	Hosts []string
	// Build only applies to images: build the first generation when the host has none.
	Build bool
	// Start, After and Templates only apply to jails.
	Start     bool
	After     []model.Hook
	Templates []string
	// SecretRefs are the secrets the object refers to.
	SecretRefs []string

	hostRefs []string
}

// Key identifies an object on one host. Project is "" for host-level kinds.
type Key struct {
	Kind    api.Kind
	Project string
	Name    string
}

// Key returns the object's key.
func (o *Object) Key() Key { return Key{o.Kind, o.Project, o.Name} }

// SecretPrefix marks an env value that refers to a secret: "secret:<name>" is
// secrets/<name>.age, and "secret:<dotted.path>" is a value of
// shared/secrets.sops.yaml (a name never contains a dot, a path always does).
const SecretPrefix = "secret:"

// IsSopsRef reports whether a secret reference (without the prefix) names a
// value of the SOPS secrets file.
func IsSopsRef(ref string) bool { return strings.Contains(ref, ".") }

// FleetFile is the name of the repository's top-level file.
const FleetFile = "fleet.yaml"

// Load reads and structurally validates the repository at path. Cross-object
// reference checks are done by Check.
func Load(path string) (*Fleet, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("fleet path: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("fleet path %q is not a directory", path)
	}
	f := &Fleet{
		Path: path, Hosts: map[string]*Host{}, Groups: map[string]*Group{},
		Templates: map[string]*Template{}, Rollouts: map[string]*Rollout{},
		Projects: map[string]*ProjectDef{}, Profiles: map[string]*Profile{},
		Secrets: map[string]bool{}, Remotes: map[string]*vault.Remote{},
	}
	if err := f.loadMeta(); err != nil {
		return nil, err
	}
	steps := []func() error{
		f.checkTopLevel, f.loadSecrets, f.loadSopsSecrets, f.loadHosts, f.loadGroups, f.loadTemplates,
		f.loadRollouts, f.loadProfiles, f.loadProjects, f.loadShared, f.loadHostObjects,
		f.loadProjectObjects, f.resolveTargets,
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(f.Objects, func(i, j int) bool {
		a, b := f.Objects[i], f.Objects[j]
		if model.Order(a.Kind) != model.Order(b.Kind) {
			return model.Order(a.Kind) < model.Order(b.Kind)
		}
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Scope < b.Scope
	})
	return f, nil
}

// ManagedBy is the ownership marker written on every object sync creates.
func (f *Fleet) ManagedBy() string { return "sync:" + f.Meta.ID }

// HostNames returns the sorted host names.
func (f *Fleet) HostNames() []string { return sortedKeys(f.Hosts) }

// GroupNames returns the sorted group names.
func (f *Fleet) GroupNames() []string { return sortedKeys(f.Groups) }

// RolloutNames returns the sorted rollout names.
func (f *Fleet) RolloutNames() []string { return sortedKeys(f.Rollouts) }

// SecretNames returns the sorted secret names.
func (f *Fleet) SecretNames() []string { return sortedKeys(f.Secrets) }

// ObjectsFor returns the objects that apply to a host, in dependency order.
func (f *Fleet) ObjectsFor(host string) []*Object {
	var out []*Object
	for _, o := range f.Objects {
		if slices.Contains(o.Hosts, host) {
			out = append(out, o)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *Fleet) rel(p string) string {
	if r, err := filepath.Rel(f.Path, p); err == nil {
		return r
	}
	return p
}

// readFile reads a regular, bounded file; symlinks are refused.
func readFile(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (symlinks are not allowed in a fleet repository)", p)
	}
	if st.Size() > maxFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", p, maxFileSize)
	}
	return os.ReadFile(p)
}

// decodeYAML decodes exactly one document, rejecting unknown keys.
func decodeYAML(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("file is empty")
		}
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("a file holds exactly one document")
	}
	return nil
}

func (f *Fleet) loadMeta() error {
	p := filepath.Join(f.Path, FleetFile)
	data, err := readFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s is missing: every fleet declares its id", FleetFile)
		}
		return err
	}
	if err := decodeYAML(data, &f.Meta); err != nil {
		return fmt.Errorf("%s: %w", FleetFile, err)
	}
	if f.Meta.ID == "" {
		return fmt.Errorf("%s: id is required (it becomes managed_by: sync:<id>)", FleetFile)
	}
	if err := model.CheckSimpleName(f.Meta.ID); err != nil {
		return fmt.Errorf("%s: id: %w", FleetFile, err)
	}
	if h := f.Meta.Hub; h != nil {
		if err := checkEndpoint(*h); err != nil {
			return fmt.Errorf("%s: hub: %w", FleetFile, err)
		}
	}
	return nil
}

func checkEndpoint(e model.Endpoint) error {
	n := 0
	if e.URL != "" {
		n++
	}
	if e.Socket != "" {
		n++
	}
	if n > 1 {
		return errors.New("set url or socket, not both")
	}
	if e.Fingerprint != "" && e.URL == "" {
		return errors.New("fingerprint needs a url")
	}
	if e.URL != "" && !strings.HasPrefix(e.URL, "https://") && !strings.HasPrefix(e.URL, "http://") {
		return fmt.Errorf("url %q must start with https:// (or http:// for loopback)", e.URL)
	}
	if strings.HasPrefix(e.URL, "http://") {
		u, err := url.Parse(e.URL)
		if err != nil {
			return fmt.Errorf("url %q: %v", e.URL, err)
		}
		h := u.Hostname()
		if ip, perr := netip.ParseAddr(h); h != "localhost" && (perr != nil || !ip.IsLoopback()) {
			return fmt.Errorf("url %q: plain http is allowed for loopback only (the SDK refuses it otherwise); use https with a pinned fingerprint", e.URL)
		}
	}
	if e.TokenSecret != "" {
		if err := model.CheckSimpleName(e.TokenSecret); err != nil {
			return fmt.Errorf("token_secret: %w", err)
		}
	}
	return nil
}

var topLevelDirs = map[string]bool{"hosts": true, "shared": true, "groups": true, "templates": true, "rollouts": true, "secrets": true, "projects": true, "profiles": true}

func (f *Fleet) checkTopLevel() error {
	ents, err := os.ReadDir(f.Path)
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || n == FleetFile || strings.HasSuffix(n, ".md") {
			continue
		}
		if e.IsDir() && topLevelDirs[n] {
			continue
		}
		return fmt.Errorf("%s: unexpected entry at the top of the fleet repository (allowed: %s, hosts/, shared/, projects/, profiles/, groups/, templates/, rollouts/, secrets/)", n, FleetFile)
	}
	return nil
}

func (f *Fleet) loadSecrets() error {
	ents, err := readDirIfExists(filepath.Join(f.Path, "secrets"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			return fmt.Errorf("secrets/%s: directories are not allowed", n)
		}
		if !strings.HasSuffix(n, ".age") {
			continue // recipients.txt and notes
		}
		name := strings.TrimSuffix(n, ".age")
		if err := model.CheckSimpleName(name); err != nil {
			return fmt.Errorf("secrets/%s: %w", n, err)
		}
		f.Secrets[name] = true
	}
	return nil
}

// loadSopsSecrets reads the key structure of shared/secrets.sops.yaml. It
// decrypts nothing; the file must be encrypted, because a plaintext secrets
// file in a repository is always a mistake.
func (f *Fleet) loadSopsSecrets() error {
	p := vault.SecretsPath(f.Path)
	raw, err := readFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if !vault.IsEncrypted(raw) {
		return fmt.Errorf("%s: the file is not SOPS-encrypted; encrypt it with the repository's %s before committing", vault.SecretsRel, vault.SopsPolicyFilename)
	}
	m, err := vault.SecretsStructure(f.Path)
	if err != nil {
		return err
	}
	f.SopsSecrets = m
	return nil
}

func readDirIfExists(dir string) ([]fs.DirEntry, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return ents, nil
}

// readDoc reads one document file, checks envelope, kind and file name.
func (f *Fleet) readDoc(p string, want api.Kind, nameFromDir bool) (*model.File, error) {
	data, err := readFile(p)
	if err != nil {
		return nil, err
	}
	var doc model.File
	if err := decodeYAML(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", f.rel(p), err)
	}
	if doc.APIVersion != api.APIVersion {
		return nil, fmt.Errorf("%s: apiVersion must be %q, got %q", f.rel(p), api.APIVersion, doc.APIVersion)
	}
	if doc.Kind != want {
		return nil, fmt.Errorf("%s: kind is %q but this location holds %q", f.rel(p), doc.Kind, want)
	}
	name := doc.Metadata.Name
	if name == "" {
		return nil, fmt.Errorf("%s: metadata.name is required", f.rel(p))
	}
	var expect string
	if nameFromDir {
		expect = filepath.Base(filepath.Dir(p))
	} else {
		base := filepath.Base(p)
		if !strings.HasSuffix(base, ".yaml") {
			return nil, fmt.Errorf("%s: fleet files end in .yaml", f.rel(p))
		}
		expect = strings.TrimSuffix(base, ".yaml")
	}
	if name != expect {
		return nil, fmt.Errorf("%s: metadata.name %q does not match the %s name %q", f.rel(p), name,
			map[bool]string{true: "directory", false: "file"}[nameFromDir], expect)
	}
	m := doc.Metadata
	if m.UUID != "" || m.Host != "" || m.Scope != "" || m.Generation != 0 || m.ManagedBy != "" || !m.CreatedAt.IsZero() || !m.UpdatedAt.IsZero() {
		return nil, fmt.Errorf("%s: metadata may only hold name, project and labels (the server owns uuid, host, scope, generation, managed_by and times)", f.rel(p))
	}
	for k := range m.Labels {
		if strings.HasPrefix(k, SyncLabelPrefix) {
			return nil, fmt.Errorf("%s: label %q is reserved for jailops-sync", f.rel(p), k)
		}
	}
	return &doc, nil
}

// SyncLabelPrefix is reserved for labels written by jailops-sync.
const SyncLabelPrefix = "sync.jailops.net/"

func yamlFiles(dir string) ([]string, error) {
	ents, err := readDirIfExists(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() {
			return nil, fmt.Errorf("%s: unexpected directory %q", dir, n)
		}
		if !strings.HasSuffix(n, ".yaml") {
			return nil, fmt.Errorf("%s: unexpected file %q (fleet files end in .yaml)", dir, n)
		}
		out = append(out, filepath.Join(dir, n))
	}
	return out, nil
}

func (f *Fleet) loadHosts() error {
	ents, err := readDirIfExists(filepath.Join(f.Path, "hosts"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.IsDir() {
			return fmt.Errorf("hosts/%s: hosts/ holds one directory per host", e.Name())
		}
		name := e.Name()
		if err := model.CheckSimpleName(name); err != nil {
			return fmt.Errorf("hosts/%s: %w", name, err)
		}
		p := filepath.Join(f.Path, "hosts", name, "host.yaml")
		doc, err := f.readDoc(p, api.KindHost, true)
		if err != nil {
			return err
		}
		var spec model.HostSpec
		if err := model.DecodeStrict(doc.Spec, &spec); err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		if err := checkEndpoint(spec.Endpoint); err != nil {
			return fmt.Errorf("%s: %w", f.rel(p), err)
		}
		if spec.ViaHub && (spec.URL != "" || spec.Socket != "") {
			return fmt.Errorf("%s: via_hub excludes url and socket", f.rel(p))
		}
		if spec.ViaHub && f.Meta.Hub == nil {
			return fmt.Errorf("%s: via_hub needs a hub in %s", f.rel(p), FleetFile)
		}
		if len(doc.Hosts)+len(doc.Templates)+len(doc.After) > 0 || doc.Start {
			return fmt.Errorf("%s: a Host document has only metadata and spec", f.rel(p))
		}
		if err := f.loadRemote(name, spec); err != nil {
			return err
		}
		f.Hosts[name] = &Host{Name: name, Labels: doc.Metadata.Labels, Spec: spec, Origin: f.rel(p)}
	}
	return nil
}

func (f *Fleet) loadGroups() error {
	files, err := yamlFiles(filepath.Join(f.Path, "groups"))
	if err != nil {
		return err
	}
	for _, p := range files {
		doc, err := f.readDoc(p, api.KindHostGroup, false)
		if err != nil {
			return err
		}
		if err := model.CheckSimpleName(doc.Metadata.Name); err != nil {
			return fmt.Errorf("%s: %w", f.rel(p), err)
		}
		var spec model.HostGroupSpec
		if err := model.DecodeStrict(doc.Spec, &spec); err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		f.Groups[doc.Metadata.Name] = &Group{Name: doc.Metadata.Name, Spec: spec, Origin: f.rel(p)}
	}
	return nil
}

func (f *Fleet) loadTemplates() error {
	ents, err := readDirIfExists(filepath.Join(f.Path, "templates"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.IsDir() {
			return fmt.Errorf("templates/%s: templates/ holds one directory per template", e.Name())
		}
		if err := model.CheckSimpleName(e.Name()); err != nil {
			return fmt.Errorf("templates/%s: %w", e.Name(), err)
		}
		p := filepath.Join(f.Path, "templates", e.Name(), "manifest.yaml")
		doc, err := f.readDoc(p, api.KindJailTemplate, true)
		if err != nil {
			return err
		}
		var spec model.TemplateSpec
		if err := model.DecodeStrict(doc.Spec, &spec); err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		if _, err := model.DecodeSpec(api.KindJail, spec.Jail); err != nil {
			return fmt.Errorf("%s: spec.jail: %w", f.rel(p), err)
		}
		if _, has := spec.Jail["profiles"]; has {
			return fmt.Errorf("%s: spec.jail.profiles: a template cannot list profiles; list them in the jail", f.rel(p))
		}
		for i, h := range spec.After {
			if err := h.Validate(); err != nil {
				return fmt.Errorf("%s: spec.after[%d]: %w", f.rel(p), i, err)
			}
		}
		f.Templates[e.Name()] = &Template{Name: e.Name(), Spec: spec, Origin: f.rel(p)}
	}
	return nil
}

func (f *Fleet) loadRollouts() error {
	files, err := yamlFiles(filepath.Join(f.Path, "rollouts"))
	if err != nil {
		return err
	}
	for _, p := range files {
		doc, err := f.readDoc(p, api.KindRollout, false)
		if err != nil {
			return err
		}
		if err := model.CheckSimpleName(doc.Metadata.Name); err != nil {
			return fmt.Errorf("%s: %w", f.rel(p), err)
		}
		var spec model.RolloutSpec
		if err := model.DecodeStrict(doc.Spec, &spec); err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		if err := spec.Validate(); err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		f.Rollouts[doc.Metadata.Name] = &Rollout{Name: doc.Metadata.Name, Labels: doc.Metadata.Labels, Spec: spec, Origin: f.rel(p)}
	}
	return nil
}

func (f *Fleet) loadShared() error {
	for _, ki := range model.Kinds {
		if ki.NoDir {
			continue
		}
		if ki.HostOnly {
			if _, err := os.Stat(filepath.Join(f.Path, "shared", ki.Dir)); err == nil {
				return fmt.Errorf("shared/%s: %s are declared in a project (projects/<project>/%s/) on a named host, never shared", ki.Dir, ki.Dir, ki.Dir)
			}
			continue
		}
		if err := f.loadObjectDir(filepath.Join(f.Path, "shared", ki.Dir), ki, "shared", ""); err != nil {
			return err
		}
	}
	ents, err := readDirIfExists(filepath.Join(f.Path, "shared"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || (!e.IsDir() && e.Name() == filepath.Base(vault.SecretsRel)) {
			continue
		}
		if ki, ok := dirKind(e.Name()); !ok || ki.HostOnly {
			return fmt.Errorf("shared/%s: unknown directory", e.Name())
		}
	}
	return nil
}

func dirKind(dir string) (model.KindInfo, bool) {
	for _, ki := range append(slices.Clone(model.Kinds), model.AppKinds...) {
		if ki.Dir == dir && !ki.NoDir {
			return ki, true
		}
	}
	return model.KindInfo{}, false
}

func (f *Fleet) loadHostObjects() error {
	for _, host := range f.HostNames() {
		base := filepath.Join(f.Path, "hosts", host)
		ents, err := os.ReadDir(base)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.Name() == "host.yaml" || (!e.IsDir() && e.Name() == vault.RemoteFile) {
				continue
			}
			ki, ok := dirKind(e.Name())
			if !ok || !e.IsDir() {
				return fmt.Errorf("hosts/%s/%s: unexpected entry (allowed: host.yaml, remote.sops.yaml and the kind directories)", host, e.Name())
			}
			if err := f.loadObjectDir(filepath.Join(base, e.Name()), ki, host, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadProfiles reads profiles/<name>.yaml (shared profiles).
func (f *Fleet) loadProfiles() error {
	files, err := yamlFiles(filepath.Join(f.Path, "profiles"))
	if err != nil {
		return err
	}
	for _, p := range files {
		pr, err := f.readProfile(p, "")
		if err != nil {
			return err
		}
		f.Profiles[pr.Name] = pr
	}
	return nil
}

func (f *Fleet) readProfile(p, project string) (*Profile, error) {
	doc, err := f.readDoc(p, model.KindProfile, false)
	if err != nil {
		return nil, err
	}
	if err := model.CheckSimpleName(doc.Metadata.Name); err != nil {
		return nil, fmt.Errorf("%s: %w", f.rel(p), err)
	}
	frag := doc.Spec
	if frag == nil {
		frag = map[string]any{}
	}
	if _, err := model.DecodeSpec(api.KindJail, frag); err != nil {
		return nil, fmt.Errorf("%s: spec: %w", f.rel(p), err)
	}
	if _, has := frag["profiles"]; has {
		return nil, fmt.Errorf("%s: a profile cannot list profiles", f.rel(p))
	}
	for _, k := range []string{"zfs_delegation"} {
		if _, has := frag[k]; has {
			return nil, fmt.Errorf("%s: a profile cannot carry %s (it needs a global admin and the host operator's approval): put it in the jail", f.rel(p), k)
		}
	}
	return &Profile{Name: doc.Metadata.Name, Project: project, Spec: frag, Origin: f.rel(p)}, nil
}

// loadProjects reads projects/<name>.yaml and, for each, the project
// directory projects/<name>/profiles/.
func (f *Fleet) loadProjects() error {
	ents, err := readDirIfExists(filepath.Join(f.Path, "projects"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || e.IsDir() {
			continue
		}
		p := filepath.Join(f.Path, "projects", n)
		doc, err := f.readDoc(p, api.KindProject, false)
		if err != nil {
			return err
		}
		name := doc.Metadata.Name
		if err := model.CheckSimpleName(name); err != nil {
			return fmt.Errorf("%s: %w", f.rel(p), err)
		}
		spec, err := model.DecodeSpec(api.KindProject, doc.Spec)
		if err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		ps := spec.(api.ProjectSpec)
		if ps.NewNetwork {
			return fmt.Errorf("%s: new_network is a create-time convenience; declare the network and grant it", f.rel(p))
		}
		if len(ps.Hosts) == 0 {
			return fmt.Errorf("%s: spec.hosts is required: a project in a fleet repository names the hosts it spans", f.rel(p))
		}
		def := &ProjectDef{Name: name, Labels: doc.Metadata.Labels, Origin: f.rel(p), Profiles: map[string]*Profile{}}
		def.Hosts, err = f.ExpandHosts(ps.Hosts)
		if err != nil {
			return fmt.Errorf("%s: hosts: %w", f.rel(p), err)
		}
		ps.Hosts = nil // each host holds its own copy; sync never sends the fleet list
		def.Spec = ps
		f.Projects[name] = def
	}
	// Project directories need a definition, and may hold profiles.
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		def := f.Projects[e.Name()]
		if def == nil {
			return fmt.Errorf("projects/%s: no projects/%s.yaml defines this project", e.Name(), e.Name())
		}
		files, err := yamlFiles(filepath.Join(f.Path, "projects", e.Name(), "profiles"))
		if err != nil {
			return err
		}
		for _, p := range files {
			pr, err := f.readProfile(p, e.Name())
			if err != nil {
				return err
			}
			def.Profiles[pr.Name] = pr
		}
	}
	for _, name := range sortedKeys(f.Projects) {
		def := f.Projects[name]
		f.Objects = append(f.Objects, &Object{
			Kind: api.KindProject, Name: name, Labels: def.Labels, Spec: def.Spec, Origin: def.Origin,
			Scope: "shared", Hosts: def.Hosts,
		})
	}
	return nil
}

// loadProjectObjects reads projects/<p>/<kind-dir>/<name>.yaml: objects of
// project p. They apply to the project's hosts unless `hosts:` narrows them.
func (f *Fleet) loadProjectObjects() error {
	for _, pname := range sortedKeys(f.Projects) {
		base := filepath.Join(f.Path, "projects", pname)
		ents, err := readDirIfExists(base)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.Name() == "profiles" {
				continue
			}
			ki, ok := dirKind(e.Name())
			if !ok || !e.IsDir() || !ki.ProjectLevel {
				return fmt.Errorf("projects/%s/%s: unexpected entry (allowed: profiles and the project-level kind directories)", pname, e.Name())
			}
			if err := f.loadObjectDir(filepath.Join(base, e.Name()), ki, "project:"+pname, pname); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *Fleet) loadObjectDir(dir string, ki model.KindInfo, scope, project string) error {
	files, err := yamlFiles(dir)
	if err != nil {
		return err
	}
	for _, p := range files {
		doc, err := f.readDoc(p, ki.Kind, false)
		if err != nil {
			return err
		}
		if err := model.CheckName(doc.Metadata.Name); err != nil {
			return fmt.Errorf("%s: %w", f.rel(p), err)
		}
		isProjectDir := strings.HasPrefix(scope, "project:")
		if ki.Kind == api.KindJail && !isProjectDir {
			return fmt.Errorf("%s: a jail belongs to a project: put it under projects/<project>/jails/ and name its host with `hosts: [<host>]`", f.rel(p))
		}
		if (ki.Kind == model.KindApp || ki.Kind == api.KindAppAccess) && !isProjectDir {
			return fmt.Errorf("%s: an %s belongs to a project: put it under projects/<project>/%s/ and name its host with `hosts: [<host>]`", f.rel(p), ki.Kind, ki.Dir)
		}
		if !isProjectDir && scope != "shared" && len(doc.Hosts) > 0 {
			return fmt.Errorf("%s: hosts: is only allowed under shared/ and projects/ (this file already belongs to host %s)", f.rel(p), scope)
		}
		if ki.Kind != api.KindJail && (len(doc.Templates) > 0 || doc.Start || len(doc.After) > 0) {
			return fmt.Errorf("%s: templates, start and after apply to jails only", f.rel(p))
		}
		if doc.Build && ki.Kind != api.KindImage {
			return fmt.Errorf("%s: build applies to images only", f.rel(p))
		}
		if !ki.ProjectLevel && doc.Metadata.Project != "" {
			return fmt.Errorf("%s: %s is a host-level kind and has no project", f.rel(p), ki.Kind)
		}
		proj := ""
		if ki.ProjectLevel {
			proj = doc.Metadata.Project
			switch {
			case project != "" && proj != "" && proj != project:
				return fmt.Errorf("%s: metadata.project %q does not match the directory's project %q", f.rel(p), proj, project)
			case project != "":
				proj = project
			case proj == "":
				return fmt.Errorf("%s: a %s belongs to a project: put it under projects/<project>/%s/ or set metadata.project", f.rel(p), ki.Kind, ki.Dir)
			}
			if err := model.CheckSimpleName(proj); err != nil {
				return fmt.Errorf("%s: project: %w", f.rel(p), err)
			}
		}
		o := &Object{
			Kind: ki.Kind, Name: doc.Metadata.Name, Project: proj, Labels: doc.Metadata.Labels, Origin: f.rel(p),
			Scope: scope, Start: doc.Start, Build: doc.Build, Templates: doc.Templates, hostRefs: doc.Hosts,
		}
		raw := doc.Spec
		if ki.Kind == api.KindJail {
			raw, o.After, o.Profiles, o.Provenance, err = f.expandJail(p, doc, proj)
			if err != nil {
				return err
			}
		}
		spec, err := model.DecodeSpec(ki.Kind, raw)
		if err != nil {
			return fmt.Errorf("%s: spec: %w", f.rel(p), err)
		}
		if as, ok := spec.(model.AppAccessSpec); ok {
			if err := as.Validate(); err != nil {
				return fmt.Errorf("%s: spec: %w", f.rel(p), err)
			}
		}
		o.Spec = spec
		if js, ok := spec.(api.JailSpec); ok {
			o.SecretRefs = secretRefs(js)
		}
		f.Objects = append(f.Objects, o)
	}
	return nil
}

func secretRefs(js api.JailSpec) []string {
	var out []string
	for _, v := range js.Env {
		if n, ok := strings.CutPrefix(v, SecretPrefix); ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// profileFor finds a profile: the jail's project first, then shared.
func (f *Fleet) profileFor(project, name string) *Profile {
	if d := f.Projects[project]; d != nil {
		if p := d.Profiles[name]; p != nil {
			return p
		}
	}
	return f.Profiles[name]
}

// expandJail builds the jail's raw spec: templates in order, then profiles in
// order (later overrides earlier, device by device), then the jail's own keys.
// The profiles key is removed from the result; sync sends the expanded spec.
// Hooks are the templates' then the jail's own. Provenance records, per
// top-level key, the last source that set it.
func (f *Fleet) expandJail(p string, doc *model.File, project string) (map[string]any, []model.Hook, []string, map[string]string, error) {
	merged := map[string]any{}
	prov := map[string]string{}
	apply := func(src map[string]any, label string) {
		merged = model.MergeSpec(merged, model.CloneMap(src))
		for k := range src {
			prov[k] = label
		}
	}
	var hooks []model.Hook
	for _, tn := range doc.Templates {
		t, ok := f.Templates[tn]
		if !ok {
			return nil, nil, nil, nil, fmt.Errorf("%s: unknown template %q", f.rel(p), tn)
		}
		apply(t.Spec.Jail, "template "+tn)
		hooks = append(hooks, t.Spec.After...)
	}
	own := model.CloneMap(doc.Spec)
	var profiles []string
	if raw, ok := own["profiles"]; ok {
		list, _ := raw.([]any)
		for _, e := range list {
			n, _ := e.(string)
			if n == "" {
				return nil, nil, nil, nil, fmt.Errorf("%s: spec.profiles must be a list of profile names", f.rel(p))
			}
			profiles = append(profiles, n)
		}
		delete(own, "profiles")
	}
	for _, pn := range profiles {
		pr := f.profileFor(project, pn)
		if pr == nil {
			return nil, nil, nil, nil, fmt.Errorf("%s: unknown profile %q (not in profiles/ or projects/%s/profiles/)", f.rel(p), pn, project)
		}
		apply(pr.Spec, "profile "+pn)
	}
	apply(own, "the jail")
	model.StripAutoNames(merged)
	for i, h := range doc.After {
		if err := h.Validate(); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("%s: after[%d]: %w", f.rel(p), i, err)
		}
	}
	return merged, append(hooks, doc.After...), profiles, prov, nil
}

// resolveTargets expands host references and detects duplicate declarations.
func (f *Fleet) resolveTargets() error {
	// Every group must expand: that surfaces cycles and unknown members.
	for _, g := range f.GroupNames() {
		if _, err := f.ExpandHosts([]string{"@" + g}); err != nil {
			return fmt.Errorf("%s: %w", f.Groups[g].Origin, err)
		}
	}
	seen := map[string]map[Key]string{}
	for _, o := range f.Objects {
		if o.Kind != api.KindProject {
			switch {
			case strings.HasPrefix(o.Scope, "project:"):
				pdef := f.Projects[strings.TrimPrefix(o.Scope, "project:")]
				o.Hosts = pdef.Hosts
				if len(o.hostRefs) > 0 {
					hs, err := f.ExpandHosts(o.hostRefs)
					if err != nil {
						return fmt.Errorf("%s: hosts: %w", o.Origin, err)
					}
					o.Hosts = hs
				}
			case o.Scope != "shared":
				o.Hosts = []string{o.Scope}
			case len(o.hostRefs) == 0:
				o.Hosts = f.HostNames()
			default:
				hs, err := f.ExpandHosts(o.hostRefs)
				if err != nil {
					return fmt.Errorf("%s: hosts: %w", o.Origin, err)
				}
				o.Hosts = hs
			}
			if o.Kind == api.KindJail && len(o.Hosts) != 1 {
				return fmt.Errorf("%s: a jail is declared on exactly one named host (got %d); give `hosts:` one host", o.Origin, len(o.Hosts))
			}
			if (o.Kind == model.KindApp || o.Kind == api.KindAppAccess) && len(o.Hosts) != 1 {
				return fmt.Errorf("%s: an %s is declared on exactly one named host (got %d); give `hosts:` one host", o.Origin, o.Kind, len(o.Hosts))
			}
			if o.Project != "" {
				pdef := f.Projects[o.Project]
				if pdef == nil {
					return fmt.Errorf("%s: project %q is not defined (projects/%s.yaml)", o.Origin, o.Project, o.Project)
				}
				for _, h := range o.Hosts {
					if !slices.Contains(pdef.Hosts, h) {
						return fmt.Errorf("%s: host %s is not one of project %s's hosts %v", o.Origin, h, o.Project, pdef.Hosts)
					}
				}
			}
		}
		for _, h := range o.Hosts {
			if seen[h] == nil {
				seen[h] = map[Key]string{}
			}
			k := o.Key()
			if prev, dup := seen[h][k]; dup {
				return fmt.Errorf("duplicate %s %q on host %s: declared in %s and in %s", o.Kind, o.Name, h, prev, o.Origin)
			}
			seen[h][k] = o.Origin
		}
	}
	return nil
}

// ExpandHosts turns host references into a sorted, de-duplicated host list.
// A reference is a host name or @group. Groups may contain other groups;
// a cycle is an error that shows the whole path.
func (f *Fleet) ExpandHosts(refs []string) ([]string, error) {
	set := map[string]bool{}
	for _, r := range refs {
		if err := f.expandRef(strings.TrimSpace(r), nil, set); err != nil {
			return nil, err
		}
	}
	return sortedKeys(set), nil
}

func (f *Fleet) expandRef(ref string, stack []string, out map[string]bool) error {
	if ref == "" {
		return errors.New("empty host reference")
	}
	name, isGroup := strings.CutPrefix(ref, "@")
	if !isGroup {
		if _, ok := f.Hosts[ref]; !ok {
			return fmt.Errorf("unknown host %q", ref)
		}
		out[ref] = true
		return nil
	}
	if i := slices.Index(stack, name); i >= 0 {
		path := append(slices.Clone(stack[i:]), name)
		return fmt.Errorf("group cycle: @%s", strings.Join(path, " -> @"))
	}
	g, ok := f.Groups[name]
	if !ok {
		return fmt.Errorf("unknown group @%s", name)
	}
	stack = append(slices.Clone(stack), name)
	for _, m := range g.Spec.Members {
		if err := f.expandRef(strings.TrimSpace(m), stack, out); err != nil {
			return err
		}
	}
	if len(g.Spec.Selector) > 0 {
		for hn, h := range f.Hosts {
			if labelsMatch(h.Labels, g.Spec.Selector) {
				out[hn] = true
			}
		}
	}
	return nil
}

// LabelsMatch reports whether labels contain every selector pair.
func LabelsMatch(labels, selector map[string]string) bool { return labelsMatch(labels, selector) }

func labelsMatch(labels, sel map[string]string) bool {
	for k, v := range sel {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	return true
}

// ProjectNames returns the sorted names of the projects the repository defines.
func (f *Fleet) ProjectNames() []string { return sortedKeys(f.Projects) }

// loadRemote reads the public part of hosts/<host>/remote.sops.yaml and checks it
// against host.yaml. Nothing is decrypted: the url and the pinned fingerprint
// are plaintext, and the certificate and key must be SOPS ciphertext.
func (f *Fleet) loadRemote(host string, spec model.HostSpec) error {
	p := vault.RemotePath(f.Path, host)
	raw, err := readFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	rel := vault.RemoteRel(host)
	if !vault.IsEncrypted(raw) {
		return fmt.Errorf("%s: the file is not SOPS-encrypted; it holds a private key", rel)
	}
	r, err := vault.RemoteStructure(f.Path, host)
	if err != nil {
		return err
	}
	for name, v := range map[string]string{"client_cert": r.ClientCert, "client_key": r.ClientKey} {
		if !strings.HasPrefix(v, "ENC[") {
			return fmt.Errorf("%s: %s is not encrypted (the policy must encrypt client_cert and client_key)", rel, name)
		}
	}
	r.ServerFingerprint = vault.NormalizeFingerprint(r.ServerFingerprint)
	chk := *r
	chk.ClientCert, chk.ClientKey = "", ""
	if !strings.HasPrefix(chk.URL, "https://") {
		return fmt.Errorf("%s: url %q must start with https://", rel, chk.URL)
	}
	if b, err := hex.DecodeString(chk.ServerFingerprint); err != nil || len(b) != 32 {
		return fmt.Errorf("%s: server_fingerprint must be a hex SHA-256", rel)
	}
	if spec.ViaHub || spec.Socket != "" {
		return fmt.Errorf("%s: a host reached through a hub or a socket has no remote file", rel)
	}
	if spec.URL != "" && spec.URL != r.URL {
		return fmt.Errorf("%s: url %q differs from host.yaml (%q); state it once", rel, r.URL, spec.URL)
	}
	if spec.Fingerprint != "" && vault.NormalizeFingerprint(spec.Fingerprint) != r.ServerFingerprint {
		return fmt.Errorf("%s: server_fingerprint differs from host.yaml; state it once", rel)
	}
	f.Remotes[host] = r
	return nil
}
