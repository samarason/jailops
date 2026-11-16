// Package apps reads the application catalog (docs/apps.md): one strict YAML
// definition per file in a directory the jailops-apps package installs. The
// daemon reads local files only and never fetches anything; the package's
// signature is the root of trust. A definition that fails to parse or to
// validate is listed as invalid with the reason and is never installed.
package apps

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// DefaultDir is where the jailops-apps package installs the definitions.
const DefaultDir = "/usr/local/share/jailops/apps"

// Bounds of a definition.
const (
	MaxFileBytes = 256 << 10
	MaxIconBytes = 64 << 10
	maxTitle     = 80
	maxSummary   = 140
	maxText      = 2000
	maxShort     = 140
	maxPath      = 1024
	maxSetup     = 32
	maxArgv      = 64
	maxArg       = 1024
	maxRCValue   = 1024
	maxWait      = 300
)

// MaxDefinitions bounds the definitions one listing reads.
const MaxDefinitions = 512

// Entry is one file of the catalog. Err is set when the definition is
// invalid; App then holds what could be read, and Summary names the file.
type Entry struct {
	// Name is the app name: the file name without .yaml.
	Name string
	// File is the file name in the catalog directory.
	File string
	// Hash is "sha256:<hex>" of the file.
	Hash string
	App  api.App
	// Icon is the icon as a data URI; empty without one.
	Icon string
	Err  error
	// Source is the directory the entry was read from (LoadAll, FindAll).
	Source api.AppSource
	// Overrides is AppSourceCatalog for a local entry that hides a packaged one.
	Overrides api.AppSource
}

// Summary is the entry as the list reports it.
func (e Entry) Summary() api.AppSummary {
	s := api.AppSummary{Name: e.Name, Valid: e.Err == nil, Source: e.Source, Overrides: e.Overrides}
	if e.Err != nil {
		s.Error = e.Err.Error()
	}
	if e.Err == nil || e.App.Name == e.Name {
		s.Title, s.Summary, s.Category = e.App.Title, e.App.Summary, e.App.Category
		if len(e.App.Packages) > 0 {
			s.Version = e.App.Packages[0].Version
		}
	}
	return s
}

// Detail is the entry as GET /api/v1/apps/<name> reports it.
func (e Entry) Detail() api.AppDetail {
	return api.AppDetail{Definition: e.App, Hash: e.Hash, File: e.File, Icon: e.Icon, Source: e.Source, Overrides: e.Overrides}
}

// Load reads the *.yaml of dir, sorted by name, without their icons (Find
// reads the icon of one). A missing directory is an empty catalog. A file
// that cannot be read or is invalid is an Entry with Err; the others are
// unaffected. At most MaxDefinitions files are read; the first one left out
// is listed as invalid, once, to say so. Only the directory itself failing
// to be read (other than not existing) is an error.
func Load(dir string) ([]Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("apps: %w", err)
	}
	var out []Entry
	for _, de := range des {
		name := de.Name()
		if !strings.HasSuffix(name, ".yaml") || strings.HasPrefix(name, ".") {
			continue
		}
		if len(out) == MaxDefinitions {
			out = append(out, Entry{Name: strings.TrimSuffix(name, ".yaml"), File: name,
				Err: fmt.Errorf("catalog has too many definitions: at most %d are read, this one and the ones after it are not", MaxDefinitions)})
			break
		}
		out = append(out, load(dir, name))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Find reads the definition of one name, with its icon.
func Find(dir, name string) (Entry, bool, error) {
	if validate.Name("name", name) != nil {
		return Entry{}, false, nil
	}
	if _, err := os.Lstat(filepath.Join(dir, name+".yaml")); errors.Is(err, os.ErrNotExist) {
		return Entry{}, false, nil
	}
	e := load(dir, name+".yaml")
	if e.Err == nil && e.App.Icon != "" {
		e.Icon, e.Err = loadIcon(dir, e.App.Icon)
	}
	return e, true, nil
}

func load(dir, file string) Entry {
	e := Entry{Name: strings.TrimSuffix(file, ".yaml"), File: file}
	path := filepath.Join(dir, file)
	fi, err := os.Lstat(path)
	if err != nil {
		e.Err = err
		return e
	}
	if !fi.Mode().IsRegular() {
		e.Err = fmt.Errorf("%s is not a regular file (a symbolic link is refused)", file)
		return e
	}
	data, err := readBounded(path, MaxFileBytes)
	if err != nil {
		e.Err = err
		return e
	}
	sum := sha256.Sum256(data)
	e.Hash = "sha256:" + hex.EncodeToString(sum[:])
	e.App, e.Err = Parse(e.Name, data)
	return e
}

// readBounded reads a file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

// loadIcon reads an icon file next to a definition as a data URI.
func loadIcon(dir, name string) (string, error) {
	path := filepath.Join(dir, name)
	fi, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("icon: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("icon %s is not a regular file", name)
	}
	data, err := readBounded(path, MaxIconBytes)
	if err != nil {
		return "", fmt.Errorf("icon: %w", err)
	}
	mime := "image/png"
	if strings.HasSuffix(name, ".svg") {
		mime = "image/svg+xml"
		if !bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n\xef\xbb\xbf"), []byte("<")) {
			return "", fmt.Errorf("icon %s is not an SVG document", name)
		}
	} else if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return "", fmt.Errorf("icon %s is not a PNG image", name)
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// Parse decodes one definition (unknown keys are errors), fills the
// defaults and validates it. name is the file name without .yaml, which
// the definition's name must equal.
func Parse(name string, data []byte) (api.App, error) {
	var app api.App
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&app); err != nil {
		if errors.Is(err, io.EOF) {
			return app, invalid("", "the definition is empty")
		}
		return app, invalid("", "%v", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var more struct{}
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return app, invalid("", "a definition is one YAML document")
	}
	if err := Validate(&app); err != nil {
		return app, err
	}
	if app.Name != name {
		return app, invalid("name", "name %q does not match the file name %s.yaml", app.Name, name)
	}
	return app, nil
}

func invalid(field, format string, args ...any) error {
	if field == "" {
		return api.Errorf(api.CodeInvalid, format, args...)
	}
	return validate.Invalid(field, field+": "+format, args...)
}

var (
	pkgRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)
	versionRE = regexp.MustCompile(`^[0-9][A-Za-z0-9._,+-]{0,63}$`)
	rcNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	rcKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	iconRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}\.(png|svg)$`)
	releaseRE = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})$`)
	cpuRE     = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,2})?$`)
)

// Validate checks a definition and fills its defaults (package repo,
// port protocol, service start, health wait and status).
func Validate(app *api.App) error {
	if app.Version != 1 {
		return invalid("version", "must be 1")
	}
	if err := validate.Name("name", app.Name); err != nil {
		return err
	}
	if err := line("title", app.Title, maxTitle, true); err != nil {
		return err
	}
	if err := line("summary", app.Summary, maxSummary, true); err != nil {
		return err
	}
	if err := text("description", app.Description, maxText); err != nil {
		return err
	}
	if !slices.Contains(api.AppCategories, app.Category) {
		return invalid("category", "%q is not one of %s", app.Category, joinCategories())
	}
	if app.StopTimeout < 0 || app.StopTimeout > api.MaxStopTimeout {
		return invalid("stop_timeout", "must be between 0 and %d seconds", api.MaxStopTimeout)
	}
	if app.Homepage != "" {
		u, err := url.Parse(app.Homepage)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return invalid("homepage", "%q must be an https URL", app.Homepage)
		}
	}
	if err := line("license", app.License, 64, false); err != nil {
		return err
	}
	if app.Icon != "" && !iconRE.MatchString(app.Icon) {
		return invalid("icon", "%q must be the name of a .png or .svg file next to the definition", app.Icon)
	}
	if err := validateImage(app.Image); err != nil {
		return err
	}
	if err := validatePackages(app.Packages); err != nil {
		return err
	}
	if err := validateServices(app.Services); err != nil {
		return err
	}
	if err := validatePorts(app.Ports); err != nil {
		return err
	}
	if err := CheckPersistent(*app, PersistentPaths); err != nil {
		return err
	}
	if err := validateData(app.Data); err != nil {
		return err
	}
	if err := validateConfig(app.Config, app.Services); err != nil {
		return err
	}
	if err := validateLogs(app.Logs); err != nil {
		return err
	}
	if err := validateSetup(app.Setup); err != nil {
		return err
	}
	if err := validateHealth(app.Health); err != nil {
		return err
	}
	if err := validateResources(app.Resources); err != nil {
		return err
	}
	if err := validateAccess(app); err != nil {
		return err
	}
	return text("notes", app.Notes, maxText)
}

func joinCategories() string {
	var l []string
	for _, c := range api.AppCategories {
		l = append(l, string(c))
	}
	return strings.Join(l, ", ")
}

// line checks a single line of printable text.
func line(field, s string, limit int, required bool) error {
	if s == "" {
		if required {
			return invalid(field, "is required")
		}
		return nil
	}
	if len(s) > limit {
		return invalid(field, "is longer than %d characters", limit)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return invalid(field, "holds a control or non-printable character")
		}
	}
	if strings.TrimSpace(s) != s {
		return invalid(field, "starts or ends with white space")
	}
	return nil
}

// text checks plain text: printable characters and new lines.
func text(field, s string, limit int) error {
	if len(s) > limit {
		return invalid(field, "is longer than %d characters", limit)
	}
	for _, r := range s {
		if r != '\n' && !unicode.IsPrint(r) {
			return invalid(field, "holds a control or non-printable character")
		}
	}
	return nil
}

func validateImage(im api.AppImage) error {
	if im.OS != "freebsd" {
		return invalid("image.os", "must be freebsd")
	}
	m := releaseRE.FindStringSubmatch(im.ReleaseMin)
	if m == nil {
		return invalid("image.release_min", "%q must be a release such as 15.1", im.ReleaseMin)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 15 || (major == 15 && minor < 1) {
		return invalid("image.release_min", "%s is older than 15.1, the oldest release JailOps runs on", im.ReleaseMin)
	}
	return nil
}

func validatePackages(pkgs []api.AppPackage) error {
	if len(pkgs) == 0 {
		return invalid("packages", "at least one package is required")
	}
	seen := map[string]bool{}
	for i := range pkgs {
		p := &pkgs[i]
		f := fmt.Sprintf("packages[%d]", i)
		if !pkgRE.MatchString(p.Name) {
			return invalid(f+".name", "%q is not a package name", p.Name)
		}
		if seen[p.Name] {
			return invalid(f+".name", "%q is listed twice", p.Name)
		}
		seen[p.Name] = true
		switch p.Repo {
		case "":
			p.Repo = "ports"
		case "ports", "jailops":
		default:
			return invalid(f+".repo", "%q must be ports or jailops", p.Repo)
		}
		if p.Version != "" && !versionRE.MatchString(p.Version) {
			return invalid(f+".version", "%q is not a package version", p.Version)
		}
	}
	return nil
}

// rcName is a service name as rc.conf spells it: "-" and "." become "_".
func rcName(service string) string { return strings.NewReplacer(".", "_", "-", "_").Replace(service) }

func validateServices(svcs []api.AppService) error {
	seen := map[string]string{} // rc.conf name -> service
	for i := range svcs {
		s := &svcs[i]
		f := fmt.Sprintf("services[%d]", i)
		if !rcNameRE.MatchString(s.Name) {
			return invalid(f+".name", "%q is not an rc.d service name", s.Name)
		}
		if o, ok := seen[rcName(s.Name)]; ok {
			if o == s.Name {
				return invalid(f+".name", "%q is listed twice", s.Name)
			}
			return invalid(f+".name", "%q and %q are the same name in rc.conf (%s)", o, s.Name, rcName(s.Name))
		}
		seen[rcName(s.Name)] = s.Name
	}
	for i := range svcs {
		s := &svcs[i]
		f := fmt.Sprintf("services[%d]", i)
		for _, k := range sortedKeys(s.RC) {
			v := s.RC[k]
			if !rcKeyRE.MatchString(k) {
				return invalid(f+".rc", "%q is not an rc.conf variable name", k)
			}
			if n, ok := strings.CutSuffix(k, "_enable"); ok && seen[n] != "" {
				return invalid(f+".rc", "%s is written by the installer; leave it out", k)
			}
			if len(v) > maxRCValue {
				return invalid(f+".rc", "%s is longer than %d characters", k, maxRCValue)
			}
			for _, r := range v {
				if !unicode.IsPrint(r) {
					return invalid(f+".rc", "%s holds a control or non-printable character", k)
				}
			}
		}
		if s.Start == nil {
			t := true
			s.Start = &t
		}
	}
	return nil
}

func validatePorts(ports []api.AppPort) error {
	seen := map[string]bool{}
	names := map[string]bool{}
	for i := range ports {
		p := &ports[i]
		f := fmt.Sprintf("ports[%d]", i)
		if !api.IsName(p.Name, 32) {
			return invalid(f+".name", "%q must match ^[a-z][a-z0-9-]{0,31}$", p.Name)
		}
		if names[p.Name] {
			return invalid(f+".name", "%q is listed twice", p.Name)
		}
		names[p.Name] = true
		if p.Port < 1 || p.Port > 65535 {
			return invalid(f+".port", "%d is not a port", p.Port)
		}
		switch p.Proto {
		case "":
			p.Proto = "tcp"
		case "tcp", "udp":
		default:
			return invalid(f+".proto", "%q must be tcp or udp", p.Proto)
		}
		key := strconv.Itoa(p.Port) + "/" + p.Proto
		if seen[key] {
			return invalid(f+".port", "%s is listed twice", key)
		}
		seen[key] = true
		if err := line(f+".description", p.Description, maxShort, false); err != nil {
			return err
		}
	}
	return nil
}

// systemPrefixes are never data, configuration or log paths of an
// application: they belong to the base system or hold the packages' own
// files.
var systemPrefixes = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/libexec", "/proc", "/rescue", "/sbin", "/sys", "/tmp",
	"/usr/bin", "/usr/include", "/usr/lib", "/usr/lib32", "/usr/libdata", "/usr/libexec", "/usr/obj", "/usr/sbin",
	"/usr/share", "/usr/src", "/usr/tests",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib", "/usr/local/lib32", "/usr/local/libexec", "/usr/local/libdata",
	"/usr/local/include", "/usr/local/share", "/usr/local/man", "/usr/local/info", "/usr/local/etc/rc.d", "/usr/local/etc/pkg",
	"/var/run", "/var/tmp", "/var/empty",
}

// PersistentPaths are the persistent datasets of every jail in the default
// layout (lifecycle.DefaultPersistent). A data or config path is never one
// of them: a volume there would hide the jail's own dataset.
var PersistentPaths = []string{"/etc", "/usr/local", "/var/db", "/var/log", "/var/mail", "/var/spool", "/home", "/root"}

// CheckPersistent refuses data and config paths equal to one of persistent;
// the installer checks the host's configured list with it too.
func CheckPersistent(app api.App, persistent []string) error {
	for i, d := range app.Data {
		if slices.Contains(persistent, d.Path) {
			return persistentErr(fmt.Sprintf("data[%d].path", i), d.Path)
		}
	}
	for i, c := range app.Config {
		if slices.Contains(persistent, c.Path) {
			return persistentErr(fmt.Sprintf("config[%d].path", i), c.Path)
		}
	}
	return nil
}

func persistentErr(field, p string) error {
	return invalid(field, "%s is a persistent dataset of every jail, not a path of the application; name a directory below it", p)
}

// dataParents are the directories a data path must lie below (not be).
var dataParents = []string{"/var", "/usr/local", "/usr/local/etc", "/home"}

// appPath checks a path of the application: absolute, clean, not in the base
// system, and below one of the parents.
func appPath(field, p string, parents []string) error {
	if len(p) > maxPath {
		return invalid(field, "is longer than %d characters", maxPath)
	}
	if err := validate.AbsPath(field, p); err != nil {
		return err
	}
	for _, s := range systemPrefixes {
		if p == s || strings.HasPrefix(p, s+"/") {
			return invalid(field, "%s is a path of the base system or of the packages, not of the application", p)
		}
	}
	for _, d := range parents {
		if strings.HasPrefix(p, d+"/") {
			return nil
		}
	}
	return invalid(field, "%s must lie below one of %s", p, strings.Join(parents, ", "))
}

func validateData(data []api.AppPath) error {
	for i := range data {
		d := data[i]
		f := fmt.Sprintf("data[%d]", i)
		if err := appPath(f+".path", d.Path, dataParents); err != nil {
			return err
		}
		for j := range i {
			o := data[j].Path
			if d.Path == o || strings.HasPrefix(d.Path, o+"/") || strings.HasPrefix(o, d.Path+"/") {
				return invalid(f+".path", "%s overlaps %s; each data path is its own dataset", d.Path, o)
			}
		}
		if err := line(f+".description", d.Description, maxShort, false); err != nil {
			return err
		}
	}
	return nil
}

func validateConfig(cfgs []api.AppConfig, svcs []api.AppService) error {
	seen := map[string]bool{}
	for i, c := range cfgs {
		f := fmt.Sprintf("config[%d]", i)
		if err := appPath(f+".path", c.Path, dataParents); err != nil {
			return err
		}
		if seen[c.Path] {
			return invalid(f+".path", "%s is listed twice", c.Path)
		}
		seen[c.Path] = true
		if err := line(f+".description", c.Description, maxShort, false); err != nil {
			return err
		}
		if c.Restart != "" && !slices.ContainsFunc(svcs, func(s api.AppService) bool { return s.Name == c.Restart }) {
			return invalid(f+".restart", "%q is not one of the services", c.Restart)
		}
	}
	return nil
}

var logParents = []string{"/var/log", "/var/db", "/usr/local"}

func validateLogs(logs []api.AppLog) error {
	names := map[string]bool{}
	for i, l := range logs {
		f := fmt.Sprintf("logs[%d]", i)
		if !api.IsName(l.Name, 32) {
			return invalid(f+".name", "%q must match ^[a-z][a-z0-9-]{0,31}$", l.Name)
		}
		if names[l.Name] {
			return invalid(f+".name", "%q is listed twice", l.Name)
		}
		names[l.Name] = true
		if err := appPath(f+".path", l.Path, logParents); err != nil {
			return err
		}
		if err := line(f+".description", l.Description, maxShort, false); err != nil {
			return err
		}
	}
	return nil
}

func validateArgv(field string, argv []string) error {
	if len(argv) == 0 {
		return invalid(field, "is empty")
	}
	if len(argv) > maxArgv {
		return invalid(field, "has more than %d arguments", maxArgv)
	}
	if !strings.HasPrefix(argv[0], "/") {
		return invalid(field, "%q must be an absolute path (no search path, no shell)", argv[0])
	}
	if err := validate.AbsPath(field, argv[0]); err != nil {
		return err
	}
	for _, a := range argv {
		if len(a) > maxArg {
			return invalid(field, "an argument is longer than %d characters", maxArg)
		}
		for _, r := range a {
			if r == 0 || (unicode.IsControl(r) && r != '\t') {
				return invalid(field, "an argument holds a control character")
			}
		}
	}
	return nil
}

func validateSetup(setup [][]string) error {
	if len(setup) > maxSetup {
		return invalid("setup", "has more than %d commands", maxSetup)
	}
	for i, argv := range setup {
		if err := validateArgv(fmt.Sprintf("setup[%d]", i), argv); err != nil {
			return err
		}
	}
	return nil
}

func validateHealth(h *api.AppHealth) error {
	if h == nil {
		return nil
	}
	n := 0
	if h.TCP != 0 {
		n++
		if h.TCP < 1 || h.TCP > 65535 {
			return invalid("health.tcp", "%d is not a port", h.TCP)
		}
	}
	if h.HTTP != nil {
		n++
		if h.HTTP.Port < 1 || h.HTTP.Port > 65535 {
			return invalid("health.http.port", "%d is not a port", h.HTTP.Port)
		}
		if !strings.HasPrefix(h.HTTP.Path, "/") || len(h.HTTP.Path) > maxPath || strings.ContainsAny(h.HTTP.Path, " \t\r\n#") {
			return invalid("health.http.path", "%q must be an absolute request path", h.HTTP.Path)
		}
		switch {
		case h.HTTP.Status == 0:
			h.HTTP.Status = 200
		case h.HTTP.Status < 100 || h.HTTP.Status > 599:
			return invalid("health.http.status", "%d is not an HTTP status", h.HTTP.Status)
		}
	}
	if len(h.Exec) > 0 {
		n++
		if err := validateArgv("health.exec", h.Exec); err != nil {
			return err
		}
	}
	if n != 1 {
		return invalid("health", "exactly one of tcp, http and exec is required")
	}
	switch {
	case h.WaitSeconds == 0:
		h.WaitSeconds = 60
	case h.WaitSeconds < 0 || h.WaitSeconds > maxWait:
		return invalid("health.wait_seconds", "must be between 1 and %d", maxWait)
	}
	return nil
}

func validateResources(r api.AppResources) error {
	for field, v := range map[string]string{"resources.memory": r.Memory, "resources.disk": r.Disk} {
		if v == "" {
			continue
		}
		if _, err := validate.ParseSize(v); err != nil {
			return invalid(field, "%q is not a size such as 512M or 10G", v)
		}
	}
	if r.CPU != "" && !cpuRE.MatchString(r.CPU) {
		return invalid("resources.cpu", "%q is not a number of CPUs", r.CPU)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
