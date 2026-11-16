package imagegen

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/internal/render"
	"jailops.net/jailops/sdk/api"
)

// Build is the context a Source gets when it plans a generation.
type Build struct {
	M      *Manager
	Image  string
	Spec   api.ImageSpec
	Number int
	Parent int    // 0 when built from the source
	Root   string // mountpoint of the staging dataset
	Work   string // scratch directory for this build
}

// Source knows how to put a base system into a staging root, how to upgrade
// an existing one and how to read the installed package set. Everything that
// depends on FreeBSD, Alpine or Debian tooling lives behind this interface and
// is UNVERIFIED until run on a FreeBSD host.
type Source interface {
	Type() string
	CheckSpec(api.ImageSpec) error
	// Install plans a fresh install into an empty root.
	Install(b *Build) ([]plan.Step, error)
	// Upgrade plans an upgrade of the parent generation's packages in the clone.
	Upgrade(b *Build) ([]plan.Step, error)
	// Check plans source specific validation after install or upgrade.
	Check(b *Build) []plan.Step
	// Packages reads the installed package set.
	Packages(ctx context.Context, b *Build) ([]Package, error)
	// RequiredPaths must exist in the root of a valid generation.
	RequiredPaths() []string
}

// DefaultSources returns the built-in sources.
func DefaultSources() map[string]Source {
	return map[string]Source{
		"pkgbase":     PkgBase{},
		"minirootfs":  Minirootfs{},
		"debootstrap": Debootstrap{},
	}
}

func quote(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"'$\\*?&;|<>(){}[]") {
			parts[i] = strconv.Quote(a)
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = "..." + s[len(s)-400:]
	}
	return s
}

func (m *Manager) execStep(name string, argv []string) plan.Step {
	return plan.Step{
		Name: name, Describe: quote(argv),
		Do: func(ctx context.Context) error {
			out, err := m.Exec.Run(ctx, argv)
			if err != nil {
				return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(out))
			}
			return nil
		},
	}
}

func (m *Manager) cleanWork(work string) plan.Step {
	return plan.Step{
		Name: "clean-work", Describe: "remove " + work,
		Do:   func(ctx context.Context) error { return m.Files.RemoveAll(ctx, work) },
		Undo: func(ctx context.Context) error { return m.Files.RemoveAll(ctx, work) },
	}
}

func confValue(name, v string) error {
	if strings.ContainsAny(v, "\"\\\n\r\x00") {
		return api.Errorf(api.CodeInvalid, "%s contains a character that is not allowed in a repository configuration", name)
	}
	return nil
}

// ---- pkgbase (FreeBSD) ----

// PkgBase builds FreeBSD generations from pkgbase packages with pkg(8) -r.
// UNVERIFIED: every pkg invocation below, including `-r`, `-o ABI=`,
// `-o REPOS_DIR=` and the pkgbase repository layout, is FreeBSD knowledge that
// has not run here (design section 16, item 2).
type PkgBase struct{}

func (PkgBase) Type() string { return "pkgbase" }

func parseRelease(rel string) (major, minor int, err error) {
	v, _, _ := strings.Cut(rel, "-")
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, fmt.Errorf("release %q is not <major>.<minor>-<type>", rel)
	}
	if major, err = strconv.Atoi(a); err == nil {
		minor, err = strconv.Atoi(b)
	}
	return
}

func (PkgBase) abi(spec api.ImageSpec) (string, error) {
	major, _, err := parseRelease(spec.Release)
	if err != nil {
		return "", api.Errorf(api.CodeInvalid, "%v", err)
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "aarch64"}[spec.Arch]
	if arch == "" {
		return "", api.Errorf(api.CodeInvalid, "unsupported architecture %q", spec.Arch)
	}
	return fmt.Sprintf("FreeBSD:%d:%s", major, arch), nil
}

func (p PkgBase) CheckSpec(s api.ImageSpec) error {
	if s.OS != api.OSFreeBSD {
		return api.Errorf(api.CodeInvalid, "pkgbase images are FreeBSD images")
	}
	if _, err := p.abi(s); err != nil {
		return err
	}
	for _, v := range append([]string{s.Source.Repo, s.Source.Keys}, s.Source.Sets...) {
		if err := confValue("source", v); err != nil {
			return err
		}
	}
	return nil
}

func (PkgBase) RequiredPaths() []string { return []string{"/bin/sh", "/libexec/ld-elf.so.1"} }

func (PkgBase) sets(s api.ImageSpec) []string {
	if len(s.Source.Sets) > 0 {
		return s.Source.Sets
	}
	// The minimal jail set (35 packages) is not enough for software from the FreeBSD ports: a package is built against
	// a complete base system and does not name the base libraries it needs (PostgreSQL stopped at "libexecinfo.so.1 not
	// found"), and administrators expect sysrc(8), ssh, ee, ntp, ftp and bmake in a jail. The optional jail set
	// (about 105 packages, 160 MiB) brings them; the development set (compiler and headers, 570 MiB) is left out: an
	// image that builds software names FreeBSD-set-devel in source.sets.
	return []string{"FreeBSD-set-minimal-jail", "FreeBSD-set-optional-jail"}
}

// pkgArgv builds a `pkg -r <root>` argv with a private repository
// directory. The ABI comes from the host (`pkg config abi`, see abiStep);
// before that ran, the one derived from the spec stands in. Verified on
// FreeBSD 15.1 (prototype 2): -o IGNORE_OSVERSION=yes and -o ABI=<abi> are
// needed because the host's pkg judges the root, not itself.
func (p PkgBase) pkgArgv(b *Build, abi string, args ...string) []string {
	if abi == "" {
		abi, _ = p.abi(b.Spec)
	}
	base := []string{"pkg", "-r", b.Root, "-o", "ABI=" + abi, "-o", "REPOS_DIR=" + path.Join(b.Work, "repos"), "-o", "IGNORE_OSVERSION=yes", "-o", "PKG_CACHEDIR=" + b.M.Layout.PkgCache()}
	return append(base, args...)
}

// pkgRun is the handle the steps of one plan share: the ABI learned from
// the host.
type pkgRun struct {
	p   PkgBase
	b   *Build
	abi string
}

func (r *pkgRun) step(name string, args ...string) plan.Step {
	return plan.Step{
		Name: name, Describe: quote(r.p.pkgArgv(r.b, r.abi, args...)),
		Do: func(ctx context.Context) error {
			argv := r.p.pkgArgv(r.b, r.abi, args...)
			var out []byte
			var err error
			// A mirror that does not answer for a moment must not fail an image build: pkg keeps what it already
			// fetched in its cache, so a second try only asks for what is missing.
			for try := 0; ; try++ {
				if out, err = r.b.M.Exec.Run(ctx, argv); err == nil {
					return nil
				}
				if try >= fetchRetries || !transientFetch(out) {
					break
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(out))
				case <-time.After(fetchBackoff << try):
				}
			}
			return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(out))
		},
	}
}

var (
	// fetchRetries is how many more times a pkg step is tried when a mirror could not be reached.
	fetchRetries = 3
	// fetchBackoff is the wait before the first retry; it doubles each time.
	fetchBackoff = 5 * time.Second
)

// transientFetch says whether the output of a failed pkg run is a network failure that a retry can cure: a mirror
// that cannot be reached or answers with a server error. A signature that does not match, a missing package or an
// unknown option are never retried.
func transientFetch(out []byte) bool {
	low := strings.ToLower(string(out))
	for _, m := range []string{
		"no route to host", "operation timed out", "connection timed out", "connection refused", "connection reset",
		"network is unreachable", "temporary failure in name resolution", "could not resolve", "service unavailable",
		"bad gateway", "gateway timeout", "http error 5", "502 ", "503 ", "504 ", "try again",
	} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// abiStep asks the host's pkg for its ABI. The answer replaces the one
// derived from the release when it looks like an ABI string.
func (r *pkgRun) abiStep() plan.Step {
	return plan.Step{
		Name: "pkg-abi", Describe: "pkg config abi",
		Do: func(ctx context.Context) error {
			out, err := r.b.M.Exec.Run(ctx, []string{"pkg", "config", "abi"})
			if err != nil {
				return fmt.Errorf("pkg config abi: %w: %s", err, tail(out))
			}
			if v := strings.TrimSpace(string(out)); strings.HasPrefix(v, "FreeBSD:") && !strings.ContainsAny(v, " \t\n\"'") {
				r.abi = v
			}
			return nil
		},
	}
}

// keysSteps copy the host's key directories into the root before the first
// `pkg -r`: an empty root cannot verify any repository until the keys are
// there (verified on FreeBSD 15.1).
func (p PkgBase) keysSteps(b *Build) []plan.Step {
	m := b.M
	return []plan.Step{
		{Name: "seed-keys", Describe: "copy the host's /usr/share/keys into " + path.Join(b.Root, "usr/share/keys"),
			Do: func(ctx context.Context) error { return m.Files.SeedKeys(ctx, b.Root) }},
	}
}

func isRelease(rel string) bool {
	return strings.Contains(strings.ToUpper(rel), "-RELEASE")
}

// repoConf writes the private repository file. ${ABI} and ${VERSION_MAJOR} are
// left for pkg to expand. A RELEASE reads base_release_<minor> with the minor
// of the image's release written out: pkg expands ${VERSION_MINOR} from the
// ABI it was given, which carries no minor, so it answered 0 and a 15.1 image
// was built from the 15.0 packages. Anything else (STABLE, CURRENT) reads
// base_latest.
func (p PkgBase) repoConf(b *Build) plan.Step {
	m := b.M
	file := path.Join(b.Work, "repos", "jailops.conf")
	url := b.Spec.Source.Repo
	keys := b.Spec.Source.Keys
	if url == "" {
		if isRelease(b.Spec.Release) {
			_, minor, err := parseRelease(b.Spec.Release)
			if err != nil {
				return plan.Step{Name: "write-repo-conf", Describe: "write the repository file",
					Do: func(context.Context) error { return api.Errorf(api.CodeInvalid, "%v", err) }}
			}
			url = fmt.Sprintf("pkg+https://pkg.FreeBSD.org/${ABI}/base_release_%d", minor)
		} else {
			// base_latest is signed with the key of the ports repositories, not the pkgbase release keys (verified on
			// 15.2-PRERELEASE: with pkgbase-15 pkg answers "No trusted public keys found")
			url = "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest"
			if keys == "" {
				keys = "/usr/share/keys/pkg"
			}
		}
	}
	if keys == "" {
		keys = "/usr/share/keys/pkgbase-${VERSION_MAJOR}"
	}
	mirror := ""
	if strings.HasPrefix(url, "pkg+") {
		mirror = "  mirror_type: \"srv\",\n"
	}
	body := fmt.Sprintf("jailops: {\n  url: \"%s\",\n%s  signature_type: \"fingerprints\",\n  fingerprints: \"%s\",\n  enabled: yes\n}\n", url, mirror, keys)
	return plan.Step{
		Name: "write-repo-conf", Describe: "write " + file + " (url " + url + ", fingerprints " + keys + ")",
		// Found on FreeBSD: the helper's atomic write does not create parent directories.
		Do: func(ctx context.Context) error {
			if err := m.Files.MkdirAll(ctx, path.Dir(file)); err != nil {
				return err
			}
			return m.Files.WriteAtomic(ctx, file, []byte(body))
		},
		Undo: func(ctx context.Context) error { return m.Files.RemoveAll(ctx, b.Work) },
	}
}

func (p PkgBase) Install(b *Build) ([]plan.Step, error) {
	r := &pkgRun{p: p, b: b}
	steps := append([]plan.Step{p.cacheStep(b), p.repoConf(b), r.abiStep()}, p.keysSteps(b)...)
	steps = append(steps,
		r.step("pkg-update", "update", "-f", "-r", "jailops"),
		r.step("pkg-install", append([]string{"install", "-y", "-r", "jailops"}, p.sets(b.Spec)...)...),
		r.step("pkg-clean", "clean", "-y"),
		p.rcConfStep(b))
	return steps, nil
}

// cacheStep creates the shared package cache dataset (Layout.CacheDS) when it is missing, and removes it again if
// this build made it and fails: a build leaves nothing behind, and the next one makes it anew.
func (PkgBase) cacheStep(b *Build) plan.Step {
	m := b.M
	ds := m.Layout.CacheDS()
	made := false
	return plan.Step{Name: "ensure-cache-dataset", Describe: "zfs create " + ds + " (the package cache, mounted at " + m.Layout.CacheMount() + ") if missing",
		Do: func(ctx context.Context) error {
			if ok, err := m.ZFS.Exists(ctx, ds); err != nil || ok {
				return err
			}
			made = true
			return m.ZFS.Create(ctx, ds, map[string]string{PropManaged: "on", PropKind: "cache", "mountpoint": m.Layout.CacheMount()})
		},
		Undo: func(ctx context.Context) error {
			if ok, err := m.ZFS.Exists(ctx, ds); !made || err != nil || !ok {
				return err
			}
			return m.ZFS.DestroyRecursive(ctx, ds)
		},
		UndoOnFail: true}
}

// jailRcConf is the /etc/rc.conf a new generation starts with (the base ships none): what a jail wants of rc
// whatever its network is. sendmail would start an MTA in every jail, syslogd would open a network socket, and a
// jail has nothing to clear in /tmp that the jail's own filesystem does not already start empty.
const jailRcConf = `# Defaults for a JailOps jail. Change them with sysrc(8); JailOps keeps its own settings in /etc/rc.conf.local.
sendmail_enable="NONE"
syslogd_flags="-ss"
`

// rcConfStep writes jailRcConf, unless the image already has an /etc/rc.conf.
func (PkgBase) rcConfStep(b *Build) plan.Step {
	m, dst := b.M, path.Join(b.Root, "etc/rc.conf")
	return plan.Step{Name: "write-rc-conf", Describe: "write " + dst + " (sendmail off, syslogd without a network socket) unless it exists",
		Do: func(ctx context.Context) error {
			if ok, err := m.Files.Exists(ctx, dst); err != nil || ok {
				return err
			}
			return m.Files.WriteAtomic(ctx, dst, []byte(jailRcConf))
		}}
}

func (p PkgBase) Upgrade(b *Build) ([]plan.Step, error) {
	r := &pkgRun{p: p, b: b}
	steps := append([]plan.Step{p.cacheStep(b), p.repoConf(b), r.abiStep()}, p.keysSteps(b)...)
	return append(steps,
		r.step("pkg-update", "update", "-f", "-r", "jailops"),
		r.step("pkg-upgrade", "upgrade", "-y", "-r", "jailops"),
		r.step("pkg-install", append([]string{"install", "-y", "-r", "jailops"}, p.sets(b.Spec)...)...),
		r.step("pkg-clean", "clean", "-y")), nil
}

func (p PkgBase) Check(b *Build) []plan.Step {
	return []plan.Step{b.M.execStep("pkg-check", p.pkgArgv(b, "", "check", "-d", "-a"))}
}

func (p PkgBase) Packages(ctx context.Context, b *Build) ([]Package, error) {
	out, err := b.M.Exec.Run(ctx, p.pkgArgv(b, "", "query", "%n %v"))
	if err != nil {
		return nil, fmt.Errorf("pkg query: %w: %s", err, tail(out))
	}
	return ParsePkgQuery(out)
}

// ---- Alpine minirootfs ----

// Minirootfs builds Alpine generations from the official minirootfs tarball.
//
// With ImageSpec.Release "3.22.1" the tarball is
// https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/<arch>/alpine-minirootfs-3.22.1-<arch>.tar.gz
// (arch x86_64 for amd64, aarch64 for arm64) and its digest comes from the
// .sha256 file next to it; with "3.22" the newest 3.22.x is looked up in
// latest-releases.yaml, which carries the digest. Source.Repo replaces the
// URL and then needs Source.Keys = "sha256:<hex>"; a pinned Keys always wins
// over the published digest. The download is checked before it is unpacked.
//
// apk does not exist on the FreeBSD host, so every apk command runs inside a
// short-lived build jail around the staging root (Linux mounts, a private
// devfs ruleset, kern.elf64.fallback_brand=3) with `jexec <jail> /sbin/apk`.
// Verified on FreeBSD 15.1 arm64: the layout, apk update and add, and the
// fallback brand. UNVERIFIED: the same driven from the host through the
// helper, and amd64.
type Minirootfs struct{}

func (Minirootfs) Type() string { return "minirootfs" }

// alpineMirror is the default mirror; repositories use https.
const alpineMirror = "https://dl-cdn.alpinelinux.org/alpine"

var alpineArch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}

func alpineVersionRE(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// alpineBranch is "3.22" for "3.22.1".
func alpineBranch(v string) string {
	p := strings.Split(strings.TrimPrefix(v, "v"), ".")
	return p[0] + "." + p[1]
}

func validSHA256(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (Minirootfs) CheckSpec(s api.ImageSpec) error {
	if s.OS != api.OSLinux {
		return api.Errorf(api.CodeInvalid, "minirootfs images are Linux images")
	}
	if alpineArch[s.Arch] == "" {
		return api.Errorf(api.CodeInvalid, "unsupported architecture %q (amd64 or arm64)", s.Arch)
	}
	if s.Source.Repo == "" {
		if !alpineVersionRE(strings.TrimPrefix(s.Release, "v")) {
			return api.Errorf(api.CodeInvalid, "an Alpine image needs release <major>.<minor> or <major>.<minor>.<patch>, for example 3.22.1")
		}
	} else {
		if !strings.HasPrefix(s.Source.Repo, "https://") {
			return api.Errorf(api.CodeInvalid, "minirootfs needs an https tarball URL in source.repo")
		}
		if !alpineVersionRE(strings.TrimPrefix(s.Release, "v")) {
			return api.Errorf(api.CodeInvalid, "an Alpine image needs its release (for example 3.22) for the package repositories")
		}
		if h := strings.TrimPrefix(s.Source.Keys, "sha256:"); h == s.Source.Keys || !validSHA256(h) {
			return api.Errorf(api.CodeInvalid, "a tarball from source.repo needs source.keys = sha256:<64 hex digits>")
		}
	}
	if s.Source.Keys != "" {
		if h := strings.TrimPrefix(s.Source.Keys, "sha256:"); h == s.Source.Keys || !validSHA256(h) {
			return api.Errorf(api.CodeInvalid, "minirootfs source.keys must be sha256:<64 lower-case hex digits>")
		}
	}
	for _, v := range append([]string{s.Source.Repo}, s.Source.Sets...) {
		if err := confValue("source", v); err != nil {
			return err
		}
	}
	for _, p := range s.Source.Sets {
		if p == "" || strings.HasPrefix(p, "-") || strings.ContainsAny(p, " \t/") {
			return api.Errorf(api.CodeInvalid, "invalid apk package name %q in source.sets", p)
		}
	}
	return nil
}

func (Minirootfs) RequiredPaths() []string { return []string{"/bin/busybox", "/lib/apk/db/installed"} }

// ParseLatestReleases finds the minirootfs entry for arch in an Alpine
// latest-releases.yaml (a list of mappings with "file:" and "sha256:").
func ParseLatestReleases(text, arch, branch string) (file, sum string, err error) {
	var cf, cs string
	flush := func() bool {
		return strings.HasPrefix(cf, "alpine-minirootfs-"+branch+".") && strings.HasSuffix(cf, "-"+arch+".tar.gz") && validSHA256(cs)
	}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "-") {
			if flush() {
				return cf, cs, nil
			}
			cf, cs = "", ""
			t = strings.TrimSpace(strings.TrimPrefix(t, "-"))
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), "\"'")
		switch strings.TrimSpace(k) {
		case "file":
			cf = v
		case "sha256":
			cs = v
		}
	}
	if flush() {
		return cf, cs, nil
	}
	return "", "", fmt.Errorf("no alpine-minirootfs %s entry for %s in latest-releases.yaml", branch, arch)
}

// alpineRun is the state the steps of one Alpine plan share.
type alpineRun struct {
	b       *Build
	m       *Manager
	arch    string
	branch  string
	url     string
	want    string // sha256 of the tarball
	tarball string
	jail    string
	ruleset int
	mounted []render.LinuxMount
	jailUp  bool
	rules   bool
}

func newAlpineRun(b *Build) *alpineRun {
	name := "jobuild-" + strings.NewReplacer(".", "-", "_", "-").Replace(b.Image) + "-g" + strconv.Itoa(b.Number)
	return &alpineRun{b: b, m: b.M, arch: alpineArch[b.Spec.Arch], branch: alpineBranch(b.Spec.Release),
		tarball: path.Join(b.Work, "rootfs.tar.gz"), jail: name}
}

func (a *alpineRun) fetch(name, url, dst string) plan.Step {
	return a.m.execStep(name, []string{"fetch", "-o", dst, url})
}

// fetchSteps download and verify the tarball.
func (a *alpineRun) fetchSteps() []plan.Step {
	b, m := a.b, a.m
	rel := strings.TrimPrefix(b.Spec.Release, "v")
	prep := plan.Step{Name: "prepare-work", Describe: "mkdir -p " + b.Work,
		Undo: func(ctx context.Context) error { return m.Files.RemoveAll(ctx, b.Work) },
		Do:   func(ctx context.Context) error { return m.Files.MkdirAll(ctx, b.Work) }}
	var out []plan.Step
	out = append(out, prep)
	pinned := strings.TrimPrefix(b.Spec.Source.Keys, "sha256:")
	if b.Spec.Source.Keys == "" {
		pinned = ""
	}
	switch {
	case b.Spec.Source.Repo != "":
		a.url, a.want = b.Spec.Source.Repo, pinned
	case strings.Count(rel, ".") == 2:
		a.url = fmt.Sprintf("%s/v%s/releases/%s/alpine-minirootfs-%s-%s.tar.gz", alpineMirror, a.branch, a.arch, rel, a.arch)
		a.want = pinned
		if pinned == "" {
			sumFile := path.Join(b.Work, "rootfs.tar.gz.sha256")
			out = append(out, a.fetch("fetch-digest", a.url+".sha256", sumFile), plan.Step{Name: "read-digest", Describe: "read " + sumFile,
				Do: func(ctx context.Context) error {
					d, err := m.Files.ReadFile(ctx, sumFile)
					if err != nil {
						return err
					}
					f := strings.Fields(string(d))
					if len(f) == 0 || !validSHA256(f[0]) {
						return api.Errorf(api.CodeInvalid, "the published digest %s is not a sha256", a.url+".sha256")
					}
					a.want = f[0]
					return nil
				}})
		}
	default:
		idx := path.Join(b.Work, "latest-releases.yaml")
		out = append(out, a.fetch("fetch-index", fmt.Sprintf("%s/v%s/releases/%s/latest-releases.yaml", alpineMirror, a.branch, a.arch), idx),
			plan.Step{Name: "resolve-release", Describe: "pick the newest " + a.branch + " minirootfs from latest-releases.yaml",
				Do: func(ctx context.Context) error {
					d, err := m.Files.ReadFile(ctx, idx)
					if err != nil {
						return err
					}
					file, sum, err := ParseLatestReleases(string(d), a.arch, a.branch)
					if err != nil {
						return api.Errorf(api.CodeInvalid, "%v", err)
					}
					a.url = fmt.Sprintf("%s/v%s/releases/%s/%s", alpineMirror, a.branch, a.arch, file)
					a.want = sum
					if pinned != "" {
						a.want = pinned
					}
					return nil
				}})
	}
	out = append(out, plan.Step{Name: "fetch", Describe: "fetch -o " + a.tarball + " <tarball url>",
		Do: func(ctx context.Context) error {
			argv := []string{"fetch", "-o", a.tarball, a.url}
			if o, err := m.Exec.Run(ctx, argv); err != nil {
				return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(o))
			}
			return nil
		}},
		plan.Step{Name: "verify-digest", Describe: "sha256 of " + a.tarball + " must equal the published or pinned digest",
			Do: func(ctx context.Context) error {
				got, err := m.Files.SHA256(ctx, a.tarball)
				if err != nil {
					return err
				}
				if got != a.want {
					return api.Errorf(api.CodeInvalid, "tarball digest %s does not match %s", got, a.want)
				}
				return nil
			}})
	return out
}

// configSteps write the files apk needs before it can reach the mirror.
func (a *alpineRun) configSteps() []plan.Step {
	b, m := a.b, a.m
	write := func(name, rel string, body func(ctx context.Context) ([]byte, error)) plan.Step {
		dst := path.Join(b.Root, rel)
		return plan.Step{Name: name, Describe: "write " + dst, Do: func(ctx context.Context) error {
			data, err := body(ctx)
			if err != nil {
				return err
			}
			if err := m.Files.MkdirAll(ctx, path.Dir(dst)); err != nil {
				return err
			}
			return m.Files.WriteAtomic(ctx, dst, data)
		}}
	}
	return []plan.Step{
		write("write-resolv-conf", "etc/resolv.conf", func(ctx context.Context) ([]byte, error) {
			d, err := m.Files.ReadFile(ctx, "/etc/resolv.conf")
			if err != nil {
				return nil, fmt.Errorf("the host's /etc/resolv.conf is needed for apk inside the build: %w", err)
			}
			// the marker lets a jail made from the image get its own resolv.conf at its first start
			return append([]byte(render.ResolvMarker+"\n"), d...), nil
		}),
		write("write-apk-repositories", "etc/apk/repositories", func(context.Context) ([]byte, error) {
			return []byte(fmt.Sprintf("%s/v%s/main\n%s/v%s/community\n", alpineMirror, a.branch, alpineMirror, a.branch)), nil
		}),
	}
}

// jailUpSteps brings up the build jail: fallback brand, private devfs ruleset,
// the Linux mounts in order, then the jail itself. Every step undoes itself
// when a later one fails, and teardown is idempotent.
func (a *alpineRun) jailUpSteps() []plan.Step {
	b, m := a.b, a.m
	n := render.BuildDevfsRuleset
	a.ruleset = n
	root := strings.TrimSuffix(b.Root, "/")
	mounts := render.LinuxMounts(root, n, 256<<20)
	steps := []plan.Step{
		{Name: "fallback-brand", Describe: "sysctl kern.elf64.fallback_brand=3 (unbranded ELF runs as Linux; apk installs such binaries)",
			Do: func(ctx context.Context) error {
				o, err := m.Exec.Run(ctx, []string{"sysctl", "kern.elf64.fallback_brand=3"})
				if err != nil {
					return fmt.Errorf("sysctl kern.elf64.fallback_brand=3: %w: %s", err, tail(o))
				}
				return nil
			}},
		{Name: "make-shm-dir", Describe: "mkdir -p " + path.Join(root, render.LinuxShmBacking),
			Do: func(ctx context.Context) error {
				if err := m.Files.MkdirAll(ctx, path.Join(root, render.LinuxCompat)); err != nil {
					return err
				}
				return m.Files.MkdirAll(ctx, path.Join(root, render.LinuxShmBacking))
			}},
	}
	rules, _ := render.LinuxDevfsRuleArgv(n, nil)
	steps = append(steps, plan.Step{Name: "load-devfs-ruleset", Describe: fmt.Sprintf("devfs rule -s %d add ... (private ruleset of the build jail)", n),
		Undo: func(ctx context.Context) error { return a.dropRules(ctx) },
		Do: func(ctx context.Context) error {
			a.rules = true
			for _, r := range rules {
				if o, err := m.Exec.Run(ctx, r); err != nil {
					return fmt.Errorf("%s: %w: %s", quote(r), err, tail(o))
				}
			}
			return nil
		}})
	for _, mt := range mounts {
		mt := mt
		argv := []string{"mount", "-t", mt.Type}
		if mt.Options != "" {
			argv = append(argv, "-o", mt.Options)
		}
		argv = append(argv, mt.Source, mt.Target)
		steps = append(steps, plan.Step{Name: "mount-" + path.Base(mt.Target), Describe: quote(argv),
			Undo: func(ctx context.Context) error { return a.unmount(ctx, mt) },
			Do: func(ctx context.Context) error {
				a.mounted = append(a.mounted, mt)
				if o, err := m.Exec.Run(ctx, argv); err != nil {
					return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(o))
				}
				return nil
			}})
	}
	jargv := []string{"jail", "-c", "name=" + a.jail, "path=" + root, "host.hostname=" + a.jail, "persist",
		"ip4=inherit", "ip6=inherit", fmt.Sprintf("devfs_ruleset=%d", n), "exec.clean"}
	steps = append(steps, plan.Step{Name: "start-build-jail", Describe: quote(jargv),
		Undo: func(ctx context.Context) error { return a.stopJail(ctx) },
		Do: func(ctx context.Context) error {
			if o, err := m.Exec.Run(ctx, jargv); err != nil {
				return fmt.Errorf("%s: %w: %s", quote(jargv), err, tail(o))
			}
			a.jailUp = true
			return nil
		}})
	return steps
}

func (a *alpineRun) stopJail(ctx context.Context) error {
	if !a.jailUp {
		return nil
	}
	a.jailUp = false
	if o, err := a.m.Exec.Run(ctx, []string{"jail", "-r", a.jail}); err != nil {
		return fmt.Errorf("jail -r %s: %w: %s", a.jail, err, tail(o))
	}
	return nil
}

func (a *alpineRun) unmount(ctx context.Context, mt render.LinuxMount) error {
	for i, x := range a.mounted {
		if x == mt {
			a.mounted = append(a.mounted[:i], a.mounted[i+1:]...)
			if o, err := a.m.Exec.Run(ctx, []string{"umount", mt.Target}); err != nil {
				return fmt.Errorf("umount %s: %w: %s", mt.Target, err, tail(o))
			}
			return nil
		}
	}
	return nil
}

func (a *alpineRun) dropRules(ctx context.Context) error {
	if !a.rules {
		return nil
	}
	a.rules = false
	if o, err := a.m.Exec.Run(ctx, []string{"devfs", "rule", "-s", strconv.Itoa(a.ruleset), "delset"}); err != nil {
		return fmt.Errorf("devfs rule delset: %w: %s", err, tail(o))
	}
	return nil
}

// apk runs an apk command inside the build jail.
func (a *alpineRun) apk(name string, args ...string) plan.Step {
	argv := append([]string{"jexec", a.jail, "/sbin/apk", "--no-interactive"}, args...)
	return a.m.execStep(name, argv)
}

// tearDown stops the jail, unmounts in reverse order and drops the ruleset.
func (a *alpineRun) tearDown() plan.Step {
	return plan.Step{Name: "tear-down-build-jail", Describe: "jail -r " + a.jail + "; umount the Linux mounts in reverse; devfs rule delset",
		Do: func(ctx context.Context) error {
			if err := a.stopJail(ctx); err != nil {
				return err
			}
			for len(a.mounted) > 0 {
				if err := a.unmount(ctx, a.mounted[len(a.mounted)-1]); err != nil {
					return err
				}
			}
			return a.dropRules(ctx)
		}}
}

func (a *alpineRun) apkSteps(upgrade bool) []plan.Step {
	steps := a.jailUpSteps()
	steps = append(steps, a.apk("apk-update", "update"))
	if upgrade {
		steps = append(steps, a.apk("apk-upgrade", "upgrade"))
	}
	if sets := a.b.Spec.Source.Sets; len(sets) > 0 {
		steps = append(steps, a.apk("apk-add", append([]string{"add"}, sets...)...))
	}
	steps = append(steps, a.apk("apk-verify", "verify"), a.tearDown())
	return steps
}

func (Minirootfs) Install(b *Build) ([]plan.Step, error) {
	a := newAlpineRun(b)
	steps := a.fetchSteps()
	steps = append(steps, plan.Step{Name: "extract", Describe: "tar -xpf " + a.tarball + " -C " + b.Root,
		Do: func(ctx context.Context) error {
			argv := []string{"tar", "-C", b.Root, "-xpzf", a.tarball}
			if o, err := b.M.Exec.Run(ctx, argv); err != nil {
				return fmt.Errorf("%s: %w: %s", quote(argv), err, tail(o))
			}
			return nil
		}})
	steps = append(steps, a.configSteps()...)
	return append(steps, a.apkSteps(false)...), nil
}

func (Minirootfs) Upgrade(b *Build) ([]plan.Step, error) {
	a := newAlpineRun(b)
	steps := a.configSteps()
	return append(steps, a.apkSteps(true)...), nil
}

// Check has nothing left to do: apk verify ran inside the build jail, before
// it was torn down.
func (Minirootfs) Check(*Build) []plan.Step { return nil }

func (Minirootfs) Packages(ctx context.Context, b *Build) ([]Package, error) {
	db, err := b.M.Files.ReadFile(ctx, path.Join(b.Root, "lib/apk/db/installed"))
	if err != nil {
		return nil, err
	}
	return ParseApkInstalled(db)
}

// ---- Debian debootstrap ----

// Debootstrap builds Debian generations with debootstrap(8). Source.Repo is the
// mirror, ImageSpec.Release the suite, Source.Keys an optional keyring path.
// Upgrading a Debian generation needs a chroot with Linux mounts and is not
// implemented: it returns api.CodeUnsupported.
// The release signature is always checked: a keyring is required.
type Debootstrap struct{}

func (Debootstrap) Type() string { return "debootstrap" }

func (Debootstrap) CheckSpec(s api.ImageSpec) error {
	if s.OS != api.OSLinux {
		return api.Errorf(api.CodeInvalid, "debootstrap images are Linux images")
	}
	if s.Release == "" || strings.HasPrefix(s.Release, "-") || strings.ContainsAny(s.Release, " /") {
		return api.Errorf(api.CodeInvalid, "debootstrap needs a suite name in release")
	}
	if s.Arch == "" {
		return api.Errorf(api.CodeInvalid, "arch is required")
	}
	if s.Source.Keys == "" {
		return api.Errorf(api.CodeInvalid, "debootstrap needs source.keys: the keyring that checks the release signature (for Debian, debian-archive-keyring.gpg)")
	}
	if s.Source.Repo != "" && !strings.HasPrefix(s.Source.Repo, "https://") {
		return api.Errorf(api.CodeInvalid, "the debootstrap mirror must be an https URL")
	}
	return nil
}

func (Debootstrap) RequiredPaths() []string { return []string{"/bin/sh", "/var/lib/dpkg/status"} }

func (Debootstrap) Install(b *Build) ([]plan.Step, error) {
	argv := []string{"debootstrap", "--arch=" + b.Spec.Arch, "--variant=minbase", "--keyring=" + b.Spec.Source.Keys, b.Spec.Release, b.Root}
	mirror := b.Spec.Source.Repo
	if mirror == "" {
		mirror = "https://deb.debian.org/debian" // debootstrap's own default is plain http
	}
	argv = append(argv, mirror)
	run := b.M.execStep("debootstrap", argv)
	// debootstrap mounts proc (and on some versions dev) inside the target while it works; a failed or killed run
	// can leave them, and the build root cannot be unmounted or rolled back while they are there.
	do := run.Do
	root, ex := b.Root, b.M.Exec
	run.Do = func(ctx context.Context) error {
		defer func() {
			for _, sub := range []string{"dev/pts", "dev", "proc", "sys"} {
				_, _ = ex.Run(ctx, []string{"umount", path.Join(root, sub)}) // not mounted is fine
			}
		}()
		return do(ctx)
	}
	return []plan.Step{run}, nil
}

func (Debootstrap) Upgrade(*Build) ([]plan.Step, error) {
	return nil, api.Errorf(api.CodeUnsupported, "upgrading a debootstrap generation is not implemented; build from the source instead")
}

func (Debootstrap) Check(*Build) []plan.Step { return nil }

func (Debootstrap) Packages(ctx context.Context, b *Build) ([]Package, error) {
	db, err := b.M.Files.ReadFile(ctx, path.Join(b.Root, "var/lib/dpkg/status"))
	if err != nil {
		return nil, err
	}
	return ParseDpkgStatus(db)
}
