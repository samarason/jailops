package priv

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// What the helper trusts when it runs a package manager or debootstrap as root is chosen by root, never by the
// daemon: key directories and keyrings live in root-owned directories named in priv.conf, and the hosts packages
// and mirrors come from are listed there too. The daemon writes the repository configuration of an image build
// through the helper, so every part of it that decides whom to trust is checked here.

const (
	// DefaultPkgKeysDir holds the key directories (fingerprints) of package repositories other than the base system's.
	DefaultPkgKeysDir = "/usr/local/etc/jailops/keys"
	// DefaultKeyringDir holds the keyrings debootstrap checks a release with.
	DefaultKeyringDir = "/usr/local/share/keyrings"
	// baseKeysDir is where the base system ships the keys of its own package repositories.
	baseKeysDir = "/usr/share/keys/"
)

// trustUID is the owner of every file a trusted directory may hold, and trustAnchor the top of the part of the path
// that is checked (every directory from there down must belong to root and not be writable by others). Tests change
// them; in use they are root and /.
var (
	trustUID    uint32 = 0
	trustAnchor        = "/"
)

var (
	// the variables pkg expands in a repository URL or a key path
	rePkgVar      = regexp.MustCompile(`\$\{(ABI|ARCH|OSNAME|RELEASE|VERSION_MAJOR|VERSION_MINOR)\}`)
	rePkgURLPath  = regexp.MustCompile(`^[A-Za-z0-9._~/%+:-]{0,300}$`)
	rePkgURLHost  = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)(:[0-9]{1,5})?$`)
	rePkgKeyPath  = regexp.MustCompile(`^[A-Za-z0-9._+/-]{1,200}$`)
	maxTrustedLen = 4096 // entries a trusted directory may hold: more is not a key directory
)

// requireRootTree checks that p and everything below it belongs to root and is not writable by anyone else, and
// that no component of the path from / to p, and nothing below p, is a symbolic link: a link inside a trusted
// directory could lead out of it.
func requireRootTree(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return forbidden("%q is not a clean absolute path", p)
	}
	cur := "/"
	for _, c := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		cur = filepath.Join(cur, c)
		if !within(trustAnchor, cur) {
			continue
		}
		if err := rootOwned(cur); err != nil {
			return err
		}
	}
	n := 0
	return filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return forbidden("%s: %v", path, err)
		}
		if n++; n > maxTrustedLen {
			return forbidden("%s holds too many entries to be a key directory", p)
		}
		return rootOwned(path)
	})
}

// rootOwned refuses a symbolic link, a path the trusted owner does not own and one that others can write.
func rootOwned(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return forbidden("%s: %v", p, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return forbidden("%s is a symbolic link: a trusted directory holds no links", p)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != trustUID {
		return forbidden("%s does not belong to root", p)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return forbidden("%s is writable by others (mode %v)", p, fi.Mode().Perm())
	}
	return nil
}

// cleanKeyPath checks the text of a path a repository configuration gives for its keys: only plain components
// and the variables pkg expands, never "..".
func cleanKeyPath(p string) bool {
	seen := map[string]bool{}
	for _, v := range rePkgVar.FindAllString(p, -1) {
		if seen[v] { // a variable twice is not a path root chose: pkg expands each one itself
			return false
		}
		seen[v] = true
	}
	plain := rePkgVar.ReplaceAllString(p, "x")
	if !rePkgKeyPath.MatchString(plain) || strings.Contains(plain, "..") || strings.Contains(plain, "//") {
		return false
	}
	return filepath.IsAbs(plain)
}

// checkPkgKeys accepts the key directory of a repository configuration: below /usr/share/keys (the base system's)
// or below PkgKeysDir, which must be intact root-owned files.
func (c Config) checkPkgKeys(fp string) error {
	if !cleanKeyPath(fp) {
		return forbidden("the key directory %q is not a plain absolute path", fp)
	}
	if strings.HasPrefix(fp, baseKeysDir) {
		return nil // the base system's own directory: the daemon cannot write there
	}
	dir := c.pkgKeysDir()
	if !strings.HasPrefix(fp, dir+"/") {
		return forbidden("the key directory %q is not below %s or %s: keys are chosen by root (pkg-keys-dir in priv.conf)", fp, strings.TrimSuffix(baseKeysDir, "/"), dir)
	}
	if err := requireRootTree(strings.TrimSuffix(rePkgVar.ReplaceAllString(fp, "x"), "/")); err != nil {
		return forbidden("the key directory %q: %v", fp, err)
	}
	return nil
}

func (c Config) pkgKeysDir() string {
	if c.PkgKeysDir != "" {
		return c.PkgKeysDir
	}
	return DefaultPkgKeysDir
}

func (c Config) keyringDir() string {
	if c.KeyringDir != "" {
		return c.KeyringDir
	}
	return DefaultKeyringDir
}

// checkKeyring accepts the keyring file debootstrap checks a release with: a file below KeyringDir that belongs to root.
func (c Config) checkKeyring(key string) error {
	dir := c.keyringDir()
	if !cleanAbs(key) || !strings.HasPrefix(key, dir+"/") || strings.Count(strings.TrimPrefix(key, dir+"/"), "/") > 0 {
		return forbidden("debootstrap: keyring %q is not a file directly in %s (keyring-dir in priv.conf)", key, dir)
	}
	if err := requireRootTree(key); err != nil {
		return forbidden("debootstrap: keyring %q: %v", key, err)
	}
	return nil
}

// pkgHostAllowed says whether a download host is listed in priv.conf (fetch-host) for the scheme: a plain entry
// allows https, an entry written http://<host> allows plain http for that host as well.
func (c Config) pkgHostAllowed(host string, https bool) bool {
	for _, h := range c.fetchHosts() {
		if plain, ok := strings.CutPrefix(h, "http://"); ok {
			if plain == host {
				return true
			}
			continue
		}
		if h == host && https {
			return true
		}
	}
	return false
}

// checkPkgURL accepts the url of a repository configuration: http(s) (optionally pkg+), a host from fetch-host
// with no user, port tricks or variable, and a path of plain characters that may use the variables pkg expands.
func (c Config) checkPkgURL(raw string) error {
	rest := strings.TrimPrefix(raw, "pkg+")
	var https bool
	switch {
	case strings.HasPrefix(rest, "https://"):
		https, rest = true, strings.TrimPrefix(rest, "https://")
	case strings.HasPrefix(rest, "http://"):
		rest = strings.TrimPrefix(rest, "http://")
	default:
		return forbidden("pkg repository url %q is not an http(s) URL", raw)
	}
	hostport, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		hostport, path = rest[:i], rest[i:]
	}
	m := rePkgURLHost.FindStringSubmatch(strings.ToLower(hostport))
	if m == nil {
		return forbidden("pkg repository url %q: the host part must be a plain host name", raw)
	}
	if !c.pkgHostAllowed(m[1], https) {
		return forbidden("pkg repository url %q: host %s is not in fetch-host of priv.conf (over %s)", raw, m[1], map[bool]string{true: "https", false: "plain http"}[https])
	}
	if p := rePkgVar.ReplaceAllString(path, "x"); !rePkgURLPath.MatchString(p) || strings.Contains(p, "..") || strings.Contains(p, "//") {
		return forbidden("pkg repository url %q: the path is not a plain path", raw)
	}
	return nil
}
