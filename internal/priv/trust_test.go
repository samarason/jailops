package priv

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trustEnv makes a root-owned (the test's user stands in) key directory, a keyring directory and a Local that
// trusts them, plus a directory the daemon could write that is not trusted.
type trustEnv struct {
	l          *Local
	keys, ring string
	daemon     string
}

func newTrustEnv(t *testing.T) *trustEnv {
	t.Helper()
	base, _ := filepath.EvalSymlinks(t.TempDir())
	oldUID, oldAnchor := trustUID, trustAnchor
	trustUID, trustAnchor = uint32(os.Getuid()), base
	t.Cleanup(func() { trustUID, trustAnchor = oldUID, oldAnchor })
	e := &trustEnv{keys: filepath.Join(base, "keys"), ring: filepath.Join(base, "keyrings"), daemon: filepath.Join(base, "state")}
	for _, d := range []string{filepath.Join(e.keys, "vendor", "trusted"), e.ring, e.daemon} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(e.keys, "vendor", "trusted", "key1"), []byte("k\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.ring, "release.gpg"), []byte("k\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixModes(t, base)
	e.l = &Local{cfg: Config{PkgKeysDir: e.keys, KeyringDir: e.ring, StateDir: e.daemon,
		FetchHosts: []string{"pkg.freebsd.org", "packages.example.net", "http://mirror.lan.example"}}}
	return e
}

// fixModes gives a test tree the modes a root-owned directory has (the test runs under any umask).
func fixModes(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		if d.Type().IsRegular() {
			return os.Chmod(p, 0o644)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repoConf(url, keys string) string {
	return "repo: {\n  url: \"" + url + "\",\n  signature_type: \"fingerprints\",\n  fingerprints: \"" + keys + "\",\n  enabled: yes\n}\n"
}

// A repository configuration is accepted when root chose its trust anchors: the key directory is the base
// system's or below pkg-keys-dir, the host is listed.
func TestPkgRepositoryTrustIsChosenByRoot(t *testing.T) {
	e := newTrustEnv(t)
	vendor := filepath.Join(e.keys, "vendor")
	for name, tc := range map[string]struct{ url, keys string }{
		"the base system's pkgbase":    {"pkg+https://pkg.FreeBSD.org/${ABI}/base_release_1", "/usr/share/keys/pkgbase-${VERSION_MAJOR}"},
		"the base system's ports keys": {"pkg+https://pkg.FreeBSD.org/${ABI}/base_latest", "/usr/share/keys/pkg"},
		"a vendor key directory":       {"https://packages.example.net/${ABI}/latest", vendor},
		"plain http for a named host":  {"http://mirror.lan.example/${ABI}/latest", vendor},
		"a port":                       {"https://packages.example.net:8443/repo", vendor},
	} {
		if err := e.l.checkRepoConf("r.conf", repoConf(tc.url, tc.keys)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

func TestPkgRepositoryRefusals(t *testing.T) {
	e := newTrustEnv(t)
	vendor := filepath.Join(e.keys, "vendor")
	// the daemon makes a key directory of its own below the area it writes
	evil := filepath.Join(e.daemon, "mykeys")
	if err := os.MkdirAll(filepath.Join(evil, "trusted"), 0o755); err != nil {
		t.Fatal(err)
	}
	// a link inside the trusted directory that leads out of it
	if err := os.Symlink(evil, filepath.Join(e.keys, "link")); err != nil {
		t.Fatal(err)
	}
	// a key directory that others can write
	loose := filepath.Join(e.keys, "loose")
	if err := os.MkdirAll(filepath.Join(loose, "trusted"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o775); err != nil {
		t.Fatal(err)
	}
	// a link in the middle of the key directory's content
	withLink := filepath.Join(e.keys, "withlink")
	if err := os.MkdirAll(withLink, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(withLink, "trusted")); err != nil {
		t.Fatal(err)
	}
	good := "https://packages.example.net/${ABI}/latest"
	for name, tc := range map[string]struct{ url, keys string }{
		"a key directory the daemon wrote":  {good, evil},
		"a link out of the trusted dir":     {good, filepath.Join(e.keys, "link")},
		"a link inside the key directory":   {good, withLink},
		"a key directory others can write":  {good, loose},
		"dot dot out of /usr/share/keys":    {good, "/usr/share/keys/../../../tmp/k"},
		"dot dot out of pkg-keys-dir":       {good, vendor + "/../../state/mykeys"},
		"a key directory that is missing":   {good, filepath.Join(e.keys, "nothing")},
		"a variable that pkg does not know": {good, "/usr/share/keys/${EVIL}"},
		"an unlisted host":                  {"https://evil.example/${ABI}/latest", vendor},
		"userinfo in front of a good host":  {"https://packages.example.net@evil.example/x", vendor},
		"userinfo with the good host last":  {"https://evil.example@packages.example.net/x", vendor},
		"a variable in the host":            {"https://${ABI}.example/x", vendor},
		"a brace host":                      {"https://pkg.freebsd.org${/x", vendor},
		"plain http to an https-only host":  {"http://packages.example.net/x", vendor},
		"a scheme that is not http":         {"file:///tmp/repo", vendor},
		"ftp":                               {"ftp://pkg.freebsd.org/x", vendor},
		"a query":                           {good + "?x=1", vendor},
		"dot dot in the path":               {"https://packages.example.net/../x", vendor},
		"a host with a trailing dot suffix": {"https://packages.example.net.evil.example/x", vendor},
	} {
		if err := e.l.checkRepoConf("r.conf", repoConf(tc.url, tc.keys)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// no signature check at all, and a key the daemon does not list
	if err := e.l.checkRepoConf("r.conf", "repo: {\n  url: \""+good+"\",\n  signature_type: \"none\",\n  enabled: yes\n}\n"); err == nil {
		t.Error("a repository without a signature check was accepted")
	}
	if err := e.l.checkRepoConf("r.conf", "repo: {\n  url: \""+good+"\",\n  signature_type: \"fingerprints\",\n  fingerprints: \""+vendor+"\",\n  pubkey: \"/tmp/k\",\n  enabled: yes\n}\n"); err == nil {
		t.Error("an extra key was accepted")
	}
}

// A keyring is a file directly in keyring-dir that root owns; a mirror host must be listed.
func TestDebootstrapKeyringAndMirrorAreChosenByRoot(t *testing.T) {
	e := newTrustEnv(t)
	c := e.l.cfg
	if err := c.checkKeyring(filepath.Join(e.ring, "release.gpg")); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(e.daemon, "release.gpg")
	if err := os.WriteFile(mine, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mine, filepath.Join(e.ring, "link.gpg")); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(e.ring, "loose.gpg")
	if err := os.WriteFile(loose, []byte("k"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"a keyring the daemon wrote": mine,
		"a link to it":               filepath.Join(e.ring, "link.gpg"),
		"a keyring others can write": loose,
		"a sub directory":            filepath.Join(e.ring, "sub", "x.gpg"),
		"dot dot":                    e.ring + "/../state/release.gpg",
		"a missing file":             filepath.Join(e.ring, "nothing.gpg"),
	} {
		if err := c.checkKeyring(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for host, want := range map[string]bool{"packages.example.net": true, "evil.example": false, "pkg.freebsd.org": true, "mirror.lan.example": true} {
		if got := c.pkgHostAllowed(host, true); got != want {
			t.Errorf("host %s over https: %v, want %v", host, got, want)
		}
	}
	if !c.pkgHostAllowed("mirror.lan.example", false) || c.pkgHostAllowed("packages.example.net", false) {
		t.Error("plain http is allowed only for a host written http://<host>")
	}
}

// pkg-keys-dir and keyring-dir may not lie where the daemon writes, and no storage root may be mounted over them.
func TestTrustedDirectoriesAreOutsideTheDaemonsDirectories(t *testing.T) {
	base := Config{StorageRoots: []string{"tank/jailops"}, StateDir: "/var/db/jailops/state", ConfDir: "/usr/local/etc/jailops/jails",
		WorkDir: "/var/tmp/jailops", HelperPath: "/usr/local/libexec/jailops-priv", MountBase: "/usr/local/jailops"}
	if c, err := base.Normalize(); err != nil || c.PkgKeysDir != DefaultPkgKeysDir || c.KeyringDir != DefaultKeyringDir {
		t.Fatalf("the defaults: %+v %v", c.PkgKeysDir, err)
	}
	for name, mod := range map[string]func(*Config){
		"keys in the work directory":     func(c *Config) { c.PkgKeysDir = "/var/tmp/jailops/keys" },
		"keys in the state directory":    func(c *Config) { c.PkgKeysDir = "/var/db/jailops/state/keys" },
		"keys in the conf directory":     func(c *Config) { c.PkgKeysDir = "/usr/local/etc/jailops/jails/keys" },
		"keys in a storage root":         func(c *Config) { c.PkgKeysDir = "/usr/local/jailops/keys" },
		"a keyring dir that is the work": func(c *Config) { c.KeyringDir = "/var/tmp/jailops" },
		"a relative keys dir":            func(c *Config) { c.PkgKeysDir = "keys" },
		"a keys dir at the top":          func(c *Config) { c.PkgKeysDir = "/keys" },
		"a dot dot keys dir":             func(c *Config) { c.KeyringDir = "/usr/local/share/../../../var/tmp/k" },
		"a fetch host with a scheme":     func(c *Config) { c.FetchHosts = []string{"https://pkg.freebsd.org"} },
	} {
		c := base
		mod(&c)
		if _, err := c.Normalize(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// no storage root can shadow them
	c, _ := base.Normalize()
	for _, d := range c.helperDirs() {
		if strings.HasPrefix(d, "/usr/local/etc/jailops/keys") {
			return
		}
	}
	t.Error("pkg-keys-dir is not among the helper's own directories")
}
