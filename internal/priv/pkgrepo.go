package priv

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var (
	rePkgKeyLine = regexp.MustCompile(`^\s*([a-z_]+)\s*:\s*(?:"([^"\n]*)"|([A-Za-z0-9_]+))\s*,?\s*$`)
)

// verifyPkg checks what a pkg command line names that does not depend on the repository directory: where it may work
// (verifyPkgTarget). The repository directory is checked and sealed when the command runs (sealRepos).
func verifyPkg(ctx context.Context, l *Local, args []string) error {
	return verifyPkgTarget(ctx, l, args)
}

const (
	maxRepoEntries = 32       // entries a repository directory may hold: more is not one JailOps writes
	maxRepoFile    = 16 << 10 // bytes of a repository configuration: a longer file is refused, never cut short
)

var reRepoBlock = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}\s*:\s*\{$`)

// sealRepos is what makes the repository check mean something. pkg runs the scripts of a package as root on the host,
// so a repository, or a key, that the daemon chose would let it run what it likes as root; and the daemon writes the
// directory pkg reads its repositories from, and can change it between the check and the run. The helper therefore
// reads the whole directory itself (every entry, every byte), checks every configuration, copies exactly the bytes it
// checked into a directory it creates for this run (root's, mode 0700) and gives pkg that one. The returned function
// removes it.
func (l *Local) sealRepos(ctx context.Context, argv []string) ([]string, func(), error) {
	none := func() {}
	dir := reposDirOf(argv[1:])
	if dir == "" {
		return argv, none, nil
	}
	files, err := l.readRepoDir(dir)
	if err != nil {
		return nil, none, err
	}
	for _, f := range files {
		if err := l.checkRepoConf(f.name, string(f.body)); err != nil {
			return nil, none, err
		}
	}
	sealed, err := os.MkdirTemp(l.cfg.StateDir, ".pkgrepos-")
	if err != nil {
		return nil, none, fmt.Errorf("sealing the repository directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(sealed) }
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(sealed, f.name), f.body, 0o600); err != nil {
			cleanup()
			return nil, none, fmt.Errorf("sealing the repository directory: %w", err)
		}
	}
	out := append([]string(nil), argv...)
	for i := 1; i+1 < len(out); i++ {
		if out[i] == "-o" && strings.HasPrefix(out[i+1], "REPOS_DIR=") {
			out[i+1] = "REPOS_DIR=" + sealed
		}
	}
	return out, cleanup, nil
}

type repoFile struct {
	name string
	body []byte
}

// readRepoDir reads the *.conf files of the directory pkg would read, all of them, each whole. It refuses a directory
// with more than maxRepoEntries entries, a configuration that is not a plain file or is longer than maxRepoFile.
func (l *Local) readRepoDir(dir string) ([]repoFile, error) {
	r, err := l.cfg.resolve(dir)
	if err != nil {
		return nil, err
	}
	root, err := r.openRoot()
	if err != nil {
		return nil, mapFSErr(err)
	}
	defer root.Close()
	d, err := root.Open(r.rel)
	if err != nil {
		return nil, mapFSErr(err)
	}
	names, err := d.Readdirnames(maxRepoEntries + 1)
	d.Close()
	if err != nil && err != io.EOF {
		return nil, mapFSErr(err)
	}
	if len(names) > maxRepoEntries {
		return nil, forbidden("pkg repository directory: more than %d entries", maxRepoEntries)
	}
	var files []repoFile
	for _, n := range names {
		if !strings.HasSuffix(n, ".conf") {
			continue
		}
		f, err := root.OpenFile(filepath.Join(r.rel, n), os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, mapFSErr(err)
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			f.Close()
			return nil, forbidden("pkg repository %s is not a plain file", n)
		}
		b, err := io.ReadAll(io.LimitReader(f, maxRepoFile+1))
		f.Close()
		if err != nil {
			return nil, mapFSErr(err)
		}
		if len(b) > maxRepoFile {
			return nil, forbidden("pkg repository %s is longer than %d bytes", n, maxRepoFile)
		}
		files = append(files, repoFile{n, b})
	}
	return files, nil
}

// checkRepoConf accepts exactly the file JailOps writes (imagegen/source.go): one block, `name: {`, the keys below it
// one to a line, `}`. A key that appears twice is refused (pkg takes the first value, a check that read the last
// one would have approved something else), and so is every line that is not one of these.
func (l *Local) checkRepoConf(name, body string) error {
	seen := map[string]string{}
	state := 0 // 0 before the block, 1 inside, 2 after
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case state == 0 && reRepoBlock.MatchString(line):
			state = 1
			continue
		case state == 1 && line == "}":
			state = 2
			continue
		case state != 1:
			return forbidden("pkg repository %s: line %q is not one JailOps writes", name, line)
		}
		m := rePkgKeyLine.FindStringSubmatch(line)
		if m == nil {
			return forbidden("pkg repository %s: line %q is not one JailOps writes", name, line)
		}
		v := m[2]
		if v == "" {
			v = m[3]
		}
		if _, dup := seen[m[1]]; dup {
			return forbidden("pkg repository %s: key %q appears twice", name, m[1])
		}
		seen[m[1]] = v
	}
	if state != 2 {
		return forbidden("pkg repository %s: it is not one block of keys", name)
	}
	if err := l.cfg.checkPkgURL(seen["url"]); err != nil {
		return forbidden("pkg repository %s: %v", name, err)
	}
	if seen["signature_type"] != "fingerprints" {
		return forbidden("pkg repository %s: the repository must be verified by fingerprints", name)
	}
	if err := l.cfg.checkPkgKeys(seen["fingerprints"]); err != nil {
		return forbidden("pkg repository %s: %v", name, err)
	}
	for k := range seen {
		switch k {
		case "url", "signature_type", "fingerprints", "enabled", "mirror_type", "priority", "ip_version":
		default:
			return forbidden("pkg repository %s: key %q is not accepted", name, k)
		}
	}
	return nil
}

// pkgTarget returns the -r ROOT and -j JAIL among the flags that come before the subcommand.
func pkgTarget(args []string) (roots, jails []string) {
	for i := 0; i < len(args) && strings.HasPrefix(args[i], "-"); i++ {
		switch args[i] {
		case "-r", "-j":
			if i+1 >= len(args) {
				return
			}
			if args[i] == "-r" {
				roots = append(roots, args[i+1])
			} else {
				jails = append(jails, args[i+1])
			}
			i++
		case "-o":
			i++
		}
	}
	return
}

// verifyPkgTarget says where pkg may work. It runs as root, and it runs the scripts of a package in a chroot of the
// root it was given, with the shell and the libraries found there: a process of a running jail that replaced them (or
// put a symbolic link where pkg writes) would have root of the host. So `pkg -r ROOT` is for a root no jail is running
// in (an image being built, a jail that is stopped), and `pkg -j JAIL` is for a running jail: pkg enters the jail first,
// so what it does is confined to it and uses the jail's own repository configuration.
func verifyPkgTarget(ctx context.Context, l *Local, args []string) error {
	roots, jails := pkgTarget(args)
	if len(roots)+len(jails) == 0 && len(args) == 2 && args[0] == "config" && args[1] == "abi" {
		return nil // the ABI of the host, which names no root
	}
	if len(roots)+len(jails) != 1 {
		return invalid("pkg needs exactly one of -r ROOT (a root no jail runs in) and -j JAIL (a running jail)")
	}
	if len(jails) == 1 {
		name := jails[0]
		if err := ValidJailName(name); err != nil {
			return err
		}
		if _, ok := l.confFileFor(name); !ok {
			return forbidden("jail %q is not managed by JailOps", name)
		}
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				if k, _, _ := strings.Cut(args[i+1], "="); k == "REPOS_DIR" || k == "PKG_CACHEDIR" {
					return forbidden("pkg -o %s is for a root: with -j pkg reads the jail's own configuration", k)
				}
			}
		}
		j, ok, err := l.d.Jails.Get(ctx, name)
		if err != nil {
			return err
		}
		if !ok {
			return invalid("jail %q is not running: pkg -j runs inside it", name)
		}
		_ = j
		return nil
	}
	root := filepath.Clean(roots[0])
	real := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		real = r
	}
	list, err := l.d.Jails.List(ctx)
	if err != nil {
		return err
	}
	for _, j := range list {
		if j.Path == "" {
			continue
		}
		jp := filepath.Clean(j.Path)
		if r, err := filepath.EvalSymlinks(jp); err == nil {
			jp = r
		}
		if within(jp, real) || within(jp, root) {
			return forbidden("pkg -r %s: it is the root of the running jail %s; stop the jail, or run pkg inside it with -j", roots[0], j.Name)
		}
	}
	return nil
}
