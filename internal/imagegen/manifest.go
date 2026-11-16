package imagegen

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Package is one installed package.
type Package struct{ Name, Version string }

// ManifestHash is a hash over the sorted installed package set and versions.
// The input order does not matter; duplicates are collapsed.
func ManifestHash(pkgs []Package) string {
	lines := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		lines = append(lines, p.Name+"\t"+p.Version)
	}
	sort.Strings(lines)
	h := sha256.New()
	prev := ""
	for i, l := range lines {
		if i > 0 && l == prev {
			continue
		}
		prev = l
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

var reReleaseVersion = regexp.MustCompile(`^([0-9]+\.[0-9]+)(?:p([0-9]+))?$`)

// FreeBSDVersion is the FreeBSD version a pkgbase package set was built from, read from the version of its
// FreeBSD-runtime package: "15.1" is 15.1-RELEASE, "15.1p6" 15.1-RELEASE-p6. Any other form (a snapshot of a branch,
// "15.snap20261031190411") is returned as it is, because it says nothing more than that. "" when the set has no
// FreeBSD-runtime (a Linux image).
func FreeBSDVersion(pkgs []Package) string {
	for _, p := range pkgs {
		if p.Name != "FreeBSD-runtime" {
			continue
		}
		m := reReleaseVersion.FindStringSubmatch(p.Version)
		switch {
		case m == nil:
			return p.Version
		case m[2] == "":
			return m[1] + "-RELEASE"
		default:
			return m[1] + "-RELEASE-p" + m[2]
		}
	}
	return ""
}

// ParsePkgQuery parses "name version" lines from pkg query '%n %v'.
func ParsePkgQuery(out []byte) ([]Package, error) {
	var pkgs []Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if strings.HasPrefix(f[0], "pkg:") { // a diagnostic the tool printed on stderr
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("unparsable package line %q", sc.Text())
		}
		pkgs = append(pkgs, Package{f[0], f[1]})
	}
	return pkgs, sc.Err()
}

// ParseApkInstalled parses an Alpine /lib/apk/db/installed database ("P:" name
// and "V:" version lines, records separated by blank lines).
func ParseApkInstalled(db []byte) ([]Package, error) {
	var pkgs []Package
	var cur Package
	flush := func() error {
		if cur.Name == "" && cur.Version == "" {
			return nil
		}
		if cur.Name == "" || cur.Version == "" {
			return fmt.Errorf("incomplete apk record %+v", cur)
		}
		pkgs = append(pkgs, cur)
		cur = Package{}
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(db))
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(l, "P:"):
			cur.Name = l[2:]
		case strings.HasPrefix(l, "V:"):
			cur.Version = l[2:]
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return pkgs, sc.Err()
}

// ParseDpkgStatus parses /var/lib/dpkg/status, keeping installed packages.
func ParseDpkgStatus(db []byte) ([]Package, error) {
	var pkgs []Package
	var name, ver, status string
	flush := func() error {
		defer func() { name, ver, status = "", "", "" }()
		if name == "" && ver == "" && status == "" {
			return nil
		}
		if name == "" || ver == "" {
			return fmt.Errorf("incomplete dpkg record for %q", name)
		}
		if strings.HasSuffix(status, " installed") {
			pkgs = append(pkgs, Package{name, ver})
		}
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(db))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			if err := flush(); err != nil {
				return nil, err
			}
		case strings.HasPrefix(l, "Package: "):
			name = l[9:]
		case strings.HasPrefix(l, "Version: "):
			ver = l[9:]
		case strings.HasPrefix(l, "Status: "):
			status = l[8:]
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return pkgs, sc.Err()
}
