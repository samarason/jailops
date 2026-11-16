package imagegen

import (
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestManifestHash(t *testing.T) {
	a := []Package{{"b", "2"}, {"a", "1"}}
	b := []Package{{"a", "1"}, {"b", "2"}, {"a", "1"}}
	if ManifestHash(a) != ManifestHash(b) {
		t.Fatal("order or duplicates changed the hash")
	}
	if ManifestHash(a) == ManifestHash([]Package{{"a", "1"}, {"b", "3"}}) {
		t.Fatal("version change must change the hash")
	}
	if ManifestHash(a) == ManifestHash([]Package{{"a", "1"}}) {
		t.Fatal("package set change must change the hash")
	}
	// name/version boundary is unambiguous
	if ManifestHash([]Package{{"a", "b\tc"}}) == ManifestHash([]Package{{"a\tb", "c"}}) {
		t.Log("known: tab inside names is not representable in pkg output")
	}
}

func TestParsers(t *testing.T) {
	if p, err := ParsePkgQuery([]byte("a 1\n\nb 2.0_1\n")); err != nil || len(p) != 2 || p[1].Version != "2.0_1" {
		t.Fatal(p, err)
	}
	if _, err := ParsePkgQuery([]byte("a\n")); err == nil {
		t.Fatal("bad line accepted")
	}
	if p, err := ParseApkInstalled([]byte("P:musl\nV:1.2\nA:x86_64\n\nP:busybox\nV:1.37\n")); err != nil || len(p) != 2 {
		t.Fatal(p, err)
	}
	if _, err := ParseApkInstalled([]byte("P:musl\n\n")); err == nil {
		t.Fatal("incomplete record accepted")
	}
	st := "Package: bash\nStatus: install ok installed\nVersion: 5.2\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: dash\nStatus: install ok installed\nVersion: 0.5\n"
	if p, err := ParseDpkgStatus([]byte(st)); err != nil || len(p) != 2 || p[0].Name != "bash" {
		t.Fatal(p, err)
	}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		in      string
		want    Ref
		invalid bool
	}{
		{"fb@stable", Ref{Image: "fb", Alias: "stable"}, false},
		{"freebsd-15-0#g3", Ref{Image: "freebsd-15-0", Gen: 3}, false},
		{"freebsd-15.0#g3", Ref{}, true},
		{"fb", Ref{Image: "fb"}, false},
		{"fb#3", Ref{}, true},
		{"fb#g0", Ref{}, true},
		{"FB@x", Ref{}, true},
		{"fb@", Ref{}, true},
		{"", Ref{}, true},
		{"a/b", Ref{}, true},
	}
	for _, tc := range tests {
		got, err := ParseRef(tc.in)
		if tc.invalid != api.IsCode(err, api.CodeInvalid) || (!tc.invalid && got != tc.want) {
			t.Errorf("%q: %v %v", tc.in, got, err)
		}
	}
	if GenerationName("fb", 4) != "fb#g4" {
		t.Fatal()
	}
}

func TestParsePkgQuerySkipsToolDiagnostics(t *testing.T) {
	pkgs, err := ParsePkgQuery([]byte("pkg: Setting ABI requires setting OSVERSION, guessing the OSVERSION as: 1500000\nFreeBSD-runtime 15.1\n"))
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "FreeBSD-runtime" {
		t.Fatalf("%v %v", pkgs, err)
	}
}

func TestFreeBSDVersionOfAPackageSet(t *testing.T) {
	for in, want := range map[string]string{
		"15.1":                  "15.1-RELEASE",
		"15.1p6":                "15.1-RELEASE-p6",
		"15.snap20261031190411": "15.snap20261031190411",
	} {
		if got := FreeBSDVersion([]Package{{"FreeBSD-utilities", "x"}, {"FreeBSD-runtime", in}}); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	if got := FreeBSDVersion([]Package{{"musl", "1.2.5-r9"}}); got != "" {
		t.Errorf("a set without FreeBSD-runtime: %q", got)
	}
}
