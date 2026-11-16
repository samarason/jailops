package cli

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "jailops.net/jailops"

// The client may import the SDK, the standard library and the few
// third-party packages allowed for it, and nothing else of JailOps.
var allowedImports = map[string]bool{
	modulePath + "/sdk":     true,
	modulePath + "/sdk/api": true,
	// writes the man pages from the command tree; it links nothing of the daemon
	modulePath + "/internal/manpage": true,
	// the catalog's parser and validator, for app validate; TestAppsLinksNoDaemon keeps it pure
	modulePath + "/internal/apps": true,
	// the grammar of a firewall reference (jail:NAME, set:NAME, tag:NAME), shared with the server; pure validation
	modulePath + "/internal/validate": true,
	"github.com/spf13/cobra":          true,
	"github.com/spf13/pflag":          true, // cobra's own flag type: it comes with cobra
	"gopkg.in/yaml.v3":                true,
	"golang.org/x/term":               true,
}

// Tests may also use the in-memory server and the package under test.
var allowedInTests = map[string]bool{
	modulePath + "/sdk/fake":     true,
	modulePath + "/internal/cli": true,
}

func isStd(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func TestImportRules(t *testing.T) {
	dirs := []string{".", filepath.Join("..", "..", "cmd", "jailops")}
	checked := 0
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files in %s: %v", dir, err)
		}
		for _, f := range files {
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			isTest := strings.HasSuffix(f, "_test.go")
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch {
				case isStd(p), allowedImports[p]:
				case isTest && allowedInTests[p]:
				case dir != "." && p == modulePath+"/internal/cli":
					// the command is a thin main around the package
				default:
					t.Errorf("%s imports %q: the client may use only sdk, sdk/api, the standard library, cobra, yaml.v3 and x/term", f, p)
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no imports checked")
	}
}

// The checker must notice a forbidden import.
func TestImportRuleDetects(t *testing.T) {
	dir := t.TempDir()
	src := "package x\nimport _ \"" + modulePath + "/internal/service\"\nimport _ \"fmt\"\n"
	path := filepath.Join(dir, "x.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	af, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	for _, imp := range af.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !isStd(p) && !allowedImports[p] {
			bad++
		}
	}
	if bad != 1 {
		t.Fatalf("expected one forbidden import, found %d", bad)
	}
}

// internal/apps is linked into the client for app validate. It and what it
// imports, transitively, stay pure validation: no command runner, renderer,
// store or anything else of the daemon.
func TestAppsLinksNoDaemon(t *testing.T) {
	pure := map[string]bool{
		modulePath + "/internal/apps":     true,
		modulePath + "/internal/validate": true,
		modulePath + "/internal/ipam":     true,
		modulePath + "/internal/schedule": true,
	}
	seen := map[string]bool{}
	var walk func(pkg string)
	walk = func(pkg string) {
		if seen[pkg] {
			return
		}
		seen[pkg] = true
		dir := filepath.Join("..", "..", strings.TrimPrefix(pkg, modulePath+"/"))
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go files in %s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch {
				case isStd(p), p == modulePath+"/sdk/api", p == "gopkg.in/yaml.v3":
				case pure[p]:
					walk(p)
				default:
					t.Errorf("%s imports %q: the client links internal/apps, which may use only %v, sdk/api, yaml.v3 and the standard library", f, p, pure)
				}
			}
		}
	}
	walk(modulePath + "/internal/apps")
	if len(seen) < 2 {
		t.Fatalf("walked %v", seen)
	}
}
