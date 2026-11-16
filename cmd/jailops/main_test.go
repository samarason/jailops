package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/internal/manpage"
)

func execute(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env := &cli.Env{Stdout: &out, Stderr: &errb, Version: "test", Getenv: func(string) string { return "" }}
	code := cli.Execute(context.Background(), env, args)
	return code, out.String(), errb.String()
}

// --version prints the version of the client alone, without asking a server.
func TestVersionFlag(t *testing.T) {
	code, out, errs := execute(t, "--version")
	if code != 0 || !strings.Contains(out, "Client:  test") || strings.Contains(out, "Server:") {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
}

// The hidden man command writes one mdoc page per command, with a NAME section; mandoc checks them when it is installed.
func TestManPages(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1761609600")
	dir := filepath.Join(t.TempDir(), "man1")
	if code, out, errs := execute(t, "man", dir); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	pages, _ := filepath.Glob(filepath.Join(dir, "*.1"))
	if len(pages) < 50 {
		t.Fatalf("only %d pages", len(pages))
	}
	_, mandoc := exec.LookPath("mandoc")
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(filepath.Base(p), ".1")
		if !strings.Contains(string(b), ".Sh NAME\n.Nm "+name+"\n.Nd ") {
			t.Errorf("%s has no NAME section:\n%s", p, b)
		}
		// the mdoc conventions (line length, one sentence per line, references in order), without mandoc
		for _, msg := range manpage.Lint(string(b)) {
			t.Errorf("%s: %s", name, msg)
		}
		if mandoc == nil {
			// the pages are not installed while the tests run, so references to other manuals cannot be found
			out, _ := exec.Command("mandoc", "-Tlint", "-Wall", p).CombinedOutput()
			for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if l != "" && !strings.Contains(l, "referenced manual not found") {
					t.Errorf("mandoc -Tlint %s: %s", p, l)
				}
			}
		}
	}
	// every page has the environment and the exit status
	for _, name := range []string{"jailops.1", "jailops-jail-delete.1"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		for _, want := range []string{".Sh ENVIRONMENT\n", ".It Ev JAILOPS_PROJECT\n", ".Sh EXIT STATUS\n", ".It 4\nnot found\n"} {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "jailops-man.1")); err == nil {
		t.Error("the man command documented itself")
	}
}
