package service_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every kind of run that a plan executor journals must have a case in the recovery at the start: a kind that has none
// leaves a record that "needs attention" for ever, and the dataset the run made behind it. The kinds are read from the
// code that starts the runs, so a new kind that forgets its recovery fails here.
func TestEveryJournaledRunKindHasARecovery(t *testing.T) {
	kinds := map[string]string{}
	re := []*regexp.Regexp{
		regexp.MustCompile(`\bs\.run\(ctx, "([a-z-]+)"`),
		regexp.MustCompile(`Executor\.Run\(ctx, "([a-z-]+)/`),
		regexp.MustCompile(`\.Run\(ctx, fmt\.Sprintf\("([a-z-]+)/`),
		regexp.MustCompile(`runID := "([a-z-]+)/`),
	}
	for _, dir := range []string{"../lifecycle", ".", "../imagegen"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range re {
				for _, m := range r.FindAllStringSubmatch(string(raw), -1) {
					kinds[m[1]] = f
				}
			}
		}
	}
	if len(kinds) < 8 {
		t.Fatalf("found only %v: the patterns no longer match how runs are started", kinds)
	}
	raw, err := os.ReadFile("recover.go")
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "case \"") {
			cases = append(cases, l)
		}
	}
	var missing []string
	for k, f := range kinds {
		found := false
		for _, c := range cases {
			if strings.Contains(c, "\""+k+"\"") {
				found = true
			}
		}
		if !found {
			missing = append(missing, k+" (started in "+f+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("no case in recoverRun (internal/service/recover.go) for: %s", strings.Join(missing, ", "))
	}
}
