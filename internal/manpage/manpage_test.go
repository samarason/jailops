package manpage

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func tree() *cobra.Command {
	root := &cobra.Command{Use: "tool", Short: "A tool", Long: "The tool does things.\n\n  indented example\n\n.A line that starts with a dot and holds a back\\slash. It is long.",
		Example:     "tool jail list -o json\ntool jail create web --project web --image freebsd-15@stable --network lan --storage default --start --memory 4G",
		Run:         func(*cobra.Command, []string) {},
		Annotations: map[string]string{Environment: "TOOL_HOME\twhere the tool keeps its files", ExitStatus: "0\tsuccess\n2\ta usage error"}}
	root.PersistentFlags().StringP("output", "o", "table", "output `format`")
	jail := &cobra.Command{Use: "jail", Short: "Manage jails", Aliases: []string{"j"}}
	list := &cobra.Command{Use: "list [flags]", Short: "List jails", Run: func(*cobra.Command, []string) {}}
	list.Flags().Bool("all", false, "every jail. Even the stopped ones! Really? Yes.")
	list.Flags().String("secret", "", "hidden")
	_ = list.Flags().MarkHidden("secret")
	set := &cobra.Command{Use: "set <name> KEY=VALUE", Short: "Set a value, which is to say write it to the server where it is kept until it is set again", Run: func(*cobra.Command, []string) {}}
	hidden := &cobra.Command{Use: "man DIR", Hidden: true, Run: func(*cobra.Command, []string) {}}
	exec := &cobra.Command{Use: "exec NAME -- COMMAND [ARG...]", Short: "Run a command", Long: "A jail is a FreeBSD jail. It runs on FreeBSD, on nothing else (FreeBSD-base is not FreeBSD). Nothing runs after -- is parsed.",
		Run: func(*cobra.Command, []string) {}}
	jail.AddCommand(set, list, exec)
	root.AddCommand(jail, hidden)
	return root
}

func TestPagesAreCompleteAndDeterministic(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1761609600") // 2025-10-28
	dir := t.TempDir()
	if err := Write(tree(), dir, "toold(8)", "atool(1)"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tool.1", "tool-jail.1", "tool-jail-list.1", "tool-jail-set.1"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if !strings.Contains(s, ".Sh NAME\n.Nm "+strings.TrimSuffix(name, ".1")+"\n.Nd ") || !strings.Contains(s, ".Dd October 28, 2025") {
			t.Errorf("%s:\n%s", name, s)
		}
		for _, msg := range Lint(s) {
			t.Errorf("%s: %s", name, msg)
		}
		lint(t, filepath.Join(dir, name))
	}
	if _, err := os.Stat(filepath.Join(dir, "tool-man.1")); err == nil {
		t.Error("a hidden command got a page")
	}
	root, _ := os.ReadFile(filepath.Join(dir, "tool.1"))
	for _, want := range []string{".It Fl o , Fl -output Ar format\noutput format (default table)", "The tool does things.\n.Bd -literal -offset indent\n  indented example\n.Ed\n.Pp\n",
		`\&.A line that starts with a dot and holds a back\eslash.` + "\nIt is long.\n",
		".Sh EXAMPLES\n.Bd -literal -offset indent\ntool jail list -o json\ntool jail create web --project web --image freebsd-15@stable --network lan \\e\n    --storage default --start --memory 4G\n.Ed",
		".Sh SEE ALSO\n.Xr atool 1 ,\n.Xr tool-jail 1 ,\n.Xr toold 8\n"} {
		if !strings.Contains(string(root), want) {
			t.Errorf("tool.1 lacks %q:\n%s", want, root)
		}
	}
	list, _ := os.ReadFile(filepath.Join(dir, "tool-jail-list.1"))
	for _, want := range []string{".Sh ENVIRONMENT\n.Bl -tag -width Ds\n.It Ev TOOL_HOME\nwhere the tool keeps its files\n.El\n.Sh EXIT STATUS\n.Bl -tag -width Ds\n.It 0\nsuccess\n.It 2\na usage error\n.El\n", ".Nm tool jail list\n.Ar [flags]", ".Sh OPTIONS\n.Bl -tag -width Ds\n.It Fl -all\nevery jail.\nEven the stopped ones!\nReally?\nYes.\n.El", ".Sh GLOBAL OPTIONS", ".Xr tool-jail 1\n"} {
		if !strings.Contains(string(list), want) {
			t.Errorf("tool-jail-list.1 lacks %q:\n%s", want, list)
		}
	}
	if strings.Contains(string(list), "secret") {
		t.Error("a hidden flag is documented")
	}
	set, _ := os.ReadFile(filepath.Join(dir, "tool-jail-set.1"))
	// a long one-line description goes on inside the Nd block
	if !strings.Contains(string(set), ".Nd Set a value, which is to say write it to the server where it is kept until\nit is set again\n.Sh SYNOPSIS") || !strings.Contains(string(set), ".Ar <name> KEY=VALUE") {
		t.Errorf("tool-jail-set.1:\n%s", set)
	}
	exec, _ := os.ReadFile(filepath.Join(dir, "tool-jail-exec.1"))
	// the operating system's name is the Fx macro, with its punctuation as arguments; "--" is two hyphens
	for _, want := range []string{".Nm tool jail exec\n.Ar NAME \\-\\- COMMAND [ARG...]\n", ".Sh DESCRIPTION\nA jail is a\n.Fx\njail.\nIt runs on\n.Fx ,\non nothing else (FreeBSD-base is not\n.Fx ) .\nNothing runs after \\-\\- is parsed.\n"} {
		if !strings.Contains(string(exec), want) {
			t.Errorf("tool-jail-exec.1 lacks %q:\n%s", want, exec)
		}
	}
	jail, _ := os.ReadFile(filepath.Join(dir, "tool-jail.1"))
	if !strings.Contains(string(jail), ".Sh COMMANDS\n.Bl -tag -width Ds\n.It Cm exec\n") || !strings.Contains(string(jail), ".It Cm list\nList jails\nSee\n.Xr tool-jail-list 1 .\n.It Cm set\n") || !strings.Contains(string(jail), "Also called j.") {
		t.Errorf("tool-jail.1:\n%s", jail)
	}

	// the same tree again gives the same bytes
	again := t.TempDir()
	if err := Write(tree(), again, "toold(8)", "atool(1)"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tool.1", "tool-jail-list.1"} {
		a, _ := os.ReadFile(filepath.Join(dir, name))
		b, _ := os.ReadFile(filepath.Join(again, name))
		if string(a) != string(b) {
			t.Errorf("%s differs between two runs", name)
		}
	}
	t.Setenv("SOURCE_DATE_EPOCH", "bogus")
	if err := Write(tree(), t.TempDir()); err == nil {
		t.Error("a bad SOURCE_DATE_EPOCH was accepted")
	}
}

func TestSentencesAndWrapping(t *testing.T) {
	cases := map[string][]string{
		"One. Two! Three? Four":                          {"One.", "Two!", "Three?", "Four"},
		"e.g. the file, i.e. this one. Then (see x.) Go": {"e.g. the file, i.e. this one.", "Then (see x.)", "Go"},
		"Version 1.2 is out. 2.0 follows":                {"Version 1.2 is out. 2.0 follows"},
		`Use "-o name." Then quit.  Really.`:             {`Use "-o name."`, "Then quit.", "Really."},
		"Ends with a period.":                            {"Ends with a period."},
		"no capital. after it":                           {"no capital. after it"},
	}
	for in, want := range cases {
		if got := sentences(in); !reflect.DeepEqual(got, want) {
			t.Errorf("sentences(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("word ", 30) + ".dot 'quote " + strings.Repeat("w", 90)
	for _, l := range textLines(long) {
		if len(l) > width && !strings.HasPrefix(l, "www") {
			t.Errorf("%d bytes: %q", len(l), l)
		}
		if strings.HasPrefix(l, ".") || strings.HasPrefix(l, "'") {
			t.Errorf("control character first: %q", l)
		}
	}
	if got := textLines("a\tb\\c"); !reflect.DeepEqual(got, []string{`a b\ec`}) {
		t.Errorf("tab and backslash: %q", got)
	}
	if got := textLines("FreeBSD. On FreeBSD; FreeBSD-base, /usr/FreeBSD, -- and --x"); !reflect.DeepEqual(got, []string{".Fx .", "On", ".Fx ;", `FreeBSD-base, /usr/FreeBSD, \-\- and --x`}) {
		t.Errorf("Fx and --: %q", got)
	}
	if got := literal("  " + strings.Repeat("x", 100)); len(got) != 1 {
		t.Errorf("a line without blanks was cut: %q", got)
	}
	for _, l := range literal("    cmd " + strings.Repeat("arg ", 40)) {
		if len(l) > width || !strings.HasPrefix(l, "    ") {
			t.Errorf("continued literal line: %q", l)
		}
	}
}

func TestLint(t *testing.T) {
	bad := ".Sh DESCRIPTION\n.Pp\nOne sentence. Another one.\n" + strings.Repeat("x", 81) + "\n.Pp\n.Bl -tag -width Ds\n.It Fl a\ntrailing \n.El\nruns on FreeBSD, not elsewhere\n.Ar NAME -- CMD\n.Sh SEE ALSO\n.Xr b 8 ,\n.Xr a 1 ,\n.Xr c 1\n"
	got := Lint(bad)
	for _, want := range []string{"paragraph macro after .Sh", "new sentence, new line", "81 bytes", "paragraph macro before .Bl", "trailing blanks", "SEE ALSO: 1 a after 8 b",
		"line 10: the operating system's name without its macro", "line 11: verbatim --"} {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, want)
		}
		if !found {
			t.Errorf("Lint did not report %q in %q", want, got)
		}
	}
	if got := Lint(".Sh DESCRIPTION\nFine.\n.Bd -literal\n" + strings.Repeat("x", 90) + " \n.Ed\n.Sh SEE ALSO\n.Xr a 1 ,\n.Xr b 1\n"); len(got) != 2 {
		t.Errorf("a literal line is still measured and trailing blanks found: %q", got)
	}
}

// The hand-written pages of the daemons follow the same conventions.
func TestHandWrittenPages(t *testing.T) {
	pages, _ := filepath.Glob(filepath.Join("..", "..", "packaging", "man", "*.8"))
	if len(pages) != 4 {
		t.Fatalf("pages: %v", pages)
	}
	for _, p := range pages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range Lint(string(b)) {
			t.Errorf("%s: %s", p, msg)
		}
		if !strings.Contains(string(b), ".Sh NAME\n.Nm ") {
			t.Errorf("%s has no NAME section", p)
		}
		lint(t, p)
	}
}

// lint runs mandoc -Tlint on a page when mandoc is installed.
func lint(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("mandoc"); err != nil {
		return
	}
	// the pages are not installed while the tests run, so references to other manuals cannot be found
	out, _ := exec.Command("mandoc", "-Tlint", "-Wall", path).CombinedOutput()
	var rest []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" && !strings.Contains(l, "referenced manual not found") {
			rest = append(rest, l)
		}
	}
	if len(rest) > 0 {
		t.Errorf("mandoc -Tlint %s:\n%s", path, strings.Join(rest, "\n"))
	}
}
