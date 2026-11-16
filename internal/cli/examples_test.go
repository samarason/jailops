package cli_test

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk/api"
)

// The examples of the help are commands a person copies. The convention: a word in capitals (NAME, FILE, JAIL,
// NAME1, FINGERPRINT, IMAGE@ALIAS) or "..." stands for a value to supply; everything else runs as written. What
// surrounds the command (sudo, VAR=value, pipes, redirections, $(...)) is the shell's.
//
// Every example line is parsed against the real command tree: the command exists, its flags exist, the number of
// arguments is right and the required flags are given. Then it runs with --dry-run against the fake server, and
// it must not end in a usage error: that catches what only the command itself checks, such as a scope an
// identity needs or a column a list does not have.

// shellWords splits the jailops invocations out of an example line: the words after each "jailops", up to a
// shell operator. Quotes are removed the way a shell removes them.
func shellWords(line string) [][]string {
	var out [][]string
	var cur []string
	var word strings.Builder
	inWord, active, quote := false, false, rune(0)
	flush := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		switch {
		case active:
			cur = append(cur, w)
		case w == "jailops":
			active, cur = true, []string{}
		}
	}
	end := func() {
		flush()
		if active {
			out = append(out, cur)
		}
		active, cur = false, nil
	}
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			flush()
		case r == '#' && !inWord:
			end()
			return out
		case strings.ContainsRune("|;&<>()", r):
			if (r == '>' || r == '<') && inWord && strings.Trim(word.String(), "0123456789") == "" {
				word.Reset() // the descriptor of 2>/dev/null
				inWord = false
			}
			end()
		case r == '$' && i+1 < len(rs) && rs[i+1] == '(':
			end()
		default:
			word.WriteRune(r)
			inWord = true
		}
	}
	end()
	return out
}

func TestShellWords(t *testing.T) {
	for line, want := range map[string]string{
		`jailops list 'web*' -c name,age`:                                           `list|web*|-c|name,age`,
		`TOKEN=$(jailops token create deploy --role operator --global 2>/dev/null)`: `token|create|deploy|--role|operator|--global`,
		`jailops events --since-id 0`:                                               `events|--since-id|0`,
		`echo 'pw' | jailops user create bob --password-file -`:                     `user|create|bob|--password-file|-`,
		`source <(jailops completion bash)`:                                         `completion|bash`,
		`jailops exec -T nginx -- cat /var/log/messages > messages`:                 `exec|-T|nginx|--|cat|/var/log/messages`,
		`jailops-sync plan`:                                                         ``,
		`jailops app list # the catalog`:                                            `app|list`,
	} {
		var got []string
		for _, w := range shellWords(line) {
			got = append(got, strings.Join(w, "|"))
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
}

type example struct {
	cmd  string // the command whose help shows it
	line string
	argv []string
}

func allExamples(t *testing.T, root *cobra.Command) []example {
	t.Helper()
	var out []example
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Hidden || c.Name() == "help" {
			return
		}
		for _, line := range strings.Split(c.Example, "\n") {
			for _, argv := range shellWords(line) {
				out = append(out, example{c.CommandPath(), line, argv})
			}
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return out
}

func TestEveryExampleParses(t *testing.T) {
	h := newHarness(t)
	exs := allExamples(t, cli.NewRootCommand(h.environ("", nil, nil)))
	if len(exs) < 300 {
		t.Fatalf("only %d examples", len(exs))
	}
	for _, ex := range exs {
		argv := ex.argv
		root := cli.NewRootCommand(h.environ("", nil, nil))
		c, rest, err := root.Find(argv)
		if err != nil {
			t.Errorf("%s: example %q: %v", ex.cmd, ex.line, err)
			continue
		}
		if c.Hidden {
			continue
		}
		if err := c.ParseFlags(rest); err != nil {
			t.Errorf("%s: example %q: %v", ex.cmd, ex.line, err)
			continue
		}
		if c.Runnable() {
			if err := c.ValidateArgs(c.Flags().Args()); err != nil {
				t.Errorf("%s: example %q: %v", ex.cmd, ex.line, err)
			}
			if err := c.ValidateRequiredFlags(); err != nil {
				t.Errorf("%s: example %q: %v", ex.cmd, ex.line, err)
			}
		}
	}
}

// notRunnable lists the examples that cannot run here, and why; nothing else may end in a usage error.
var notRunnable = map[string]string{
	"wireguard join --token-file token.txt --name office":                                           "reads a file of the host",
	"user create admin --admin --password-prompt":                                                   "asks on a terminal",
	"user set-password alice":                                                                       "asks on a terminal",
	"user create carol --role operator --projects web --password-file /root/carol.pass":             "reads a file of the host",
	"user set-password alice --password-file /root/alice.pass":                                      "reads a file of the host",
	"apply -f - --project web":                                                                      "reads a file on standard input",
	"firewall validate -f - --offline":                                                              "reads a file on standard input",
	"host certificate upload --cert fullchain.pem --key privkey.pem":                                "reads a certificate of the host",
	"host certificate upload --cert fullchain.pem --key privkey.pem --hostname console.example.org": "reads a certificate of the host",
}

// placeholder is a word that stands for a value to supply: capitals (NAME, IMAGE@ALIAS, NAME.yaml) or "...".
func placeholder(argv []string) bool {
	for _, w := range argv {
		if strings.Contains(w, "...") {
			return true
		}
		for _, part := range strings.FieldsFunc(w, func(r rune) bool { return strings.ContainsRune("@:=/,.#", r) }) {
			if len(part) > 1 && strings.Trim(part, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" && strings.Trim(part, "0123456789") != "" {
				return true
			}
		}
	}
	return false
}

func TestEveryExampleRuns(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedProject(api.Project{Metadata: api.ObjectMeta{Name: "web"}, Spec: api.ProjectSpec{
		Networks: []api.ProjectNetwork{{Network: "web"}}, Storage: []api.ProjectStorage{{Storage: "default"}}}})
	// the remotes the examples name, all of them the fake
	var cfg strings.Builder
	cfg.WriteString("current: t\nremotes:\n")
	for _, r := range []string{"t", "prod", "hub", "old"} {
		cfg.WriteString("  " + r + ":\n    url: " + h.ts.URL + "\n")
	}
	cfg.WriteString("projects:\n  t: main\n  prod: main\n  hub: main\n")
	h.writeConfig(cfg.String())
	h.env["JAILOPS_EDITOR"] = "true"
	h.timeout = 2 * time.Second // a stream (events, logs -f) ends here
	t.Chdir(t.TempDir())
	ran := 0
	for _, ex := range allExamples(t, cli.NewRootCommand(h.environ("", nil, nil))) {
		key := strings.Join(ex.argv, " ")
		if _, skip := notRunnable[key]; skip || placeholder(ex.argv) {
			continue
		}
		ran++
		_, errs, code := h.run("", append([]string{"--dry-run"}, ex.argv...)...)
		if code == 2 && strings.HasPrefix(errs, "usage: ") && !strings.Contains(errs, "confirmation required") {
			t.Errorf("%s: example %q ends in a usage error:\n%s", ex.cmd, ex.line, errs)
		}
	}
	if ran < 250 {
		t.Errorf("only %d examples ran", ran)
	}
}
