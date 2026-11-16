package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// bashCompletionFile finds the bash-completion package: JAILOPS_BASH_COMPLETION names its bash_completion file, the
// usual places are tried otherwise.
func bashCompletionFile() string {
	for _, p := range []string{
		os.Getenv("JAILOPS_BASH_COMPLETION"),
		"/usr/share/bash-completion/bash_completion",
		"/usr/local/share/bash-completion/bash_completion",
		"/etc/bash_completion",
	} {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// bashWords splits a command line into the words bash hands to a completion function: white space separates, a quote
// keeps what is inside it together, and each character of COMP_WORDBREAKS (the default ones) is a word of its own, so
// that jail:po is the three words jail, : and po. A line that ends in a space ends in an empty word.
func bashWords(line string) []string {
	const breaks = "><=;|&(:"
	var words []string
	cur, inWord := "", false
	var quote rune
	flush := func() {
		if inWord {
			words = append(words, cur)
		}
		cur, inWord = "", false
	}
	for _, r := range line {
		switch {
		case quote != 0:
			cur += string(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
			cur += string(r)
		case r == ' ' || r == '\t':
			flush()
		case strings.ContainsRune(breaks, r):
			flush()
			words = append(words, string(r))
		default:
			cur += string(r)
			inWord = true
		}
	}
	flush()
	if strings.HasSuffix(line, " ") && quote == 0 {
		words = append(words, "")
	}
	return words
}

// TestBashCompletion drives the generated bash script the way bash does: it sets COMP_WORDS, COMP_CWORD, COMP_LINE
// and COMP_POINT, calls the function the script registered and reads COMPREPLY, against the fake server and the real
// binary. With the bash-completion package (the usual case on a FreeBSD host) and, for hosts without it, with the
// small replacements the script brings along.
func TestBashCompletion(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bc := bashCompletionFile()

	bin := filepath.Join(t.TempDir(), "jailops")
	build := exec.Command("go", "build", "-o", bin, "./cmd/jailops")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	h := newHarness(t)
	h.seed()
	for _, args := range [][]string{
		{"jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default"},
		{"jail", "create", "db", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default"},
		{"jail", "snapshot", "create", "web", "s1"},
		{"firewall", "policy", "create", "floor", "--default-in", "deny", "--default-out", "allow"},
		{"firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"},
		{"jail", "label", "web", "tier=front"},
	} {
		if o, e, code := h.run("", args...); code != 0 {
			t.Fatalf("%v: %s %s", args, o, e)
		}
	}
	work := t.TempDir()
	for _, f := range []string{"a.yaml", "b.txt"} {
		if err := os.WriteFile(filepath.Join(work, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	type bcase struct {
		line      string   // what the user has typed, up to the cursor
		want      []string // every one of these is in COMPREPLY
		none      []string // none of these is
		empty     bool     // COMPREPLY is empty
		needsBash bool     // only with the bash-completion package
	}
	cases := []bcase{
		{line: "jailops fir", want: []string{"firewall"}},
		{line: "jailops firewall ", want: []string{"policy", "address-set", "test", "validate"}},
		{line: "jailops firewall test --", want: []string{"--from", "--to", "--proto", "--family"}},
		{line: "jailops firewall test --proto ", want: []string{"tcp", "udp", "icmp", "icmp6"}, none: []string{"jail:db"}},
		{line: "jailops firewall test --proto=", want: []string{"tcp", "udp"}},
		{line: "jailops firewall test --family ", want: []string{"4", "6"}},
		{line: "jailops firewall test --icmp-type ", want: []string{"echoreq"}},
		{line: "jailops firewall test --from ", want: []string{"jail:db", "jail:web", "host"}, none: []string{"set:office"}},
		// the colon is a word break of bash: what is replaced is the part after it
		{line: "jailops firewall test --from jail:", want: []string{"db", "web"}, none: []string{"jail:db"}},
		{line: "jailops firewall test --from jail:d", want: []string{"db"}, none: []string{"jail:db", "web"}},
		{line: "jailops firewall test --from host --to jail:", want: []string{"db", "web"}, none: []string{"jail:db"}},
		{line: "jailops firewall test --from=jail:", want: []string{"db", "web"}},
		{line: "jailops firewall test --from jail:web --to jail:db --proto ", want: []string{"tcp", "udp"}},
		{line: "jailops firewall address-set create x --address set:", want: []string{"office"}, none: []string{"set:office"}},
		{line: "jailops firewall policy create x --default-in ", want: []string{"allow", "deny"}},
		{line: `jailops firewall rule add x in --from "`, want: []string{`jail:`}},
		{line: "jailops stop ", want: []string{"web", "db"}},
		{line: "jailops stop web ", want: []string{"db"}, none: []string{"web"}},
		{line: "jailops stop -l ", want: []string{"tier="}},
		{line: "jailops --pro", want: []string{"--project"}},
		{line: "jailops --project ", want: []string{"main"}},
		{line: "jailops project set main --firewall-policy ", want: []string{"floor"}},
		{line: "jailops project set main --firewall-policy floor --firewall-policy ", want: []string{"floor"}},
		{line: "jailops project set main --hosts ", empty: false},
		{line: "jailops config set web boot.autostart ", want: []string{"true", "false"}},
		{line: "jailops config set web boot.autostart=", want: []string{"true", "false"}},
		{line: "jailops config set web boot.autostart true limits.", want: []string{"limits.memory", "limits.cpu"}},
		{line: "jailops config set web nic.eth0.network ", want: []string{"lan"}},
		{line: "jailops config set web firewall.policies ", want: []string{"floor"}},
		{line: "jailops config set web update.strategy ", want: []string{"rebase", "inplace", "manual"}},
		{line: "jailops config get web ", want: []string{"boot.autostart"}},
		{line: "jailops create x --network ", want: []string{"lan"}},
		{line: "jailops create x --layout ", want: []string{"thin", "thick"}},
		{line: "jailops create x --firewall-policy ", want: []string{"floor"}},
		{line: "jailops jail snapshot delete web ", want: []string{"s1"}},
		{line: "jailops exec web -- ", empty: true},
		{line: "jailops doctor ", empty: true},
		{line: "jailops -o ", want: []string{"table", "json", "yaml", "csv"}},
		{line: "jailops apply -f ", want: []string{"a.yaml"}, none: []string{"b.txt"}, needsBash: true},
	}

	run := func(t *testing.T, withBC bool, c bcase) {
		words := bashWords(c.line)
		var b strings.Builder
		b.WriteString("export PATH=" + shq(filepath.Dir(bin)) + ":$PATH JAILOPS_CONFIG=" + shq(h.cfgFile) + " HOME=" + shq(work) + "\n")
		b.WriteString("cd " + shq(work) + "\n")
		if withBC {
			b.WriteString("source " + shq(bc) + "\n")
		}
		b.WriteString("source <(jailops completion bash)\n")
		b.WriteString("COMP_LINE=" + shq(c.line) + "\nCOMP_POINT=${#COMP_LINE}\nCOMP_TYPE=9\nCOMP_KEY=9\n")
		b.WriteString("COMP_WORDS=(")
		for _, w := range words {
			b.WriteString(shq(w) + " ")
		}
		b.WriteString(")\nCOMP_CWORD=" + itoa(len(words)-1) + "\n")
		b.WriteString("COMPREPLY=()\n__start_jailops\nprintf '%s\\n' \"${COMPREPLY[@]}\"\n")
		cmd := exec.Command(bash, "--norc", "--noprofile", "-c", b.String())
		cmd.Env = []string{"HOME=" + work, "PATH=" + os.Getenv("PATH"), "TERM=dumb"}
		out, err := cmd.Output()
		if err != nil {
			stderr := ""
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = string(ee.Stderr)
			}
			t.Fatalf("%q: bash: %v\n%s", c.line, err, stderr)
		}
		var got []string
		for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
			if l != "" {
				got = append(got, strings.SplitN(l, "\t", 2)[0])
			}
		}
		// the script writes a description after the candidate, in brackets after two spaces
		for i, g := range got {
			got[i] = describedSuffix.ReplaceAllString(g, "")
		}
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: %q missing in %q", c.line, w, got)
			}
		}
		for _, w := range c.none {
			if slices.Contains(got, w) {
				t.Errorf("%q: %q offered in %q", c.line, w, got)
			}
		}
		if c.empty && len(got) > 0 {
			t.Errorf("%q: want nothing, got %q", c.line, got)
		}
	}

	if bc != "" {
		t.Run("with bash-completion", func(t *testing.T) {
			for _, c := range cases {
				run(t, true, c)
			}
		})
	} else {
		t.Log("bash-completion is not installed (set JAILOPS_BASH_COMPLETION): only the script's own replacements are tested")
	}
	t.Run("without bash-completion", func(t *testing.T) {
		for _, c := range cases {
			if c.needsBash {
				continue
			}
			run(t, false, c)
		}
	})
}

var describedSuffix = regexp.MustCompile(`\s{2,}\(.*\)\s*$`)

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}
