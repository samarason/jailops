package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// ptyDriver drives an interactive bash on a pseudo terminal: for each case it types the text and the keys, reads what
// bash shows and clears the line. It prints "=== TYPED ===" and the screen text per case. The optional second argument
// is a bash-completion script to source first.
const ptyDriver = `
import os, pty, select, sys, time, json
cases = json.loads(sys.argv[1])
bc = sys.argv[2] if len(sys.argv) > 2 else ""
env = dict(os.environ, PS1="$ ", TERM="dumb", INPUTRC="/dev/null")
pid, fd = pty.fork()
if pid == 0:
    os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], env)
def read(quiet=0.5, limit=8.0):
    out = b""; end = time.time() + limit; last = time.time()
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                break
            if not d:
                break
            out += d; last = time.time()
        elif time.time() - last > quiet:
            break
    return out.decode("utf-8", "replace")
def send(s): os.write(fd, s.encode())
read()
send("bind 'set show-all-if-ambiguous on'; bind 'set bell-style none'\n"); read()
if bc:
    send("source %s\n" % bc); read()
send("source <(jailops completion bash)\n"); read()
for c in cases:
    send(c["typed"] + c["keys"])
    text = read()
    send("\x15\x03"); read(0.2)
    print("=== %s ===" % c["typed"]); print(text)
send("exit\n")
`

// Completion of a reference in a real bash, which splits a word at a colon: the kinds after a Tab, the names after a
// kind, inside a quoted value too. It runs the generated completion script in an interactive bash (python3 drives
// the terminal) after sourcing the bash-completion package, which the generated script needs: it is opt-in, with
// BASH_COMPLETION_SCRIPT set to the package's bash_completion file (for example /usr/share/bash-completion/bash_completion).
// Without it, bash, python3 or go it is skipped.
func TestBashCompletionOfReferences(t *testing.T) {
	if os.Getenv("BASH_COMPLETION_SCRIPT") == "" {
		t.Skip("set BASH_COMPLETION_SCRIPT to the bash-completion package's bash_completion file to run this")
	}
	for _, tool := range []string{"bash", "python3", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	for _, args := range [][]string{
		{"app", "install", "postgresql", "db", "--image", "freebsd-151@stable"},
		{"app", "install", "nginx", "web", "--image", "freebsd-151@stable"},
		{"firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"},
	} {
		if o, e, code := h.run("", args...); code != 0 {
			t.Fatalf("%v: %s %s", args, o, e)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "jailops")
	if out, err := exec.Command("go", "build", "-o", bin, "jailops.net/jailops/cmd/jailops").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	script := filepath.Join(dir, "drive_bash.py")
	if err := os.WriteFile(script, []byte(ptyDriver), 0o600); err != nil {
		t.Fatal(err)
	}
	type tc struct {
		Typed string `json:"typed"`
		Keys  string `json:"keys"`
	}
	cases := []tc{
		{`jailops firewall address-set create s --address `, "\t\t"},
		{`jailops firewall address-set create s --address ja`, "\t"},
		{`jailops firewall address-set create s --address jail:`, "\t\t"},
		{`jailops firewall rule add p in --from "`, "\t\t"},
		{`jailops firewall rule add p in --from "ja`, "\t"},
		{`jailops firewall rule add p in --from "jail:`, "\t\t"},
		{`jailops app allow db --from `, "\t\t"},
		{`jailops firewall test --from jail:`, "\t\t"},
	}
	arg, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{script, string(arg)}
	if bc := os.Getenv("BASH_COMPLETION_SCRIPT"); bc != "" {
		args = append(args, bc)
	}
	cmd := exec.Command("python3", args...)
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "JAILOPS_CONFIG="+h.cfgFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	screens := map[string]string{}
	for _, part := range strings.Split(string(out), "=== ")[1:] {
		head, body, _ := strings.Cut(part, " ===\n")
		screens[head] = body
	}
	for _, c := range []struct {
		typed string
		want  []string
		none  []string
	}{
		{cases[0].Typed, []string{"jail:", "set:"}, []string{"host", "tag:"}},
		{cases[1].Typed, []string{"--address jail:"}, []string{"set:"}},
		{cases[2].Typed, []string{"web", "db"}, []string{"office"}},
		{cases[3].Typed, []string{"jail:", "set:", "tag:", "any"}, []string{"host"}},
		{cases[4].Typed, []string{"from jail:"}, nil},
		{cases[5].Typed, []string{"web", "db"}, []string{"office"}},
		{cases[6].Typed, []string{"jail:", "set:", "host"}, []string{"tag:"}},
		{cases[7].Typed, []string{"web", "db"}, []string{"office"}},
	} {
		screen, ok := screens[c.typed]
		if !ok {
			t.Errorf("no screen for %q in:\n%s", c.typed, out)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(screen, w) {
				t.Errorf("%q + Tab: %q is not shown:\n%s", c.typed, w, screen)
			}
		}
		for _, w := range c.none {
			if strings.Contains(strings.ReplaceAll(screen, c.typed, ""), w) {
				t.Errorf("%q + Tab: %q is shown:\n%s", c.typed, w, screen)
			}
		}
	}
}

// The generated bash script asks the program through eval, which refuses an unfinished quote: a value typed as
// --from "ja<Tab> would complete nothing. The script closes the quote of the last word first, so the
// request reaches the program. This runs the script's own function in bash (no bash-completion package needed).
func TestBashScriptClosesAnUnfinishedQuote(t *testing.T) {
	for _, tool := range []string{"bash", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is not installed")
		}
	}
	h := newHarness(t)
	if o, e, code := h.run("", "firewall", "address-set", "create", "office", "--address", "198.51.100.0/24"); code != 0 {
		t.Fatalf("%s %s", o, e)
	}
	script, _, code := h.run("", "completion", "bash")
	if code != 0 || !strings.Contains(script, `\"*) [[ ${#lastParam} -eq 1`) {
		t.Fatalf("the generated script does not close an unfinished quote (exit %d)", code)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "jailops")
	if out, err := exec.Command("go", "build", "-o", bin, "jailops.net/jailops/cmd/jailops").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	file := filepath.Join(dir, "jailops.bash")
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ last, want string }{
		{`"ja`, "jail:"},
		{`'ja`, "jail:"},
		{`"ja"`, "jail:"},
		{`"set:o`, "set:office"}, // a name after a kind, the colon inside the word
	} {
		cmd := exec.Command("bash", "-c", `source "$1"; words=("$2" firewall rule add p in --from "$3"); cur="$3"; __jailops_get_completion_results; printf '%s' "$out"`, "bash", file, bin, c.last)
		cmd.Env = append(os.Environ(), "JAILOPS_CONFIG="+h.cfgFile)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%q: %v\n%s", c.last, err, out)
		}
		if !strings.Contains(string(out), c.want) {
			t.Errorf("%s: the program was not asked, or answered %q, want %q", c.last, out, c.want)
		}
	}
}
