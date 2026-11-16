package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// seedDualStack adds a dual-stack network next to "lan" and two jails: web on
// lan only, db on both networks.
func (h *harness) seedDualStack() {
	h.t.Helper()
	h.seed()
	for _, args := range [][]string{
		{"network", "create", "sw", "--ipv4", "10.94.0.1/24", "--uplink", "em0", "--ipv6", "2001:db8:1:2:100::/80", "--ipv6-mode", "proxy"},
		{"network", "grant", "sw", "--project", "main"},
		{"volume", "create", "data", "--storage", "default", "--uid", "770", "--gid", "770"},
		{"jail", "create", "web", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan", "--memory", "2G", "--cpu", "2", "--label", "env=prod"},
		{"jail", "create", "db", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan", "--network", "sw"},
		{"volume", "attach", "db", "data", "/var/db"},
		{"jail", "start", "web"},
	} {
		if _, errs, code := h.run("", args...); code != 0 {
			h.t.Fatalf("seed %v: %s", args, errs)
		}
	}
}

// On a terminal the lists are short boxed tables; a jail with several
// addresses shows all of them, one per line. Pipes keep the plain form.
func TestPrettyListsOnTerminal(t *testing.T) {
	h := newHarness(t)
	h.seedDualStack()
	h.run("", "jail", "snapshot", "create", "db", "before", "-m", "before the migration")
	h.tty = true
	h.env["NO_COLOR"] = "1" // the colour is covered by TestColourOnlyOnTTY; the shape is what matters here
	tr := h.transcript()
	tr.ok("jail", "list")
	tr.ok("jail", "list", "-o", "wide")
	tr.ok("jail", "list", "--no-headers")
	tr.ok("network", "list")
	tr.ok("image", "list")
	tr.ok("project", "list")
	tr.ok("jail", "snapshot", "list", "db")
	// A narrow terminal loses the least important columns, never a character of an address.
	h.cols = 60
	tr.ok("jail", "list")
	h.cols = 30
	tr.ok("jail", "list")
	h.cols = 0
	h.tty = false
	tr.ok("jail", "list")
	tr.ok("jail", "list", "-o", "wide")
	tr.golden("pretty_lists")
}

func TestJailInfo(t *testing.T) {
	h := newHarness(t)
	h.seedDualStack()
	h.run("", "jail", "snapshot", "create", "db", "before", "-m", "first")
	h.run("", "jail", "snapshot", "create", "db", "after")
	tr := h.transcript()
	tr.ok("jail", "info", "web")
	tr.ok("jail", "info", "db")
	tr.ok("info", "db", "-o", "yaml")
	tr.ok("jail", "info", "web", "-o", "json")
	tr.do("", "jail", "info", "nope")
	tr.golden("jail_info")
	// -o name gives the name, as for every object.
	if out, _, code := h.run("", "jail", "info", "web", "-o", "name"); code != 0 || out != "web\n" {
		t.Fatalf("-o name: %d %q", code, out)
	}
}

// The generated scripts must be valid for their shell, where the shell is at hand.
func TestCompletionScriptsParse(t *testing.T) {
	h := newHarness(t)
	for shell, check := range map[string][]string{"bash": {"bash", "-n"}, "zsh": {"zsh", "-n"}, "fish": {"fish", "--no-execute"}} {
		path, err := exec.LookPath(check[0])
		if err != nil {
			t.Logf("%s is not installed: the %s script is not parsed", check[0], shell)
			continue
		}
		out, errs, code := h.run("", "completion", shell)
		if code != 0 || errs != "" {
			t.Fatalf("completion %s: %d %s", shell, code, errs)
		}
		f := filepath.Join(h.dir, "jailops."+shell)
		if err := os.WriteFile(f, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		if msg, err := exec.Command(path, append(check[1:], f)...).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse the %s completion script: %v\n%s", check[0], shell, err, msg)
		}
	}
}

// Completing names against a server that cannot be reached yields nothing and
// says nothing: the shell would show the text.
func TestCompletionWithoutServer(t *testing.T) {
	h := newHarness(t)
	h.writeConfig("")
	h.env["JAILOPS_SOCKET"] = filepath.Join(h.dir, "missing.sock")
	for _, args := range [][]string{{"jail", "show", ""}, {"jail", "create", "--image", ""}, {"--project", ""}} {
		out, errs, code := h.run("", append([]string{"__complete"}, args...)...)
		// The one line on stderr is the directive the shell scripts discard (they run __complete with 2>/dev/null).
		if code != 0 || strings.TrimSpace(errs) != "Completion ended with directive: ShellCompDirectiveNoFileComp" {
			t.Fatalf("%v: exit %d, stderr %q", args, code, errs)
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if !strings.HasPrefix(l, ":") {
				t.Fatalf("%v: unexpected completion %q", args, l)
			}
		}
	}
	// Subcommands and flags do not need a server.
	out, _, _ := h.run("", "__complete", "jail", "")
	if !strings.Contains(out, "info\t") && !strings.Contains(out, "info\n") {
		t.Fatalf("static completion: %q", out)
	}
	out, _, _ = h.run("", "__complete", "jail", "list", "--")
	if !strings.Contains(out, "--state") {
		t.Fatalf("flag completion: %q", out)
	}
}
