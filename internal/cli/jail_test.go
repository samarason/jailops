package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// mutations returns the non-GET requests the server saw, as "METHOD path".
func (h *harness) mutations() []string {
	var out []string
	for _, r := range h.srv.Requests() {
		if r.Method != "GET" {
			out = append(out, r.Method+" "+r.Path)
		}
	}
	return out
}

func (h *harness) lastBody(method, path string) []byte {
	reqs := h.srv.Requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].Method == method && reqs[i].Path == path {
			return reqs[i].Body
		}
	}
	return nil
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJailLifecycle(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan", "--memory", "2G", "--label", "env=prod", "--autostart")
	tr.ok("volume", "create", "data", "--storage", "default")
	tr.ok("jail", "create", "db", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan", "--env", "A=1")
	tr.ok("volume", "attach", "db", "data", "/srv/data", "--ro")
	tr.ok("jail", "list")
	tr.ok("jail", "start", "web")
	tr.ok("jail", "list")
	tr.ok("jail", "list", "--state", "running", "-o", "name")
	tr.ok("jail", "list", "-l", "env=prod", "--no-headers")
	tr.ok("jail", "list", "--network", "other")
	tr.ok("jail", "show", "web")
	tr.ok("jail", "restart", "web", "--grace", "5")
	tr.ok("jail", "stop", "web", "--force")
	tr.do("", "jail", "delete", "-y", "db") // data loss: -y does not answer it
	tr.do("web\n", "jail", "delete", "db")  // the wrong name
	if _, ok := h.srv.JailIn("main", "db"); !ok {
		t.Fatal("db deleted without its name typed")
	}
	tr.do("db\n", "jail", "delete", "db")
	tr.do("", "jail", "delete", "web") // running, no --force: refused before the question
	tr.do("", "jail", "show", "db")
	tr.golden("jail_lifecycle")
	if _, ok := h.srv.JailIn("main", "db"); ok {
		t.Fatal("db survived delete")
	}
}

func TestJailCreateFromFiles(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	env := writeFile(t, h.dir, "env.yaml", `apiVersion: jailops/v1
kind: Jail
metadata:
  name: web
  labels: {tier: front}
spec:
  image: freebsd-15@stable
  storage: default
  network:
    - network: lan
      ipv4: auto
  resources: {memory: 1G}
`, 0o644)
	bare := writeFile(t, h.dir, "bare.yaml", "image: freebsd-15#g1\nhostname: bare.example\nstorage: default\nnetwork: [{network: lan}]\n", 0o644)
	multi := writeFile(t, h.dir, "multi.yaml", "kind: Jail\nmetadata: {name: m1}\nspec: {image: freebsd-15@stable, storage: default, network: [{network: lan}]}\n---\nkind: Jail\nmetadata: {name: m2}\nspec: {image: freebsd-15@stable, storage: default, network: [{network: lan}]}\n", 0o644)
	typo := writeFile(t, h.dir, "typo.yaml", "image: freebsd-15@stable\nmemmory: 1G\n", 0o644)
	wrongKind := writeFile(t, h.dir, "wk.yaml", "kind: Network\nmetadata: {name: x}\nspec: {}\n", 0o644)
	tr.ok("jail", "create", "-f", env)
	tr.ok("jail", "create", "bare", "-f", bare)
	tr.ok("jail", "create", "-f", multi)
	tr.do("", "jail", "create", "-f", bare) // bare spec without a name
	tr.do("", "jail", "create", "x", "-f", typo)
	tr.do("", "jail", "create", "-f", wrongKind)
	tr.do("", "jail", "create", "web", "-f", env) // duplicate
	out, _, code := tr.do("kind: Jail\nmetadata: {name: viastdin}\nspec: {image: freebsd-15@stable, storage: default, network: [{network: lan}]}\n", "jail", "create", "-f", "-")
	if code != 0 || !strings.Contains(out, "jail/viastdin created") {
		t.Fatalf("stdin create: %d %s", code, out)
	}
	tr.ok("jail", "show", "web", "-o", "yaml")
	tr.golden("jail_create_files")
	j, _ := h.srv.JailIn("main", "web")
	if j.Metadata.Labels["tier"] != "front" || j.Spec.Resources.Memory != "1G" {
		t.Fatalf("envelope not applied: %+v", j)
	}
	if b, _ := h.srv.JailIn("main", "bare"); b.Spec.Hostname != "bare.example" {
		t.Fatalf("bare spec not applied: %+v", b)
	}
}

func TestJailSnapshotAndCopy(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan=10.20.0.15")
	tr.ok("jail", "snapshot", "create", "web", "s1", "-m", "first")
	tr.ok("jail", "snapshot", "create", "web", "s2")
	h.srv.SetSnapshotWritten("main", "web", "s2", 3<<20)
	tr.ok("jail", "snapshot", "list", "web")
	tr.ok("jail", "snapshot", "show", "web", "s2")
	tr.ok("jail", "snapshot", "show", "web", "s1", "-o", "yaml")
	tr.do("", "jail", "snapshot", "show", "web", "nope")
	tr.do("", "jail", "snapshot", "delete", "web", "s1") // no -y, no stdin
	tr.ok("jail", "snapshot", "delete", "-y", "web", "s1")
	tr.do("y\n", "jail", "snapshot", "delete", "web", "s2")
	tr.ok("jail", "copy", "web", "web2")
	tr.ok("jail", "show", "web2", "-o", "json")
	tr.ok("jail", "copy", "web", "web3", "--keep-ip", "--dry-run")
	tr.do("", "jail", "copy", "web", "web2")
	tr.do("", "jail", "exec", "web", "--", "ls")
	tr.do("", "jail", "console", "web")
	tr.golden("jail_snapshot_copy")
	if got := h.srv.Snapshots("main", "web"); len(got) != 0 {
		t.Fatalf("snapshots left: %v", got)
	}
}

func TestJailRollbackConfirmation(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	tr.ok("jail", "snapshot", "create", "web", "good")
	tr.ok("jail", "snapshot", "create", "web", "newer")
	h.srv.SetSnapshotWritten("main", "web", "good", 1536*1024)
	h.srv.SetSnapshotWritten("main", "web", "newer", 10)
	base := len(h.mutations())
	rolled := func() bool {
		for _, m := range h.mutations()[base:] {
			if strings.HasSuffix(m, "/rollback") {
				return true
			}
		}
		return false
	}

	// No answer available: refuses and exits with the usage code.
	_, errs, code := tr.do("", "jail", "rollback", "web", "--data", "--snapshot", "good")
	if code != 2 || rolled() || !strings.Contains(errs, "--confirm-data-loss") {
		t.Fatalf("no answer: code %d rolled %v: %s", code, rolled(), errs)
	}
	// -y never satisfies data loss.
	_, _, code = tr.do("", "jail", "rollback", "web", "--data", "--snapshot", "good", "-y")
	if code != 2 || rolled() {
		t.Fatalf("-y: code %d rolled %v", code, rolled())
	}
	// A wrong name aborts.
	_, errs, code = tr.do("nope\n", "jail", "rollback", "web", "--data", "--snapshot", "good")
	if code != 1 || rolled() || !strings.Contains(errs, "aborted") {
		t.Fatalf("wrong name: code %d rolled %v: %s", code, rolled(), errs)
	}
	// Dry run shows the bytes and sends nothing.
	out, _, code := tr.do("", "jail", "rollback", "web", "--data", "--snapshot", "good", "--dry-run")
	if code != 0 || rolled() || !strings.Contains(out, "1.5 MiB written") {
		t.Fatalf("dry-run: %d %v %s", code, rolled(), out)
	}
	// Mixed scopes are a usage error.
	_, _, code = tr.do("", "jail", "rollback", "web", "--data", "--all")
	if code != 2 {
		t.Fatalf("scopes: %d", code)
	}
	// Typing the name proceeds; the latest snapshot is used by default and
	// the request carries the confirmation.
	out, _, code = tr.do("web\n", "jail", "rollback", "web", "--data")
	if code != 0 || !rolled() {
		t.Fatalf("typed: %d %v %s", code, rolled(), out)
	}
	var rb api.JailRollback
	if err := json.Unmarshal(h.lastBody("POST", "/api/v1/jails/web/rollback"), &rb); err != nil {
		t.Fatal(err)
	}
	if rb.Scope != api.RollbackData || rb.Snapshot != "newer" || !rb.ConfirmDataLoss {
		t.Fatalf("request: %+v", rb)
	}
	// The flag proceeds without a prompt.
	h.srv.SetSnapshotWritten("main", "web", "good", 2048)
	out, _, code = tr.do("", "jail", "rollback", "web", "--all", "--snapshot", "good", "--confirm-data-loss")
	if code != 0 || !strings.Contains(out, "2.0 KiB written") {
		t.Fatalf("flag: %d %s", code, out)
	}
	// Root rollback needs an earlier generation: the fake says invalid.
	_, _, code = tr.do("", "jail", "rollback", "web")
	if code != 2 {
		t.Fatalf("root without history: %d", code)
	}
	h.srv.SeedGeneration("freebsd-15")
	tr.ok("jail", "upgrade", "web")
	tr.ok("jail", "rollback", "web", "--root")
	tr.golden("jail_rollback")
}

func TestJailUpgrade(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.SeedGeneration("freebsd-15")
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15#g1", "--network", "lan", "--storage", "default")
	before := len(h.mutations())
	tr.ok("jail", "upgrade", "web", "--dry-run")
	if j, _ := h.srv.JailIn("main", "web"); j.Status.Generation != "g1" {
		t.Fatalf("dry-run upgraded the jail: %+v", j.Status)
	}
	var up api.JailUpgrade
	_ = json.Unmarshal(h.lastBody("POST", "/api/v1/jails/web/upgrade"), &up)
	if !up.DryRun || len(h.mutations()) != before+1 {
		t.Fatalf("dry-run request: %+v %v", up, h.mutations())
	}
	tr.ok("jail", "upgrade", "web")
	tr.do("", "jail", "upgrade", "web") // already current
	tr.ok("jail", "show", "web")
	tr.golden("jail_upgrade")
}

func TestJailEditorFlow(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	sed := writeFile(t, h.dir, "ed-sed.sh", "#!/bin/sh\nsed 's/hostname: web/hostname: edited/' \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"\n", 0o755)
	noop := writeFile(t, h.dir, "ed-noop.sh", "#!/bin/sh\nexit 0\n", 0o755)
	empty := writeFile(t, h.dir, "ed-empty.sh", "#!/bin/sh\n: > \"$1\"\n", 0o755)
	broken := writeFile(t, h.dir, "ed-broken.sh", "#!/bin/sh\nprintf 'spec: [unclosed\\n' >> \"$1\"\n", 0o755)
	typo := writeFile(t, h.dir, "ed-typo.sh", "#!/bin/sh\nsed 's/hostname: web/hostnme: x/' \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"\n", 0o755)
	fail := writeFile(t, h.dir, "ed-fail.sh", "#!/bin/sh\nexit 3\n", 0o755)
	rename := writeFile(t, h.dir, "ed-rename.sh", "#!/bin/sh\nsed 's/name: web/name: other/' \"$1\" > \"$1.new\" && mv \"$1.new\" \"$1\"\n", 0o755)

	h.env["EDITOR"] = noop
	tr.ok("jail", "edit", "web")
	h.env["EDITOR"] = empty
	tr.ok("jail", "edit", "web")
	h.env["EDITOR"] = typo
	tr.do("", "jail", "edit", "web")
	h.env["EDITOR"] = broken
	tr.do("", "jail", "edit", "web")
	h.env["EDITOR"] = rename
	tr.do("", "jail", "edit", "web")
	h.env["EDITOR"] = fail
	tr.do("", "jail", "edit", "web")
	// the create, and the dry run of the rename the changed name asked about (not confirmed: no answer)
	if m := h.mutations(); len(m) != 2 || !strings.HasSuffix(m[1], "/rename") {
		t.Fatalf("failed edits must not write: %v", m)
	}
	if _, ok := h.srv.JailIn("main", "other"); ok {
		t.Fatal("an unconfirmed rename renamed the jail")
	}
	h.env["EDITOR"] = sed + " " // trailing blanks are tolerated
	tr.do("", "jail", "edit", "web", "--dry-run")
	if j, _ := h.srv.JailIn("main", "web"); j.Spec.Hostname != "web" {
		t.Fatal("dry-run edit changed the jail")
	}
	tr.ok("jail", "edit", "web")
	j, _ := h.srv.JailIn("main", "web")
	if j.Spec.Hostname != "edited" {
		t.Fatalf("edit not applied: %+v", j.Spec)
	}
	// -f replaces from a file.
	f := writeFile(t, h.dir, "new.yaml", "image: freebsd-15@stable\nhostname: viafile\nstorage: default\nnetwork: [{network: lan}]\n", 0o644)
	tr.ok("jail", "edit", "web", "-f", f)
	if j, _ = h.srv.JailIn("main", "web"); j.Spec.Hostname != "viafile" {
		t.Fatalf("-f edit: %+v", j.Spec)
	}
	// VISUAL beats EDITOR; JAILOPS_EDITOR beats both.
	h.env["EDITOR"], h.env["VISUAL"] = fail, sed
	h.env["JAILOPS_EDITOR"] = noop
	tr.ok("jail", "edit", "web")
	tr.golden("jail_edit")
}

func TestJailEditorConflict(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	// The editor waits until the test has changed the jail underneath it.
	ready, gate := filepath.Join(h.dir, "ready"), filepath.Join(h.dir, "go")
	script := writeFile(t, h.dir, "ed-wait.sh", fmt.Sprintf(`#!/bin/sh
sed 's/hostname: web/hostname: mine/' "$1" > "$1.new" && mv "$1.new" "$1"
touch %s
while [ ! -f %s ]; do sleep 0.02; done
`, ready, gate), 0o755)
	h.env["EDITOR"] = script
	type res struct {
		out, errs string
		code      int
	}
	done := make(chan res, 1)
	go func() {
		o, e, c := h.run("", "jail", "edit", "web")
		done <- res{o, e, c}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("editor never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.srv.Touch("main", "web")
	_ = os.WriteFile(gate, nil, 0o600)
	r := <-done
	if r.code != 5 || !strings.HasPrefix(r.errs, "conflict:") || !strings.Contains(r.errs, "hint: someone changed the jail") {
		t.Fatalf("conflict: %d %q", r.code, r.errs)
	}
	if j, _ := h.srv.JailIn("main", "web"); j.Spec.Hostname != "web" {
		t.Fatal("stale edit overwrote the jail")
	}
}

func TestDryRunSendsNothing(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.run("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	h.run("", "jail", "snapshot", "create", "web", "s1")
	n := len(h.mutations())
	tr := h.transcript()
	netFile := writeFile(t, h.dir, "net.yaml", "subnet-less: true\n", 0o644)
	_ = netFile
	for _, args := range [][]string{
		{"jail", "create", "x", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default"},
		{"jail", "start", "web"},
		{"jail", "stop", "web"},
		{"jail", "restart", "web"},
		{"jail", "delete", "-y", "web"},
		{"jail", "snapshot", "create", "web", "s2"},
		{"jail", "snapshot", "delete", "-y", "web", "s1"},
		{"jail", "rollback", "web", "--all", "--snapshot", "s1"},
		{"jail", "copy", "web", "w2"},
		{"network", "create", "n2", "--subnet", "10.1.0.0/24", "--gateway", "10.1.0.1", "--range", "10.1.0.5-10.1.0.9"},
		{"network", "delete", "-y", "lan"},
		{"image", "alias", "add", "freebsd-15", "x"},
		{"image", "alias", "remove", "-y", "freebsd-15", "x"},
		{"image", "generation", "delete", "-y", "freebsd-15", "1"},
		{"firewall", "address-set", "create", "s", "--address", "10.0.0.0/8"},
		{"token", "create", "t1", "--global"},
		{"user", "create", "bob", "--global"},
		{"user", "disable", "bob"},
		{"op", "cancel", "abc"},
		{"backup", "run", "p"},
		{"remote", "remove", "t"},
		{"remote", "switch", "local"},
	} {
		tr.ok(append([]string{"--dry-run"}, args...)...)
	}
	tr.ok("--dry-run", "-o", "json", "jail", "start", "web")
	if got := h.mutations(); len(got) != n {
		t.Fatalf("dry-run sent changes: %v", got[n:])
	}
	if _, err := os.Stat(h.cfgFile); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(h.cfgFile)
	if !strings.Contains(string(b), "current: t") {
		t.Fatalf("dry-run changed the config: %s", b)
	}
	tr.golden("dry_run")
}

func TestOperationsNoWaitAndWait(t *testing.T) {
	h := newHarness(t, fake.WithHostName("alpha"))
	h.seed()
	tr := h.transcript()
	h.srv.SetOperationDelay(150 * time.Millisecond)
	out := tr.ok("jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--no-wait", "-o", "name")
	id := strings.TrimSpace(out)
	if len(id) != 36 {
		t.Fatalf("operation id %q", id)
	}
	tr.ok("op", "wait", id)
	tr.ok("op", "list")
	tr.ok("op", "list", "--active")
	tr.ok("op", "show", id, "-o", "yaml")
	tr.do("", "op", "show", "nonexistent")
	tr.ok("jail", "create", "w2", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--no-wait")
	// A timeout leaves the operation running and says how to follow it.
	h.srv.SetOperationDelay(2 * time.Second)
	_, errs, code := tr.do("", "jail", "start", "web", "--timeout", "100ms")
	if code != 1 || !strings.Contains(errs, "timed out") || !strings.Contains(errs, "jailops op wait") {
		t.Fatalf("timeout: %d %s", code, errs)
	}
	h.srv.SetOperationDelay(0)
	tr.golden("operations")
}

func TestOperationFailureAndCancel(t *testing.T) {
	h := newHarness(t)
	h.seed()
	h.srv.FailOperation("jails.create", api.Errorf(api.CodePoolExhausted, "no addresses left").WithHint("widen the range"))
	tr := h.transcript()
	_, _, code := tr.do("", "jail", "create", "web", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default")
	if code != 5 {
		t.Fatalf("pool_exhausted exit %d", code)
	}
	h.srv.SetOperationDelay(5 * time.Second)
	out := tr.ok("jail", "create", "slow", "--image", "freebsd-15@stable", "--network", "lan", "--storage", "default", "--no-wait", "-o", "name")
	id := strings.TrimSpace(out)
	tr.ok("op", "cancel", id)
	_, _, code = tr.do("", "op", "wait", id)
	if code != 1 {
		t.Fatalf("cancelled wait exit %d", code)
	}
	tr.golden("operation_failure")
}
