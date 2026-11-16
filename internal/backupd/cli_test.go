package backupd_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/backupd"
	"jailops.net/jailops/internal/node/client"
	"jailops.net/jailops/internal/node/nodetest"
	"jailops.net/jailops/internal/testdb"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type cliRun struct {
	t   *testing.T
	cfg string
}

func (c *cliRun) run(stdin string, args ...string) (int, string, string) {
	c.t.Helper()
	var out, errb bytes.Buffer
	st := backupd.RunCLI(context.Background(), append([]string{"-c", c.cfg}, args...), strings.NewReader(stdin), &out, &errb)
	return st, out.String(), errb.String()
}

func (c *cliRun) must(stdin string, args ...string) string {
	c.t.Helper()
	st, out, errs := c.run(stdin, args...)
	if st != 0 {
		c.t.Fatalf("%v: exit %d\n%s\n%s", args, st, out, errs)
	}
	return out
}

func TestCommandLineFromInitToDeletion(t *testing.T) {
	dir, err := os.MkdirTemp("", "jo")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	port := freePort(t)
	dsnFile := filepath.Join(dir, "dsn")
	if err := os.WriteFile(dsnFile, []byte(testdb.New(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "backupd.yaml")
	cfg := fmt.Sprintf(`
hostname: clinode
listen: 127.0.0.1:%d
admin_socket: %s
tls: {cert_file: %s, key_file: %s}
database: {dsn_file: %s}
datastore: {kind: directory, directory: %s}
grace: 12h
deletion_delay: 48h
`, port, filepath.Join(dir, "sock"), filepath.Join(dir, "n.crt"), filepath.Join(dir, "n.key"), dsnFile, filepath.Join(dir, "repo"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &cliRun{t: t, cfg: cfgPath}

	// a datastore directory that does not exist yet is created by the backend; init is the first command
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte("an admin password of some length\n"), 0o600)
	out := c.must("", "init", "--admin", "boss", "--password-file", pwFile)
	m := regexp.MustCompile(`pin this\): ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "datastore probe: ok") || !strings.Contains(out, "administrator boss created") {
		t.Fatalf("init output:\n%s", out)
	}
	nodeFP := m[1]
	// a second init is not an error: it reports the repository and its owner
	if out := c.must("", "init"); !strings.Contains(out, "already initialised (owner node-") || !strings.Contains(out, nodeFP) {
		t.Fatalf("a second init:\n%s", out)
	}
	// the secret file rule
	_ = os.Chmod(dsnFile, 0o644)
	if st, _, errs := c.run("", "users", "list"); st == 0 || !strings.Contains(errs, "readable by group or others") {
		t.Fatalf("a world-readable dsn file: %d %s", st, errs)
	}
	_ = os.Chmod(dsnFile, 0o600)

	// a host: its certificate, enrolled from the PEM
	cert, certPEM, _, err := auth.GenerateCertificate(auth.CertOptions{CommonName: "cli-host"})
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "host.crt")
	_ = os.WriteFile(certFile, certPEM, 0o644)
	out = c.must("", "hosts", "enroll", "cli-host", "--cert", certFile, "--note", "from a test")
	hostFP := auth.Fingerprint(cert.Certificate[0])
	if !strings.Contains(out, hostFP) || !strings.Contains(out, nodeFP) {
		t.Fatalf("enroll output:\n%s", out)
	}
	if st, _, _ := c.run("", "hosts", "enroll", "cli-host", "--fingerprint", hostFP); st == 0 {
		t.Fatal("a duplicate enrolment")
	}
	if st, _, _ := c.run("", "hosts", "enroll", "evil", "--fingerprint", strings.Repeat("a", 64), "--scopes", "backup-admin"); st == 0 {
		t.Fatal("administration accepted as a host scope")
	}
	if out := c.must("", "hosts", "list"); !strings.Contains(out, "cli-host") || !strings.Contains(out, "active") {
		t.Fatal(out)
	}
	c.must("another password long enough\n", "users", "add", "viewer", "readonly")
	if out := c.must("", "users", "list"); !strings.Contains(out, "boss") || !strings.Contains(out, "viewer") {
		t.Fatal(out)
	}
	if st, _, _ := c.run("short\n", "users", "add", "weak", "admin"); st == 0 {
		t.Fatal("a weak password")
	}

	// admin commands need the daemon
	if st, _, errs := c.run("", "status"); st == 0 || !strings.Contains(errs, "admin socket") {
		t.Fatalf("status without a daemon: %d %s", st, errs)
	}
	sctx, stop := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		var o, e bytes.Buffer
		done <- backupd.RunCLI(sctx, []string{"-c", cfgPath, "serve"}, strings.NewReader(""), &o, &e)
	}()
	t.Cleanup(func() { stop(); <-done })
	for i := 0; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, "sock")); err == nil {
			if st, _, _ := c.run("", "status"); st == 0 {
				break
			}
		}
		if i > 200 {
			t.Fatal("the daemon did not come up")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// a backup from the enrolled host through the real listener
	f := nodetest.NewFixture(t, 5)
	g := f.Group("cli-host", "web")
	cl, err := client.New(client.Config{Address: fmt.Sprintf("127.0.0.1:%d", port), Fingerprint: nodeFP, Cert: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	b := f.NewBackup(t, g, nodetest.SnapshotID(time.Now(), 1), manyChunks(t, f, 6))
	upload(t, cl, b, "")

	if out := c.must("", "status"); !strings.Contains(out, "snapshots 1 in 1 groups") || !strings.Contains(out, "mode online") {
		t.Fatalf("status:\n%s", out)
	}
	if out := c.must("", "status", "--json"); !strings.Contains(out, `"snapshots": 1`) {
		t.Fatalf("status --json:\n%s", out)
	}
	if out := c.must("", "gc", "--dry-run"); !strings.Contains(out, "succeeded") || !strings.Contains(out, `"dry_run": true`) {
		t.Fatalf("gc:\n%s", out)
	}
	if st, _, errs := c.run("", "gc", "--grace", "1h"); st == 0 || !strings.Contains(errs, "shorter than the minimum") {
		t.Fatalf("gc with a short grace: %d %s", st, errs)
	}
	if out := c.must("", "verify", "all"); !strings.Contains(out, "succeeded") || !strings.Contains(out, `"snapshots": 1`) {
		t.Fatalf("verify:\n%s", out)
	}
	if out := c.must("", "verify"); !strings.Contains(out, `"skipped": 1`) {
		t.Fatalf("verify new after verify all:\n%s", out)
	}
	if out := c.must("", "retention", "--dry-run"); !strings.Contains(out, "succeeded") {
		t.Fatalf("retention:\n%s", out)
	}
	if out := c.must("", "reconcile"); !strings.Contains(out, "succeeded") {
		t.Fatal(out)
	}
	c.must("", "protect", g, b.Snapshot)
	if st, _, _ := c.run("", "delete", "request", g, b.Snapshot); st == 0 {
		t.Fatal("a deletion request for a protected snapshot")
	}
	c.must("", "unprotect", g, b.Snapshot)
	if out := c.must("", "delete", "request", g, b.Snapshot, "--delay", "48h"); !strings.Contains(out, "can be executed after") {
		t.Fatal(out)
	}
	if st, _, errs := c.run("", "delete", "execute", g, b.Snapshot); st == 0 || !strings.Contains(errs, "becomes executable") {
		t.Fatalf("an early execute: %d %s", st, errs)
	}
	c.must("", "delete", "cancel", g, b.Snapshot)
	if out := c.must("", "maintenance"); strings.TrimSpace(out) != "online" {
		t.Fatal(out)
	}
	c.must("", "maintenance", "read-only")
	if _, err := cl.Begin(ctx, g, nodetest.SnapshotID(time.Now(), 2), ""); err == nil || code(err) != "maintenance" {
		t.Fatalf("a host during maintenance: %v", err)
	}
	if st, _, _ := c.run("", "maintenance", "bogus"); st == 0 {
		t.Fatal("a bogus mode")
	}
	c.must("", "maintenance", "online")
	if out := c.must("", "quarantine", "list"); !strings.Contains(out, "CHUNK") {
		t.Fatal(out)
	}
	if out := c.must("", "jobs"); !strings.Contains(out, "verify") || !strings.Contains(out, "gc") {
		t.Fatal(out)
	}
	c.must("", "hosts", "revoke", "cli-host")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := cl.Info(ctx); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked host is still served")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if out := c.must("", "version"); !strings.Contains(out, "schema 0001") {
		t.Fatal(out)
	}
}
