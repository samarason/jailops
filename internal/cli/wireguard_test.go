package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWireGuardCommands(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.do("", "wireguard", "create", "office", "--address", "10.99.0.1/24", "--network", "lan", "--endpoint", "vpn.example.com:51820")
	tr.do("", "wireguard", "create", "bad", "--mode", "client", "--address", "10.98.0.2/32")
	tr.ok("--dry-run", "wireguard", "peer", "add", "office", "laptop")
	token := strings.TrimSpace(tr.ok("wireguard", "peer", "add", "office", "laptop"))
	if !strings.HasPrefix(token, "jwg1.") {
		t.Fatalf("token %q", token)
	}
	tr.ok("wireguard", "peer", "add", "office", "phone", "--format", "conf")
	tr.do("", "wireguard", "peer", "add", "office", "laptop")
	tr.ok("wireguard", "peer", "list", "office")
	tr.ok("wireguard", "peer", "show", "office", "phone")
	tr.do("", "wireguard", "peer", "show", "office", "ghost")
	tr.ok("wireguard", "status", "office")
	tokenFile := writeFile(t, h.dir, "wg.token", token+"\n", 0o600)
	tr.ok("--dry-run", "wireguard", "join", "laptop", "--token-file", tokenFile)
	tr.do("", "wireguard", "join", "laptop")
	tr.do("", "wireguard", "join")
	tr.ok("wireguard", "join", "home", "--token-file", tokenFile, "--endpoint", "203.0.113.10:51820")
	tr.do("", "wireguard", "join", "broken", "--token-file", writeFile(t, h.dir, "bad.token", "not-a-token\n", 0o600))
	tr.ok("wireguard", "list")
	tr.ok("wireguard", "status", "home")
	tr.ok("wireguard", "down", "home")
	tr.ok("wireguard", "up", "home")
	tr.ok("-y", "wireguard", "rotate-keys", "office")
	tr.ok("-y", "wireguard", "peer", "remove", "office", "laptop")
	tr.ok("wireguard", "peer", "list", "office", "-o", "name")
	tr.ok("-y", "wireguard", "delete", "home")
	tr.ok("wireguard", "list", "-o", "name")
	tr.golden("wireguard")
	if strings.Contains(tr.buf.String(), "PrivateKey = ") == false {
		t.Fatal("--format conf printed no configuration")
	}
}

// A token read from standard input stays out of the arguments (and the shell history).
func TestWireGuardJoinFromStdin(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tok, _, code := h.run("", "wireguard", "create", "office", "--address", "10.99.0.1/24")
	if code != 0 {
		t.Fatal(tok)
	}
	tok, errs, code := h.run("", "wireguard", "peer", "add", "office", "laptop")
	if code != 0 {
		t.Fatal(errs)
	}
	out, errs, code := h.run(tok, "wireguard", "join", "home", "--token-file", "-")
	if code != 0 || !strings.Contains(out, "wireguard/home joined") || strings.Contains(errs, "warning") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	// or from a file
	file := filepath.Join(h.dir, "token.txt")
	if err := os.WriteFile(file, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errs, code = h.run("", "wireguard", "join", "home2", "--token-file", file)
	if code != 0 || !strings.Contains(out, "wireguard/home2 joined") || strings.Contains(errs, "warning") {
		t.Fatalf("--token-file: %d %s %s", code, out, errs)
	}
	if _, errs, code := h.run("", "wireguard", "join", "home3"); code != 2 || !strings.Contains(errs, "--token-file") {
		t.Fatalf("no token: %d %s", code, errs)
	}
	for _, r := range h.srv.Requests() {
		if strings.Contains(r.Path, "jwg1.") {
			t.Fatalf("the token reached a URL: %s", r.Path)
		}
	}
}
