package cli_test

import "testing"

// 'jailops stop-all' is what a host shutdown runs: every running jail, a jail before the jails it depends on.
func TestStopAll(t *testing.T) {
	h := newHarness(t)
	h.seed()
	tr := h.transcript()
	tr.ok("stop-all") // nothing runs yet
	create := func(name string, extra ...string) {
		args := append([]string{"create", name, "--image", "freebsd-15@stable", "--storage", "default", "--network", "lan", "--start"}, extra...)
		tr.ok(args...)
	}
	create("db")
	create("web", "--depends", "db")
	create("cache")
	create("idle")
	tr.ok("stop", "idle") // a stopped jail is left alone
	tr.ok("stop-all", "--dry-run")
	tr.ok("stop-all", "--grace", "30s")
	tr.ok("list", "-c", "name,state")
	tr.do("", "stop-all", "--grace", "soon")
	tr.golden("stop_all")
}
