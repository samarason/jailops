package pfctl

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/sdk/api"
)

func TestValidateNames(t *testing.T) {
	for in, ok := range map[string]bool{
		"jailops/web": true, "jailops/shared.pf": true, "a": true, "jailops/web-1.x": true,
		"": false, "/": false, "jailops//x": false, "-x": false, "jailops/-x": false,
		"jailops/../x": false, "a b": false, "a;b": false, "jailops/.hidden": false,
		"a/b/c/d/e/f/g/h/i": false,
	} {
		if err := ValidateAnchor(in); (err == nil) != ok {
			t.Errorf("anchor %q: %v", in, err)
		}
	}
	for in, ok := range map[string]bool{"web_ips": true, "A1": true, "": false, "1a": false, "a-b": false, "a b": false, strings.Repeat("a", 33): false} {
		if err := ValidateTable(in); (err == nil) != ok {
			t.Errorf("table %q: %v", in, err)
		}
	}
	for in, want := range map[string]string{"10.0.0.1": "10.0.0.1", "10.0.0.0/24": "10.0.0.0/24", "FD00::1": "fd00::1", "fe80::1%em0": "", "-f": "", "a": "", "10.0.0.1 -f": ""} {
		got, err := ValidateAddr(in)
		if (err == nil) != (want != "") || got != want {
			t.Errorf("addr %q: %q %v", in, got, err)
		}
	}
}

const rules = "match out on em0 inet from 10.0.0.0/24 to any nat-to (em0)\npass in quick on jo0 proto tcp to port 22\nblock drop all\n"

func TestLoadSequence(t *testing.T) {
	ctx := context.Background()
	f := run.NewFake()
	f.On("pfctl", []string{"-n", "-v", "-a", "jailops/web", "-f", "-"}, "set skip on lo\n"+rules)
	f.On("pfctl", []string{"-a", "jailops/web", "-f", "-"}, "")
	// the readback has the same rules with different spacing
	f.On("pfctl", []string{"-a", "jailops/web", "-sr"}, "match out on em0 inet from 10.0.0.0/24 to any   nat-to (em0)\npass in quick on jo0 proto tcp to port 22\nblock drop all\n")
	if err := NewCommand(f).Load(ctx, "jailops/web", rules); err != nil {
		t.Fatal(err)
	}
	argv := f.Argv()
	if len(argv) != 3 || !strings.Contains(argv[0], "-n -v") || strings.Contains(argv[1], "-n") {
		t.Fatalf("order: %q", argv)
	}
	for _, c := range f.Calls()[:2] {
		b := string(c.StdinData)
		if b != rules {
			t.Errorf("stdin %q", b)
		}
	}
}

func TestLoadStopsOnValidationFailure(t *testing.T) {
	f := run.NewFake()
	f.OnFail("pfctl", []string{"-n", run.RestArgs}, 1, "/dev/stdin:1: syntax error")
	err := NewCommand(f).Load(context.Background(), "jailops/web", "bogus")
	if !api.IsCode(err, api.CodeInvalid) || len(f.Calls()) != 1 {
		t.Fatalf("%v calls=%d", err, len(f.Calls()))
	}
}

func TestLoadReadbackMismatch(t *testing.T) {
	f := run.NewFake()
	f.On("pfctl", []string{"-n", run.RestArgs}, rules)
	f.On("pfctl", []string{"-a", "jailops/web", "-f", "-"}, "")
	f.On("pfctl", []string{"-a", "jailops/web", "-sr"}, "block drop all\n")
	err := NewCommand(f).Load(context.Background(), "jailops/web", rules)
	if !api.IsCode(err, api.CodeInternal) {
		t.Fatal(err)
	}
}

func TestTablesAndFlush(t *testing.T) {
	ctx := context.Background()
	f := run.NewFake()
	f.Add(run.Rule{Name: "pfctl", Args: []string{run.RestArgs}, Result: run.Result{Stdout: []byte("   10.0.0.1\n   10.0.0.0/24\n")}})
	c := NewCommand(f)
	if err := c.TableAdd(ctx, "jailops/shared.pf", "trusted", "10.0.0.1", "FD00::1"); err != nil {
		t.Fatal(err)
	}
	if err := c.TableDelete(ctx, "jailops/shared.pf", "trusted", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	got, err := c.TableShow(ctx, "jailops/shared.pf", "trusted")
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.0/24"}) {
		t.Fatal(got, err)
	}
	if err := c.Flush(ctx, "jailops/web"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"pfctl -a jailops/shared.pf -t trusted -T add 10.0.0.1 fd00::1",
		"pfctl -a jailops/shared.pf -t trusted -T delete 10.0.0.1",
		"pfctl -a jailops/shared.pf -t trusted -T show",
		"pfctl -a jailops/web -F Tables",
		"pfctl -a jailops/web -F rules",
	}
	if !reflect.DeepEqual(f.Argv(), want) {
		t.Errorf("%q", f.Argv())
	}
	before := len(f.Calls())
	for _, err := range []error{
		c.TableAdd(ctx, "jailops/x", "t", "-f"),
		c.TableAdd(ctx, "jailops/x", "t"),
		c.TableAdd(ctx, "-a", "t", "10.0.0.1"),
		c.TableAdd(ctx, "jailops/x", "t;x", "10.0.0.1"),
		c.Flush(ctx, ""),
		func() error { _, e := c.Validate(ctx, "ok", "a\x00b"); return e }(),
		func() error { _, e := c.Validate(ctx, "ok", strings.Repeat("x", MaxRulesetBytes+1)); return e }(),
	} {
		if !api.IsCode(err, api.CodeInvalid) {
			t.Errorf("%v", err)
		}
	}
	if len(f.Calls()) != before {
		t.Error("invalid input reached pfctl")
	}
}

// The dry run prints the adaptive timeouts that pf derives from a state limit; the readback of the loaded rule prints
// them on 15.2 and leaves them out on 15.1. Both are the same rule.
func TestLoadAcceptsTheAdaptiveTimeoutsInEitherOutput(t *testing.T) {
	withAdaptive := "pass out quick on jo0 all flags S/SA keep state (max 10000, adaptive.start 6000, adaptive.end 12000) label \"jo-1\"\n"
	without := "pass out quick on jo0 all flags S/SA keep state (max 10000) label \"jo-1\"\n"
	for name, tc := range map[string][2]string{"15.1": {withAdaptive, without}, "15.2": {withAdaptive, withAdaptive}, "reverse": {without, withAdaptive}} {
		f := run.NewFake()
		f.On("pfctl", []string{"-n", run.RestArgs}, tc[0])
		f.On("pfctl", []string{"-a", "jailops/web", "-f", "-"}, "")
		f.On("pfctl", []string{"-a", "jailops/web", "-sr"}, tc[1])
		if err := NewCommand(f).Load(context.Background(), "jailops/web", "x"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := RuleLines(withAdaptive); len(got) != 1 || strings.Contains(got[0], "adaptive") {
		t.Errorf("%q", got)
	}
}

// A real difference is named in the error: the first rule the two sides do not share.
func TestLoadMismatchNamesTheFirstDifference(t *testing.T) {
	f := run.NewFake()
	f.On("pfctl", []string{"-n", run.RestArgs}, "pass in all\nblock drop all\n")
	f.On("pfctl", []string{"-a", "jailops/web", "-f", "-"}, "")
	f.On("pfctl", []string{"-a", "jailops/web", "-sr"}, "pass in all\nblock all\n")
	err := NewCommand(f).Load(context.Background(), "jailops/web", "x")
	if err == nil || !strings.Contains(err.Error(), `expected "block drop all", read back "block all"`) {
		t.Fatalf("%v", err)
	}
}

func TestRuleLines(t *testing.T) {
	got := RuleLines("# c\nset skip on lo\ntable <a> { 1.1.1.1 }\n  pass   in  all \nblock\tdrop all\nNo ALTQ support in kernel\n")
	want := []string{"block drop all", "pass in all"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%q", got)
	}
}

func FuzzRuleLines(f *testing.F) {
	f.Add(rules)
	f.Fuzz(func(t *testing.T, s string) {
		a := RuleLines(s)
		b := RuleLines(strings.Join(a, "\n"))
		if !reflect.DeepEqual(a, b) {
			t.Fatal("not idempotent")
		}
		ParseTable(s)
	})
}

func FuzzValidateAddr(f *testing.F) {
	f.Add("10.0.0.0/8")
	f.Fuzz(func(t *testing.T, s string) {
		if n, err := ValidateAddr(s); err == nil && (n == "" || n[0] == '-' || strings.ContainsAny(n, " \n\t;")) {
			t.Fatalf("%q -> %q", s, n)
		}
	})
}

func TestFake(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	if err := f.Load(ctx, "jailops/a", rules); err != nil {
		t.Fatal(err)
	}
	if err := f.Load(ctx, "jailops/a", "!syntax-error\n"); !api.IsCode(err, api.CodeInvalid) {
		t.Fatal(err)
	}
	if got, _ := f.Read(ctx, "jailops/a"); got != rules {
		t.Fatal("failed load must keep old rules")
	}
	if _, err := f.TableShow(ctx, "jailops/a", "t"); !api.IsCode(err, api.CodeNotFound) {
		t.Fatal(err)
	}
	f.TableAdd(ctx, "jailops/a", "t", "10.0.0.2", "10.0.0.1")
	f.TableDelete(ctx, "jailops/a", "t", "10.0.0.2")
	if got, _ := f.TableShow(ctx, "jailops/a", "t"); !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Fatal(got)
	}
	f.Flush(ctx, "jailops/a")
	if got, _ := f.Read(ctx, "jailops/a"); got != "" {
		t.Fatal(got)
	}
}
