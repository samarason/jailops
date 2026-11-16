package render

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

func TestPromptFileGolden(t *testing.T) {
	for name, ps1 := range map[string]string{
		"prompt_file":       api.DefaultPS1(api.DefaultPromptColor),
		"prompt_file_short": api.ShortPS1(api.DefaultPromptColor),
		"prompt_file_text":  api.EffectivePS1(`\u@{jail} {project}/{host}:\w\$ `, api.DefaultPromptColor),
	} {
		got, err := PromptFile(ps1)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, name, got)
	}
	for _, bad := range []string{"default", "short", "none", "", "it's", "$(id)", "`id`", "a\nb", "\\x", "${HOME}", "${JAILOPS_JAIL-}x$(id)",
		"{${JAILOPS_JAIL-}jail}", "{jail}", "${JAILOPS_X-}"} {
		if _, err := PromptFile(bad); err == nil {
			t.Errorf("PromptFile(%q) was accepted", bad)
		}
	}
}

// The variables script is the same text in every jail and exports what the sysctl security.jail.env says: a fake sysctl
// prints a sample, and the script runs in the local sh and bash, with valid values and with hostile ones.
func TestEnvScript(t *testing.T) {
	script := EnvScript()
	if strings.Contains(script, "web") || strings.Contains(script, "shop") {
		t.Fatalf("the script holds a name of a jail:\n%s", script)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sysctl"), []byte("#!/bin/sh\n[ \"$1 $2\" = \"-n security.jail.env\" ] || exit 1\nprintf '%s' \"$FAKE_JAIL_ENV\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "jailops-env.sh")
	if err := os.WriteFile(file, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	shells := map[string]string{}
	for _, n := range []string{"sh", "bash"} {
		p, err := exec.LookPath(n)
		if err != nil {
			t.Fatalf("%s is needed for this test: %v", n, err)
		}
		shells[n] = p
	}
	const show = `printf '[%s|%s|%s]' "${JAILOPS_JAIL-unset}" "${JAILOPS_PROJECT-unset}" "${JAILOPS_HOST-unset}"; printf '{%s%s}' "${_jailops_k-}" "${_jailops_v-}"`
	for _, tc := range []struct{ name, env, want string }{
		{"all three", "jailops_jail=web\njailops_project=shop\njailops_host=babel\n", "[web|shop|babel]{}"},
		{"no final newline", "jailops_jail=web\njailops_project=shop\njailops_host=babel", "[web|shop|babel]{}"},
		{"a missing host", "jailops_jail=web\njailops_project=shop\n", "[web|shop|unset]{}"},
		{"nothing", "", "[unset|unset|unset]{}"},
		{"hyphens and digits", "jailops_jail=web-2\njailops_project=a1-b\njailops_host=node-01\n", "[web-2|a1-b|node-01]{}"},
		{"foreign keys are ignored", "app=nginx\nPATH=/evil\nHOME=x\njail=web\nJAILOPS_JAIL=up\njailops_other=1\nLD_PRELOAD=y\nxjailops_host=zzz\njailops_project=shop\n", "[unset|shop|unset]{}"},
		{"foreign keys only", "jail=web\nproject=shop\nhost=babel\nPS1=x\nJAILOPS_HOST=babel\n", "[unset|unset|unset]{}"},
		{"upper case value", "jailops_jail=Web\njailops_project=shop\njailops_host=babel\n", "[unset|shop|babel]{}"},
		{"a command", "jailops_jail=$(touch OWNED)\njailops_project=`touch OWNED`\njailops_host=babel;touch OWNED\n", "[unset|unset|unset]{}"},
		{"a glob and a space", "jailops_jail=*\njailops_project=sh op\njailops_host=ba bel\n", "[unset|unset|unset]{}"},
		{"an equals sign in the value", "jailops_jail=a=b\njailops_project=shop\n", "[unset|shop|unset]{}"},
		{"an empty value", "jailops_jail=\njailops_project=shop\n", "[unset|shop|unset]{}"},
		{"a quote and a backslash", "jailops_jail=we'b\njailops_project=sho\\p\njailops_host=babel\n", "[unset|unset|babel]{}"},
		{"a key that looks like ours", "jailops_jail =web\n jailops_project=shop\njailops_host=babel\n", "[unset|unset|babel]{}"},
	} {
		for name, sh := range shells {
			cmd := exec.Command(sh, "-c", `. "$1"; `+show, name, file)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "FAKE_JAIL_ENV=" + tc.env}
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != tc.want {
				t.Errorf("%s in %s: %q %v, want %q", tc.name, name, out, err, tc.want)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "OWNED")); err == nil {
		t.Fatal("a value ran a command")
	}
	// a sysctl that fails leaves the shell without the variables and without an error
	cmd := exec.Command(shells["sh"], "-c", `. "$1"; printf '[%s]' "${JAILOPS_JAIL-unset}"`, "sh", file)
	cmd.Env = []string{"PATH=/nonexistent", "FAKE_JAIL_ENV="}
	if out, err := cmd.CombinedOutput(); err != nil || !strings.HasSuffix(string(out), "[unset]") {
		t.Errorf("no sysctl: %q %v", out, err)
	}
}

func TestPromptHook(t *testing.T) {
	got, err := PromptHookSet("", true)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "prompt_hook_empty", got)
	existing := "# the administrator's own profile\nexport EDITOR=vi\nPS1='admin> '\n"
	got, err = PromptHookSet(existing, true)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "prompt_hook_existing", got)
	if !strings.HasSuffix(got, existing) {
		t.Fatalf("the file's own lines must follow the block unchanged:\n%s", got)
	}
	// idempotent, one block only
	again, err := PromptHookSet(got, true)
	if err != nil || again != got || strings.Count(again, "BEGIN jailops shell") != 1 {
		t.Fatalf("%q %v", again, err)
	}
	// a block somewhere else moves to the top, the rest stays
	moved, err := PromptHookSet(existing+promptBlock(true), true)
	if err != nil || moved != got {
		t.Fatalf("%q %v", moved, err)
	}
	// without a prompt the block sources the variables only, and the file's own lines are untouched
	none, err := PromptHookSet(got, false)
	if err != nil || !strings.HasSuffix(none, existing) || !strings.Contains(none, api.EnvFile) || strings.Contains(none, api.PromptFile) {
		t.Fatalf("%q %v", none, err)
	}
	// a block cut in half by a hand edit is left alone
	broken := promptBegin + "\nwhatever\n"
	if _, err := PromptHookSet(broken, true); err == nil {
		t.Fatal("an unterminated block was accepted")
	}
	if _, err := PromptHookSet(promptBlock(true)+"x\n"+promptBlock(true), true); err == nil {
		t.Fatal("two blocks were accepted")
	}
}

// hostile prompts that pass CheckPrompt: they look like shell syntax but are only prompt text and escapes
var trickyPrompts = []string{
	api.DefaultPS1(40),
	api.ShortPS1(40),
	api.EffectivePS1(`\u@{jail} {project}/{host}:\w\$ `, 40),
	`\u@\h:\w\$ `,
	`\[\033[1;31m\]\D{%H:%M}\[\033[0m\] \w \$ `,
	`a;b|c&d>e<f"g\$(touch MARK)`,
	`\$(touch MARK) \$HOME !! \#`,
	`→ \W ✓ `,
}

func TestPromptFileIsInertInTheShells(t *testing.T) {
	dir := t.TempDir()
	mark := filepath.Join(dir, "MARK")
	for _, ps1 := range trickyPrompts {
		if err := api.CheckPS1(ps1); err != nil {
			t.Fatalf("CheckPS1(%q): %v", ps1, err)
		}
		body, err := PromptFile(ps1)
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, "prompt.sh")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// POSIX sh reads the file as it is and assigns nothing (BASH_VERSION is unset in sh).
		out, err := exec.Command("sh", "-c", `PS1=x; . "$1"; printf %s "$PS1"`, "sh", f).CombinedOutput()
		if err != nil || string(out) != "x" {
			t.Fatalf("sh with %q: %q %v", ps1, out, err)
		}
		// bash assigns the text exactly and expanding it as a prompt runs nothing.
		bash, err := exec.LookPath("bash")
		if err != nil {
			continue // the sh part above holds on every system; bash is checked where it is installed
		}
		cmd := exec.Command(bash, "--norc", "--noprofile", "-c", `PS1=x; . "$1"; printf '%s\n' "$PS1"; printf '%s' "${PS1@P}" >/dev/null`, "bash", f)
		cmd.Dir = dir
		out, err = cmd.CombinedOutput()
		if err != nil || string(out) != ps1+"\n" {
			t.Fatalf("bash with %q: %q %v", ps1, out, err)
		}
		if _, err := os.Stat(mark); err == nil {
			t.Fatalf("expanding %q ran a command", ps1)
		}
	}
}

// The escapes CheckPrompt refuses are the ones that do run a command when bash expands the prompt: the check is
// not stricter than it has to be by guesswork.
func TestRefusedPromptEscapesWouldRun(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Log("bash is not installed here; CheckPrompt's refusals are still covered by sdk/api")
		return
	}
	for _, ps1 := range []string{`\\\$(touch MARK)`, `\044(touch MARK)`, `\134\$(touch MARK)`, `\140touch MARK\140`, `$(touch MARK)`} {
		if api.CheckPrompt(ps1) == nil {
			t.Fatalf("CheckPrompt accepts %q", ps1)
		}
		dir := t.TempDir()
		cmd := exec.Command(bash, "--norc", "--noprofile", "-c", `PS1=$1; printf '%s' "${PS1@P}" >/dev/null`, "bash", ps1)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%q: %s %v", ps1, out, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "MARK")); err != nil {
			t.Logf("bash %s did not run the command of %q: the refusal may be stricter than needed here (not a safety property)", bash, ps1)
		}
	}
}

// FuzzPromptFile: whatever CheckPrompt accepts is assigned exactly and runs nothing when bash shows it.
func FuzzPromptFile(f *testing.F) {
	for _, p := range trickyPrompts {
		f.Add(p)
	}
	f.Add(`\\\$(touch MARK)`)
	f.Add(`\044(touch MARK)`)
	bash, _ := exec.LookPath("bash")
	f.Fuzz(func(t *testing.T, ps1 string) {
		if api.CheckPrompt(ps1) != nil || ps1 == api.PromptDefault || ps1 == api.PromptShort || ps1 == api.PromptNone {
			return
		}
		exp := api.ExpandPrompt(ps1)
		body, err := PromptFile(exp)
		if err != nil {
			t.Fatalf("%q passed CheckPrompt but PromptFile refused it: %v", ps1, err)
		}
		if bash == "" {
			return
		}
		dir := t.TempDir()
		file := filepath.Join(dir, "prompt.sh")
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bash, "--norc", "--noprofile", "-c", `PS1=x; . "$1"; printf '%s' "$PS1"; printf '%s' "${PS1@P}" >/dev/null`, "bash", file)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != exp {
			t.Fatalf("%q: %q %v", ps1, out, err)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 1 {
			t.Fatalf("expanding %q made files: %v", ps1, ents)
		}
	})
}

// The default and the short prompt as bash shows them, with the variables of the jail known and not known: the tag is
// "[project/host]", "[project]", "[host]" or absent, and the line ends in "# " or "$ ".
func TestPromptAsBashShowsIt(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed here")
	}
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	host, _ := os.Hostname()
	host, _, _ = strings.Cut(host, ".")
	id := u.Username + "@" + host
	suffix := ":/tmp$ "
	if u.Uid == "0" {
		suffix = ":/tmp# "
	}
	dir := t.TempDir()
	run := func(ps1 string, env ...string) string {
		t.Helper()
		body, err := PromptFile(ps1)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, "prompt.sh")
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bash, "--norc", "--noprofile", "-c", `PS1=x; . "$1"; cd /tmp; printf '%s' "${PS1@P}"`, "bash", file)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		// drop the colour sequences and the markers bash puts around them
		return regexp.MustCompile("[\x01\x02]|\x1b\\[[0-9;]*m").ReplaceAllString(string(out), "")
	}
	def := api.DefaultPS1(api.DefaultPromptColor)
	for _, tc := range []struct {
		env  []string
		want string
	}{
		{[]string{"JAILOPS_PROJECT=shop", "JAILOPS_HOST=babel"}, id + " [shop/babel]" + suffix},
		{[]string{"JAILOPS_PROJECT=shop"}, id + " [shop]" + suffix},
		{[]string{"JAILOPS_HOST=babel"}, id + " [babel]" + suffix},
		{nil, id + suffix},
	} {
		if got := run(def, tc.env...); got != tc.want {
			t.Errorf("default with %v: %q, want %q", tc.env, got, tc.want)
		}
		if got := run(api.ShortPS1(api.DefaultPromptColor), tc.env...); got != id+suffix {
			t.Errorf("short with %v: %q", tc.env, got)
		}
	}
	// a prompt text with placeholders reads the variables when it is shown
	if got := run(api.EffectivePS1(`{jail}.{project}.{host}> `, api.DefaultPromptColor), "JAILOPS_JAIL=web", "JAILOPS_PROJECT=shop", "JAILOPS_HOST=babel"); got != "web.shop.babel> " {
		t.Errorf("placeholders: %q", got)
	}
}
