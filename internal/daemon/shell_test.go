package daemon_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"jailops.net/jailops/internal/daemon"
	"jailops.net/jailops/internal/daemon/dtest"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

const webRoot = "/jailops/projects/alpha/jails/web/root"

// shellT is the test the helpers below report to (the tests of this file do not run in parallel).
var shellT *testing.T

func mustOp[T any](op *sdk.Operation[T], err error) T {
	t := shellT
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	v, err := op.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// opErr is the error of submitting an operation or, when it was submitted, of the operation.
func opErr[T any](op *sdk.Operation[T], err error) error {
	if err != nil {
		return err
	}
	_, err = op.Wait(context.Background())
	return err
}

func shellCond(j api.Jail) *api.Condition {
	for i := range j.Status.Conditions {
		if j.Status.Conditions[i].Type == "ShellSetup" {
			return &j.Status.Conditions[i]
		}
	}
	return nil
}

func installedBash(e *dtest.Env, root string) int {
	n := 0
	for _, in := range e.Installed {
		if in == root+" bash" {
			n++
		}
	}
	return n
}

// A new FreeBSD jail gets bash and the default prompt at its first start; the prompt key changes the file at once
// in a running jail, and none removes what JailOps wrote.
func TestNewJailGetsBashAndThePrompt(t *testing.T) {
	shellT = t
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	sj := &scriptedJails{env: e}
	e.Jails.SetExecFn(sj.fn)
	ctx := context.Background()
	j := mustOp(e.Admin.Jails().Create(ctx, dtest.WebJail("web")))
	if j.Spec.Shell != api.BashPath || j.Spec.Prompt != api.PromptDefault {
		t.Fatalf("the defaults of jailopsd.yaml are not in the spec: %+v", j.Spec)
	}
	if installedBash(e, webRoot) != 0 || e.HasFile(webRoot+api.PromptFile) {
		t.Fatal("the shell was set up before the first start")
	}
	mustOp(e.Admin.Jails().Start(ctx, "web"))
	// bash went in from the host before the jail first ran, so the start's own rc builds the library cache with it
	if installedBash(e, webRoot) != 1 {
		t.Fatalf("bash was not installed from the host: %v %v", e.Installed, sj.cmds)
	}
	if sj.ran("pkg install") {
		t.Fatalf("pkg ran inside the jail although the host had installed bash: %v", sj.cmds)
	}
	want := "PS1='" + api.DefaultPS1(39) + "'"
	if !strings.Contains(e.File(webRoot+api.PromptFile), want) {
		t.Fatalf("prompt file: %q", e.File(webRoot+api.PromptFile))
	}
	// the variables script is the same text in every jail and the jail's own jail.conf says where it is; the prompt file
	// only reads the variables
	if env := e.File(webRoot + api.EnvFile); !strings.Contains(env, "security.jail.env") || strings.Contains(env, "alpha") || strings.Contains(env, "testhost") {
		t.Fatalf("env file: %q", env)
	}
	if conf := e.File("/etc/jailops/jails/alpha_web/jail.conf"); !strings.Contains(conf, "\tenv.jailops_jail = \"web\";\n\tenv.jailops_project = \"alpha\";\n\tenv.jailops_host = \"testhost\";\n") {
		t.Fatalf("jail.conf: %q", conf)
	}
	if strings.Contains(e.File(webRoot+api.PromptFile), "alpha") || strings.Contains(e.File(webRoot+api.PromptFile), "testhost") {
		t.Fatalf("the prompt file holds names: %q", e.File(webRoot+api.PromptFile))
	}
	for _, p := range []string{api.ProfilePath, api.BashrcPath} {
		if f := e.File(webRoot + p); !strings.HasPrefix(f, "# BEGIN jailops shell") || !strings.Contains(f, ". "+api.EnvFile) || !strings.Contains(f, ". "+api.PromptFile) {
			t.Fatalf("%s: %q", p, f)
		}
	}
	// a second start sets nothing up again
	mustOp(e.Admin.Jails().Restart(ctx, "web"))
	if installedBash(e, webRoot) != 1 {
		t.Fatalf("bash was installed twice: %v", e.Installed)
	}
	// the console and jailops shell start bash
	sess, err := e.Admin.Jails().Exec(ctx, "web", nil, sdk.ExecOptions{Shell: true})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sess.Run(strings.NewReader(""), io.Discard, io.Discard)
	calls := e.FakeExec.Calls()
	if last := calls[len(calls)-1]; !slices.Equal(last.Argv, []string{api.BashPath}) {
		t.Fatalf("the shell ran %v", last.Argv)
	}
	// a changed prompt is written at once into the running jail
	red := `\[\e[38;5;196m\]\u@\h:\w\$\[\e[0m\] `
	mustOp(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": red}, nil, false))
	if !strings.Contains(e.File(webRoot+api.PromptFile), "PS1='"+red+"'") {
		t.Fatalf("the new prompt was not written: %q", e.File(webRoot+api.PromptFile))
	}
	// a prompt that would run a command is refused and changes nothing
	for _, bad := range []string{"$(id)", "`id`", "a'b", `\044(id)`, `\\\$(id)`, "a\nb"} {
		if err := opErr(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": bad}, nil, false)); !api.IsCode(err, api.CodeInvalid) {
			t.Fatalf("prompt %q: %v", bad, err)
		}
	}
	if !strings.Contains(e.File(webRoot+api.PromptFile), "PS1='"+red+"'") {
		t.Fatal("a refused prompt changed the file")
	}
	// short is the default without the tag
	mustOp(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": "short"}, nil, false))
	if f := e.File(webRoot + api.PromptFile); !strings.Contains(f, "PS1='"+api.ShortPS1(39)+"'") || strings.Contains(f, api.Where) {
		t.Fatalf("short: %q", f)
	}
	// none removes the prompt file and keeps the variables; a start-up file with lines of its own keeps them
	e.Files.Put(webRoot+api.BashrcPath, []byte(e.File(webRoot+api.BashrcPath)+"alias ll='ls -l'\n"))
	mustOp(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": "none"}, nil, false))
	if b := e.File(webRoot + api.BashrcPath); e.HasFile(webRoot+api.PromptFile) || !e.HasFile(webRoot+api.EnvFile) || !strings.Contains(b, ". "+api.EnvFile) ||
		strings.Contains(b, api.PromptFile) || !strings.HasSuffix(b, "alias ll='ls -l'\n") {
		t.Fatalf("none left: %v %q", e.Files.Paths(), b)
	}
	// a stopped jail gets a changed prompt at its next start
	mustOp(e.Admin.Jails().Stop(ctx, "web"))
	mustOp(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": "default"}, nil, false))
	if e.HasFile(webRoot + api.PromptFile) {
		t.Fatal("the prompt was written into a stopped jail")
	}
	mustOp(e.Admin.Jails().Start(ctx, "web"))
	if !strings.Contains(e.File(webRoot+api.PromptFile), want) || !strings.HasPrefix(e.File(webRoot+api.BashrcPath), "# BEGIN jailops shell") ||
		!strings.HasSuffix(e.File(webRoot+api.BashrcPath), "alias ll='ls -l'\n") {
		t.Fatalf("after the start: %q %q", e.File(webRoot+api.PromptFile), e.File(webRoot+api.BashrcPath))
	}
	// the app draft of the jail does not take the shell for a part of the app
	d, err := e.Client(api.PermOperator).Project("alpha").Jails().AppDraft(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Definition.Packages {
		if p.Name == api.BashPackage {
			t.Fatalf("the draft names the shell: %+v", d.Definition.Packages)
		}
	}
	for _, c := range d.Definition.Config {
		if strings.Contains(c.Path, "profile") || strings.Contains(c.Path, "bash") {
			t.Fatalf("the draft names the prompt files: %+v", d.Definition.Config)
		}
	}
	// deleting the jail forgets its record
	mustOp(e.Admin.Jails().Stop(ctx, "web"))
	mustOp(e.Admin.Jails().Delete(ctx, "web"))
	if _, err := os.Stat(filepath.Join(e.Cfg.StateDir, "shell", "alpha", "web.json")); !errors.Is(err, os.ErrNotExist) {
		if _, err2 := os.Stat(filepath.Join(e.Cfg.StateDir, "shell", "alpha/web.json")); !errors.Is(err2, os.ErrNotExist) {
			t.Fatalf("the shell record of a deleted jail is left: %v", err)
		}
	}
}

// What the request, a profile and jailopsd.yaml say wins over the default; an existing jail changes only when asked.
func TestShellChoicesAndExistingJails(t *testing.T) {
	shellT = t
	dir := t.TempDir()
	e := dtest.New(t, dtest.Options{Dir: dir, Mutate: func(c *daemon.Config) { c.Jails.Shell = "sh" }})
	e.Seed()
	ctx := context.Background()
	// a host that chose sh: nothing is installed or written, the shell is /bin/sh
	j := mustOp(e.Admin.Jails().Create(ctx, dtest.WebJail("web")))
	if j.Spec.Shell != "" || j.Spec.Prompt != "" {
		t.Fatalf("%+v", j.Spec)
	}
	mustOp(e.Admin.Jails().Start(ctx, "web"))
	if installedBash(e, webRoot) != 0 || e.HasFile(webRoot+api.PromptFile) {
		t.Fatalf("jails.shell sh installed bash or wrote the prompt: %v", e.Installed)
	}
	// the request's own choice wins: bash by name, with a prompt of its own
	j2 := dtest.WebJail("web2")
	j2.Spec.Shell, j2.Spec.Prompt = "bash", `\u@\h \$ `
	j = mustOp(e.Admin.Jails().Create(ctx, j2))
	if j.Spec.Shell != api.BashPath || j.Spec.Prompt != `\u@\h \$ ` {
		t.Fatalf("%+v", j.Spec)
	}
	mustOp(e.Admin.Jails().Start(ctx, "web2"))
	root2 := "/jailops/projects/alpha/jails/web2/root"
	if installedBash(e, root2) != 1 || !strings.Contains(e.File(root2+api.PromptFile), `PS1='\u@\h \$ '`) {
		t.Fatalf("%v %q", e.Installed, e.File(root2+api.PromptFile))
	}
	// the same daemon with the default configuration: the old jail is not changed by a start... (the fakes, and
	// what the fake pkg installed, stay with e)
	e.Stop()
	e2 := dtest.New(t, dtest.Options{Reuse: e})
	e2.Admin = e2.Admin.Project("alpha")
	mustOp(e2.Admin.Jails().Restart(ctx, "web"))
	if installedBash(e, webRoot) != 0 || e2.HasFile(webRoot+api.PromptFile) {
		t.Fatal("an existing jail was changed without being asked")
	}
	e2.Files.Put(webRoot+api.ShPath, []byte("x"))
	if sess, err := e2.Admin.Jails().Exec(ctx, "web", nil, sdk.ExecOptions{Shell: true}); err != nil {
		t.Fatalf("the shell of an existing jail: %v", err)
	} else {
		_, _ = sess.Run(strings.NewReader(""), io.Discard, io.Discard)
	}
	// ... but shell-setup gives it what a new jail gets
	res := mustOp(e2.Client(api.PermOperator).Project("alpha").Jails().ShellSetup(ctx, "web"))
	if res.Shell != api.BashPath || res.Prompt != api.PromptDefault || res.PS1 != api.DefaultPS1(39) || len(res.Steps) < 3 {
		t.Fatalf("%+v", res)
	}
	got, _ := e2.Admin.Jails().Get(ctx, "web")
	if got.Spec.Shell != api.BashPath || got.Spec.Prompt != api.PromptDefault || installedBash(e, webRoot) != 1 || !e2.HasFile(webRoot+api.PromptFile) {
		t.Fatalf("%+v %v", got.Spec, e.Installed)
	}
	// running it again installs nothing
	res = mustOp(e2.Admin.Jails().ShellSetup(ctx, "web"))
	if installedBash(e, webRoot) != 1 || !slices.Contains(res.Steps, api.BashPath+" is installed") {
		t.Fatalf("%+v %v", res, e.Installed)
	}
	// a profile's shell wins over the host default
	if _, err := e2.Admin.Profiles().Create(ctx, api.Profile{Metadata: api.ObjectMeta{Name: "plain"}, Spec: api.ProfileSpec{Config: map[string]string{"shell": "sh"}}}); err != nil {
		t.Fatal(err)
	}
	j3 := dtest.WebJail("web3")
	j3.Spec.Profiles = []string{"plain"}
	j = mustOp(e2.Admin.Jails().Create(ctx, j3))
	if j.Spec.Shell != "" || j.Spec.Prompt != "" {
		t.Fatalf("the default overrode the profile: %+v", j.Spec)
	}
	// a whole spec written back (jailops apply, jailops-sync) may name the shell too
	cur, etag, err := e2.Admin.Jails().GetETag(ctx, "web3")
	if err != nil {
		t.Fatal(err)
	}
	cur.Spec.Shell = "sh"
	if up, err := e2.Admin.Jails().Update(ctx, "web3", cur, etag); err != nil || up.Spec.Shell != api.ShPath {
		t.Fatalf("%+v %v", up.Spec, err)
	}
	// readonly may not run it
	if err := opErr(e2.Client(api.PermReadonly).Project("alpha").Jails().ShellSetup(ctx, "web")); !api.IsCode(err, api.CodeForbidden) {
		t.Fatalf("readonly: %v", err)
	}
	// a stopped jail is refused
	mustOp(e2.Admin.Jails().Stop(ctx, "web"))
	if err := opErr(e2.Admin.Jails().ShellSetup(ctx, "web")); !api.IsCode(err, api.CodeBusy) {
		t.Fatalf("stopped: %v", err)
	}
}

// A failed installation does not fail the start: it is a condition, the shell says how to repair it, and
// shell-setup repairs it. A start-up file whose block was cut by hand is left alone.
func TestShellSetupFailureIsReportedAndRepaired(t *testing.T) {
	shellT = t
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	ctx := context.Background()
	mustOp(e.Admin.Jails().Create(ctx, dtest.WebJail("web")))
	e.SetPkgInstallErr(errors.New("pkg: no network"))
	mustOp(e.Admin.Jails().Start(ctx, "web"))
	got, _ := e.Admin.Jails().Get(ctx, "web")
	c := shellCond(got)
	if got.Status.Power != api.PowerRunning || c == nil || c.Status != api.ConditionFalse || !strings.Contains(c.Message, "jailops jail shell-setup web") {
		t.Fatalf("%+v", got.Status)
	}
	_, err := e.Admin.Jails().Exec(ctx, "web", nil, sdk.ExecOptions{Shell: true})
	var ae *api.Error
	if !errors.As(err, &ae) || ae.Code != api.CodeNotFound || !strings.Contains(ae.Hint, "jailops jail shell-setup web") {
		t.Fatalf("%v", err)
	}
	assertRealCommand(t, ae.Hint)
	// the failure is not retried at every start
	mustOp(e.Admin.Jails().Restart(ctx, "web"))
	if installedBash(e, webRoot) != 0 {
		t.Fatal("bash appeared")
	}
	e.SetPkgInstallErr(nil)
	mustOp(e.Admin.Jails().ShellSetup(ctx, "web"))
	got, _ = e.Admin.Jails().Get(ctx, "web")
	if shellCond(got) != nil || installedBash(e, webRoot) != 1 {
		t.Fatalf("%+v %v", got.Status.Conditions, e.Installed)
	}
	// a hand edit that cut the block in half: refused with the file named, the file untouched
	cut := "# BEGIN jailops shell: managed by JailOps\nmy own line\n"
	e.Files.Put(webRoot+api.BashrcPath, []byte(cut))
	if err := opErr(e.Admin.Jails().ShellSetup(ctx, "web")); err == nil || !strings.Contains(err.Error(), api.BashrcPath) {
		t.Fatalf("%v", err)
	}
	if e.File(webRoot+api.BashrcPath) != cut {
		t.Fatal("the hand-edited file was changed")
	}
}

// Linux jails are left alone.
func TestLinuxJailsKeepTheirShell(t *testing.T) {
	shellT = t
	e := dtest.New(t, dtest.Options{})
	e.Seed()
	e.SeedLinux()
	ctx := context.Background()
	j := mustOp(e.Admin.Jails().Create(ctx, dtest.AlpineJail("alp")))
	if j.Spec.Shell != "" || j.Spec.Prompt != "" {
		t.Fatalf("%+v", j.Spec)
	}
	bad := dtest.AlpineJail("alp2")
	bad.Spec.Prompt = "default"
	if _, err := e.Admin.Jails().Create(ctx, bad); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("%v", err)
	}
	if err := opErr(e.Admin.Jails().Config(ctx, "alp", map[string]string{"prompt": "default"}, nil, false)); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("%v", err)
	}
	mustOp(e.Admin.Jails().Start(ctx, "alp"))
	if err := opErr(e.Admin.Jails().ShellSetup(ctx, "alp")); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("%v", err)
	}
	if len(e.Installed) != 0 {
		t.Fatalf("%v", e.Installed)
	}
}

func TestJailsConfig(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\n"))
	if err != nil || cfg.Jails.Shell != "bash" || cfg.Jails.Prompt != "default" || cfg.Jails.PromptColor == nil || *cfg.Jails.PromptColor != 39 {
		t.Fatalf("%+v %v", cfg.Jails, err)
	}
	cfg, err = daemon.Decode(strings.NewReader("pool: tank\njails:\n  shell: sh\n  prompt: '\\u@\\h:\\w\\$ '\n  prompt_color: 196\n"))
	if err != nil || cfg.Jails.Shell != "sh" || cfg.Jails.Prompt != `\u@\h:\w\$ ` || *cfg.Jails.PromptColor != 196 {
		t.Fatalf("%+v %v", cfg.Jails, err)
	}
	// a host-wide prompt may say where the jail is, with the three words in braces
	cfg, err = daemon.Decode(strings.NewReader("pool: tank\njails:\n  prompt: '[{host}] {project}/{jail} \\$ '\n"))
	if err != nil || cfg.Jails.Prompt != `[{host}] {project}/{jail} \$ ` {
		t.Fatalf("%+v %v", cfg.Jails, err)
	}
	if _, err := daemon.Decode(strings.NewReader("pool: tank\njails:\n  prompt: '{nope} \\$ '\n")); err == nil || !strings.Contains(err.Error(), "{host}") {
		t.Errorf("an unknown placeholder in jails.prompt: %v", err)
	}
	for _, bad := range []string{"shell: zsh", "shell: /usr/local/bin/bash", "prompt: '$(id)'", "prompt: '`id`'", "prompt_color: 0", "prompt_color: 256", "prompt_color: -1", "colour: 3"} {
		if _, err := daemon.Decode(strings.NewReader("pool: tank\njails:\n  " + bad + "\n")); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
}

// The variables say where the jail is: JAILOPS_JAIL, JAILOPS_PROJECT and JAILOPS_HOST (the short name of the host),
// from the parameters env.jailops_* of the jail's jail.conf, which every start renders. The prompt reads the
// variables each time it is shown, so the words {jail}, {project} and {host} of a prompt text become references to
// them, and a rename changes the jail.conf of the next start and neither the variables script nor the prompt.
func TestPromptSaysWhereTheJailIs(t *testing.T) {
	shellT = t
	e := dtest.New(t, dtest.Options{Hostname: "Babel.Example.org"})
	e.Seed()
	sj := &scriptedJails{env: e}
	e.Jails.SetExecFn(sj.fn)
	ctx := context.Background()
	mustOp(e.Admin.Jails().Create(ctx, dtest.WebJail("web")))
	mustOp(e.Admin.Jails().Start(ctx, "web"))
	envScript := e.File(webRoot + api.EnvFile)
	if conf := e.File("/etc/jailops/jails/alpha_web/jail.conf"); !strings.Contains(conf, "env.jailops_host = \"babel\";") || !strings.Contains(conf, "env.jailops_project = \"alpha\";") {
		t.Fatalf("the jail.conf does not say project and host: %q", conf)
	}
	// a prompt text with the words: written at once into the running jail, as references to the variables
	mustOp(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": `[{project}/{jail}@{host}] \$ `}, nil, false))
	const text = `PS1='[${JAILOPS_PROJECT-}/${JAILOPS_JAIL-}@${JAILOPS_HOST-}] \$ '`
	if f := e.File(webRoot + api.PromptFile); !strings.Contains(f, text) {
		t.Fatalf("the placeholders were not turned into references: %q", f)
	}
	// a word that is not one of the three is refused and the message names them
	err := opErr(e.Admin.Jails().Config(ctx, "web", map[string]string{"prompt": "{nope} \\$ "}, nil, false))
	if !api.IsCode(err, api.CodeInvalid) || !strings.Contains(err.Error(), "{jail}") || !strings.Contains(err.Error(), "{host}") {
		t.Fatalf("an unknown placeholder: %v", err)
	}
	// after a rename of the jail the next start renders the new name into its jail.conf; the variables script and the
	// prompt are the same text
	mustOp(e.Admin.Jails().Stop(ctx, "web"))
	mustOp(e.Admin.Jails().Rename(ctx, "web", api.Rename{NewName: "site"}, ""))
	mustOp(e.Admin.Jails().Start(ctx, "site"))
	if conf := e.File("/etc/jailops/jails/alpha_site/jail.conf"); !strings.Contains(conf, "env.jailops_jail = \"site\";") || strings.Contains(conf, "env.jailops_jail = \"web\";") {
		t.Fatalf("the jail.conf of the renamed jail: %q", conf)
	}
	// nothing was written into the jail's files for the rename: they are the same text as before (a real rename moves
	// the dataset that holds them; the fake files stay where they were written)
	if env := e.File(webRoot + api.EnvFile); env != envScript {
		t.Fatalf("the variables script changed with the rename: %q", env)
	}
	if f := e.File(webRoot + api.PromptFile); !strings.Contains(f, text) {
		t.Fatalf("the prompt file changed with the rename: %q", f)
	}
}

// jails.max_states is the pf state limit of a jail that sets none: 10000 unless the host says otherwise, 0 for no
// limit, and never negative.
func TestJailsMaxStatesConfig(t *testing.T) {
	cfg, err := daemon.Decode(strings.NewReader("pool: tank\n"))
	if err != nil || cfg.Jails.MaxStates == nil || *cfg.Jails.MaxStates != daemon.DefaultMaxStates || daemon.DefaultMaxStates != 10000 {
		t.Fatalf("%+v %v", cfg.Jails, err)
	}
	for in, want := range map[string]int{"0": 0, "250000": 250000} {
		cfg, err = daemon.Decode(strings.NewReader("pool: tank\njails:\n  max_states: " + in + "\n"))
		if err != nil || *cfg.Jails.MaxStates != want {
			t.Fatalf("max_states %s: %+v %v", in, cfg.Jails, err)
		}
	}
	for _, bad := range []string{"-1", "10000001"} {
		if _, err := daemon.Decode(strings.NewReader("pool: tank\njails:\n  max_states: " + bad + "\n")); err == nil || !strings.Contains(err.Error(), "jails.max_states") {
			t.Errorf("max_states %s: %v", bad, err)
		}
	}
}
