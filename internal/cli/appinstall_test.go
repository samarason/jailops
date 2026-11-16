package cli_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"jailops.net/jailops/internal/cli"
	"jailops.net/jailops/sdk/api"
	"jailops.net/jailops/sdk/fake"
)

// An app is installed as a jail with one command; the report says how to
// reach it, 'installed' lists what came from the catalog, and the refusals of
// the server are reported as they are.
func TestAppInstall(t *testing.T) {
	h := newHarness(t)
	h.seed() // freebsd-15 is 15.0-RELEASE: too old for the definitions
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}}})
	h.srv.SeedGeneration("freebsd-151")
	h.srv.SeedInvalidApp("broken", "title: is required")
	tr := h.transcript()
	tr.ok("app", "installed")
	tr.ok("app", "install", "nginx", "--image", "freebsd-151", "--dry-run")
	tr.ok("app", "install", "nginx", "--image", "freebsd-151")
	tr.ok("app", "install", "postgresql", "db", "--image", "freebsd-151", "--network", "lan", "--storage", "default", "--memory", "2G", "--disk", "20G", "--cpu", "2")
	tr.ok("app", "install", "valkey", "--image", "freebsd-151", "--no-wait")
	tr.ok("app", "installed")
	tr.ok("app", "installed", "ng*")
	tr.ok("app", "installed", "-o", "name")
	tr.ok("list")
	tr.do("", "app", "install", "nginx", "--image", "freebsd-151")
	tr.ok("app", "install", "nginx", "web2", "--dry-run") // no --image: the highest release the host runs
	tr.do("", "app", "install", "nginx", "web2", "--image", "freebsd-15")
	tr.do("", "app", "install", "missing")
	tr.do("", "app", "install", "broken")
	tr.do("", "app", "install", "nginx", "web2", "--image", "freebsd-151", "--network", "other")
	tr.do("", "app", "install")
	tr.golden("appinstall")

	out, _, code := h.run("", "app", "install", "nginx", "web3", "--image", "freebsd-151", "-o", "json")
	if code != 0 {
		t.Fatal(out)
	}
	var res api.AppInstallResult
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.App != "nginx" || res.Jail.Metadata.Name != "web3" || res.Snapshot != "app-installed" ||
		res.Jail.Metadata.Labels[api.LabelApp] != "nginx" || res.Jail.Metadata.Labels[api.LabelAppVersion] != "1.30.6,3" || len(res.Ports) != 1 || res.Ports[0].Endpoint == "" {
		t.Fatalf("%v %+v", err, res)
	}
	if len(res.Jail.Spec.Volumes) != 1 || res.Jail.Spec.Volumes[0].Mount != "/usr/local/www" || res.Jail.Spec.Resources.Memory != "256M" {
		t.Fatalf("%+v", res.Jail.Spec)
	}
	out, _, code = h.run("", "app", "installed", "-o", "json")
	if code != 0 {
		t.Fatal(out)
	}
	var rows []struct {
		Metadata api.ObjectMeta `json:"metadata"`
		App      string         `json:"app"`
		Version  string         `json:"version"`
		Ports    []string       `json:"ports"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 4 || rows[0].App != "postgresql" || rows[0].Ports[0] != "5432/tcp" || rows[0].Version != "18.6" {
		t.Fatalf("%v %+v", err, rows)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"app", "install", ""}, "postgresql"},
		{[]string{"app", "install", "nginx", "--network", ""}, "lan"},
		{[]string{"app", "install", "nginx", "--storage", ""}, "default"},
		{[]string{"app", "install", "nginx", "--image", ""}, "freebsd-151"},
	} {
		out, _, code := h.run("", append([]string{"__complete"}, c.args...)...)
		if code != 0 || !strings.Contains(out, c.want) {
			t.Errorf("complete %v: %d %q", c.args, code, out)
		}
	}
}

// commandAccepted parses a command line the way the real command tree would,
// without running it: the command must exist, its flags must be known and its
// arguments must fit. It returns the path of the command found.
func commandAccepted(line string) (string, error) {
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != "jailops" {
		return "", fmt.Errorf("%q does not start with jailops", line)
	}
	root := cli.NewRootCommand(&cli.Env{})
	cmd, rest, err := root.Find(f[1:])
	if err != nil {
		return "", err
	}
	if cmd == root || !cmd.Runnable() {
		return "", fmt.Errorf("%q names no command", line)
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return "", err
	}
	if err := cmd.ValidateArgs(cmd.Flags().Args()); err != nil {
		return "", err
	}
	return cmd.CommandPath(), nil
}

// The rollback command the install report prints must be one the CLI accepts.
func TestAppInstallRollbackCommandIsReal(t *testing.T) {
	if _, err := commandAccepted("jailops jail rollback web --scope all --snapshot app-installed"); err == nil {
		t.Fatal("the checker accepted an unknown flag")
	}
	h := newHarness(t)
	h.seed()
	h.srv.SeedImage(api.Image{Metadata: api.ObjectMeta{Name: "freebsd-151"},
		Spec: api.ImageSpec{OS: api.OSFreeBSD, Release: "15.1-RELEASE", Arch: "amd64", Source: api.ImageSource{Type: "pkgbase"}, Aliases: []string{"stable"}}})
	h.srv.SeedGeneration("freebsd-151")
	out, errs, code := h.run("", "app", "install", "nginx", "--image", "freebsd-151")
	if code != 0 {
		t.Fatal(out, errs)
	}
	m := regexp.MustCompile(`\((jailops [^)]*) goes back to it\)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no rollback command in the report:\n%s", out)
	}
	path, err := commandAccepted(m[1])
	if err != nil || path != "jailops jail rollback" {
		t.Fatalf("%q: %q %v", m[1], path, err)
	}
	if !strings.Contains(m[1], " --all ") || !strings.HasSuffix(m[1], " --snapshot app-installed") {
		t.Fatalf("the command must restore root and data from the install snapshot: %q", m[1])
	}
}

// Without --image the install takes the only FreeBSD image with the alias
// stable, here the quick start's freebsd-15 (too old for the definition).
func TestAppInstallDefaultImage(t *testing.T) {
	h := newHarness(t)
	h.seed()
	_, errs, code := h.run("", "app", "install", "nginx")
	if code != 2 || !strings.Contains(errs, `image "freebsd-15" is release 15.0-RELEASE`) {
		t.Fatalf("%d %s", code, errs)
	}
}

// Without any image, app install and jail create say how to make the base image: the two commands, for the image of
// the host's release when the server reports it and of 15.1-RELEASE when it does not. No alias is proposed; one the
// request named is kept.
func TestNoImageHintNamesTheCommands(t *testing.T) {
	h := newHarness(t, fake.WithRelease("15.2-RELEASE-p1"))
	_, errs, code := h.run("", "app", "install", "nginx")
	if code != 2 || !strings.Contains(errs, "there is no FreeBSD image yet") ||
		!strings.Contains(errs, "hint: create the base image with 'jailops image create freebsd-15-2 --release 15.2-RELEASE', then build it with 'jailops image build freebsd-15-2'") {
		t.Fatalf("app install: %d %s", code, errs)
	}
	out, errs, _ := h.run("", "image", "list")
	if !strings.Contains(out+errs, "jailops image create freebsd-15-2 --release 15.2-RELEASE, then jailops image build freebsd-15-2") {
		t.Fatalf("image list: %s %s", out, errs)
	}
	h.srv.SeedNetwork(api.Network{Metadata: api.ObjectMeta{Name: "lan"}, Spec: api.NetworkSpec{IPv4: &api.IPv4Net{
		Subnet: "10.20.0.0/24", Gateway: "10.20.0.1", Range: "10.20.0.10-10.20.0.20"}}})
	_, errs, code = h.run("", "jail", "create", "web", "--image", "base")
	if code == 0 || !strings.Contains(errs, "hint: create it with 'jailops image create base --release 15.2-RELEASE', then build it with 'jailops image build base'") {
		t.Fatalf("jail create: %d %s", code, errs)
	}
	_, errs, _ = h.run("", "jail", "create", "web", "--image", "base@lts")
	if !strings.Contains(errs, "'jailops image create base --release 15.2-RELEASE --alias lts'") {
		t.Fatalf("jail create with an alias: %s", errs)
	}
	h = newHarness(t, fake.WithRelease(""))
	_, errs, _ = h.run("", "app", "install", "nginx")
	if !strings.Contains(errs, "jailops image create freebsd-15-1 --release 15.1-RELEASE'") {
		t.Fatalf("no release: %s", errs)
	}
}
