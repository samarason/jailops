package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"jailops.net/jailops/sdk/api"
)

// Without --image an app is installed from the FreeBSD image of the highest release the host can run, by its bare
// name, the first by name on a tie; none is refused with the images there are.
func TestDefaultAppImage(t *testing.T) {
	s := newSvc(t)
	host := "15.2-RELEASE-p1"
	s.d.Sysctl = func(context.Context, string) (string, error) { return host, nil }
	ctx := WithActor(bg, Actor{Name: "root", Kind: "unix", Perm: api.PermAdmin, Global: true})
	add := func(name string, os api.OS, release string, aliases ...string) {
		t.Helper()
		if _, err := s.imgKind.create(ctx, api.ObjectMeta{Name: name}, api.ImageSpec{OS: os, Release: release, Aliases: aliases}); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(msg, hint string) {
		t.Helper()
		_, err := s.defaultAppImage(ctx)
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Code != api.CodeInvalid || !strings.Contains(ae.Message, msg) || !strings.Contains(ae.Hint, hint) {
			t.Fatalf("want invalid %q with hint %q, got %v", msg, hint, err)
		}
	}
	want := func(image string) {
		t.Helper()
		if got, err := s.defaultAppImage(ctx); err != nil || got != image {
			t.Fatalf("want %q, got %q %v", image, got, err)
		}
	}
	// no FreeBSD image at all: the hint names the image of the host's release
	refused("there is no FreeBSD image yet", "create the base image with 'jailops image create freebsd-15-2 --release 15.2-RELEASE', then build it with 'jailops image build freebsd-15-2'")
	add("alp", api.OSLinux, "3.22")
	refused("there is no FreeBSD image yet", "; your images: alp")
	add("freebsd-16-0", api.OSFreeBSD, "16.0-RELEASE")
	refused("every FreeBSD image is of a newer release than this host (15.2-RELEASE)", "name an image with --image; your images: alp, freebsd-16-0")
	add("freebsd-15-1", api.OSFreeBSD, "15.1-RELEASE", "stable")
	want("freebsd-15-1")
	add("freebsd-15-2", api.OSFreeBSD, "15.2-RELEASE")
	want("freebsd-15-2")
	add("base", api.OSFreeBSD, "15.2-RELEASE")
	add("zz", api.OSFreeBSD, "15.2-RELEASE")
	want("base") // a tie goes to the first name
	add("odd", api.OSFreeBSD, "weird")
	want("base")
	// a host whose release cannot be read: every image counts, the newest release wins
	s2 := newSvc(t)
	for _, n := range []string{"freebsd-15-1", "freebsd-16-0"} {
		r := map[string]string{"freebsd-15-1": "15.1-RELEASE", "freebsd-16-0": "16.0-RELEASE"}[n]
		if _, err := s2.imgKind.create(ctx, api.ObjectMeta{Name: n}, api.ImageSpec{OS: api.OSFreeBSD, Release: r}); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s2.defaultAppImage(ctx); err != nil || got != "freebsd-16-0" {
		t.Fatalf("unknown host release: %q %v", got, err)
	}
	s3 := newSvc(t)
	if _, err := s3.defaultAppImage(ctx); err == nil || !strings.Contains(err.(*api.Error).Hint, "jailops image create freebsd-15-1 --release 15.1-RELEASE'") {
		t.Fatalf("unknown host release, no image: %v", err)
	}
}

// The hints for a missing image name the host's release when the service can read it, else a placeholder; the
// environment reports it as the kernel version.
func TestMissingImageHintNamesTheHostRelease(t *testing.T) {
	s := newSvc(t)
	reads := 0
	s.d.Sysctl = func(_ context.Context, name string) (string, error) {
		reads++
		if name != "kern.osrelease" {
			return "", errors.New("unexpected sysctl " + name)
		}
		return "15.1-RELEASE-p3\n", nil
	}
	ctx := WithActor(bg, Actor{Name: "root", Kind: "unix", Perm: api.PermAdmin, Global: true})
	_, err := s.defaultAppImage(ctx)
	var ae *api.Error
	if !errors.As(err, &ae) || !strings.Contains(ae.Hint, "jailops image create freebsd-15-1 --release 15.1-RELEASE'") {
		t.Fatalf("hint: %v", err)
	}
	_, _, err = s.imageFor(api.JailSpec{Image: "base@lts"})
	if !errors.As(err, &ae) || ae.Code != api.CodeNotFound ||
		ae.Hint != "create it with 'jailops image create base --release 15.1-RELEASE --alias lts', then build it with 'jailops image build base' (the console's Images page does both with Create image)" {
		t.Fatalf("jail create hint: %v %q", err, ae.Hint)
	}
	if env := s.Info("trusted").Environment; env.KernelVersion != "15.1-RELEASE-p3" {
		t.Fatalf("environment: %+v", env)
	}
	if reads != 1 {
		t.Fatalf("the release is read once, then kept: %d reads", reads)
	}
}
