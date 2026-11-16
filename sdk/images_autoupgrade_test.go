package sdk_test

import (
	"testing"

	"jailops.net/jailops/sdk/api"
)

// The nightly upgrade of an image is part of its spec, set with a patch; the status says when it runs next.
func TestImageAutoUpgradePatch(t *testing.T) {
	srv, c := newEnv(t)
	seedBasics(srv)
	ctx := ctxT(t)
	patch := map[string]any{"spec": map[string]any{"auto_upgrade": api.ImageAutoUpgrade{Enabled: true, At: "04:30", Packages: true}}}
	im, err := c.Images().Patch(ctx, "freebsd-15", patch, "")
	if err != nil || im.Spec.AutoUpgrade == nil || !im.Spec.AutoUpgrade.Packages || im.Spec.AutoUpgrade.At != "04:30" {
		t.Fatalf("%v %+v", err, im.Spec.AutoUpgrade)
	}
	if im.Status.AutoUpgrade == nil || im.Status.AutoUpgrade.Next.Hour() != 4 || im.Status.AutoUpgrade.Next.Minute() != 30 {
		t.Fatalf("next run: %+v", im.Status.AutoUpgrade)
	}
	if len(im.Status.Generations) != 1 || im.Spec.Release != "15.0-RELEASE" {
		t.Fatalf("the patch keeps the rest: %+v", im)
	}
	bad := map[string]any{"spec": map[string]any{"auto_upgrade": map[string]any{"enabled": true, "at": "25:00"}}}
	if _, err := c.Images().Patch(ctx, "freebsd-15", bad, ""); !api.IsCode(err, api.CodeInvalid) {
		t.Fatalf("a bad time: %v", err)
	}
	off := map[string]any{"spec": map[string]any{"auto_upgrade": map[string]any{"enabled": false}}}
	if im, err = c.Images().Patch(ctx, "freebsd-15", off, ""); err != nil || im.Status.AutoUpgrade != nil || im.Spec.AutoUpgrade.Enabled {
		t.Fatalf("off: %v %+v", err, im)
	}
}
