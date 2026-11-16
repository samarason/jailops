package cli

import "testing"

func TestImageWithGenerationAndPatchLevel(t *testing.T) {
	for _, c := range []struct{ ref, gen, ver, want string }{
		{"freebsd-15-1", "freebsd-15-1#g1", "15.1-RELEASE-p6", "freebsd-15-1 (g1, p6)"},
		{"freebsd-15-1", "freebsd-15-1#g1", "15.1-RELEASE", "freebsd-15-1 (g1)"},
		{"freebsd-15-1", "freebsd-15-1#g2", "", "freebsd-15-1 (g2)"},
		{"freebsd-15-1@stable", "freebsd-15-1#g2", "15.snap20261031190411", "freebsd-15-1@stable (g2)"},
		{"freebsd-15-1#g2", "freebsd-15-1#g2", "15.1-RELEASE-p3", "freebsd-15-1#g2 (p3)"},
		{"freebsd-15-1", "", "", "freebsd-15-1"},
	} {
		if got := imageWithGen(c.ref, c.gen, c.ver); got != c.want {
			t.Errorf("%s %s %s: %q, want %q", c.ref, c.gen, c.ver, got, c.want)
		}
	}
}
