package backupd

import (
	"testing"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/sdk/api"
)

func TestPeerPermission(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    auth.Cred
		want api.Permission
	}{
		{"root", auth.Cred{UID: 0}, api.PermAdmin},
		{"root with other groups", auth.Cred{UID: 0, GID: 5, Groups: []uint32{7}}, api.PermAdmin},
		{"non-root in group 0", auth.Cred{UID: 1000, GID: 0, Groups: []uint32{0}}, ""},
		{"stranger", auth.Cred{UID: 1000, GID: 1000}, ""},
	} {
		if got := peerPermission(tc.c); got != tc.want {
			t.Errorf("%s: %q want %q", tc.name, got, tc.want)
		}
	}
}
