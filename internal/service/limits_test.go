package service

import (
	"strings"
	"testing"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

// The quota ZFS reports is bytes; the stored one compares by value, so a project's quota is set once and not on
// every pass of the reconcile loop.
func TestQuotaComparesByValue(t *testing.T) {
	for _, c := range []struct {
		have, want string
		differs    bool
	}{
		{"4294967296", "4294967296", false},
		{"4294967296", "4G", false},
		{"4294967296", "4GiB", false},
		{"4294967296", "5G", true},
		{"none", "4G", true},
		{"-", "4G", true},
		{"0", "4G", true},
	} {
		if got := quotaDiffers(c.have, c.want); got != c.differs {
			t.Errorf("%s vs %s: %v", c.have, c.want, got)
		}
	}
}

func TestUplinkOfARoutedNetwork(t *testing.T) {
	ifs := []ifconfig.Iface{
		{Name: "em0"}, {Name: "em1"},
		{Name: "vlan7", Groups: []string{"vlan"}, VlanParent: "em1", VlanTag: 7},
		{Name: "lagg0", Groups: []string{"lagg"}},
		{Name: "jo1", Groups: []string{"bridge"}, Members: []ifconfig.Member{{Name: "em2"}}}, {Name: "em2"},
		{Name: "lo0", Groups: []string{"lo"}, Flags: []string{"LOOPBACK"}}, {Name: "jo1ga", Groups: []string{"epair"}, Description: "jailops net lan gateway"},
		{Name: "upa", Groups: []string{"epair"}},
	}
	for up, want := range map[string]string{
		"em0": "", "vlan7": "", "lagg0": "", "em1": "",
		"em2":   "member of bridge jo1",
		"jo1":   "bridge interface",
		"lo0":   "lo interface",
		"jo1ga": "interface of JailOps",
		"upa":   "",
		"em9":   "does not exist",
	} {
		got := routedUplinkProblem(up, ifs)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", up, got, want)
		}
	}
	if c := strings.Join(uplinkCandidates(ifs, false), " "); c != "em0 em1 vlan7 lagg0 upa" {
		t.Errorf("candidates %q", c)
	}
}

// Objects created before the name limits keep working; the doctor lists them, and says nothing when there is none.
func TestDoctorListsNamesOverTheLimits(t *testing.T) {
	s := newSvc(t)
	c := &checkSet{}
	s.doctorNameLengths(bg, c)
	if len(c.list) != 0 {
		t.Fatalf("%+v", c.list)
	}
	if _, err := s.projKind.create(bg, api.ObjectMeta{Name: "a-long-project-name"}, api.ProjectSpec{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.projKind.create(bg, api.ObjectMeta{Name: "short"}, api.ProjectSpec{}); err != nil {
		t.Fatal(err)
	}
	s.doctorNameLengths(bg, c)
	if len(c.list) != 1 || c.list[0].Name != "names.length" || c.list[0].Status != api.DoctorInfo ||
		!strings.Contains(c.list[0].Message, "project a-long-project-name (19 > 13)") || strings.Contains(c.list[0].Message, "short") {
		t.Fatalf("%+v", c.list)
	}
}
