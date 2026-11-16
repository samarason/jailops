package validate

import (
	"strings"
	"testing"
)

func TestCanonicalSize(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"4GiB", "4294967296"},
		{"4G", "4294967296"},
		{"512m", "536870912"},
		{"1k", "1024"},
		{"7B", "7"},
		{"100", "100"},
		{"16T", "17592186044416"},
		{"17592186044416", "17592186044416"},
		{"0", ""},
		{"0G", ""},
		{"17592186044417", ""},
		{"17T", ""},
		{"1P", ""},
		{"-1G", ""},
		{"1.5G", ""},
		{"4 GiB", ""},
		{"lots", ""},
		{"", ""},
	} {
		got, err := CanonicalSize("quota", c.in)
		if c.want == "" {
			wantInvalid(t, err, "quota")
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q %v, want %q", c.in, got, err, c.want)
		}
	}
}

func TestNameLengthLimits(t *testing.T) {
	for _, c := range []struct {
		kind string
		max  int
	}{{"project", MaxProjectName}, {"jail", MaxJailName}, {"volume", MaxVolumeName}, {"image", MaxImageName}} {
		if err := NameLength(c.kind, "name", strings.Repeat("a", c.max), c.max); err != nil {
			t.Errorf("%s at the limit: %v", c.kind, err)
		}
		err := NameLength(c.kind, "name", strings.Repeat("a", c.max+1), c.max)
		wantInvalid(t, err, "name")
		if !strings.Contains(err.Error(), "at most") {
			t.Errorf("%s: %v", c.kind, err)
		}
	}
	if MaxStorageDataset != 91 {
		t.Errorf("MaxStorageDataset = %d", MaxStorageDataset)
	}
	// the deepest derived name of a jail at every limit, on a storage at its limit, fits ZFS with two to spare
	deepest := strings.Repeat("d", MaxStorageDataset) + "/projects/" + strings.Repeat("p", MaxProjectName) + "/jails/" + strings.Repeat("j", MaxJailName) +
		"/data/" + strings.Repeat("v", MaxVolumeName) + "@" + strings.Repeat("s", MaxSnapshotName)
	if len(deepest) != MaxDatasetName-2 {
		t.Errorf("deepest name has %d characters", len(deepest))
	}
}

func TestSnapshotName(t *testing.T) {
	good := []string{"a", "before-upgrade", "v1-2-3", "update-1730000000-ab", strings.Repeat("s", 64)}
	bad := []string{"", "0", "v1.2_3", "a-", "-a", ".a", "_a", "Snap", "a:b", "a b", "a/b", "a@b", strings.Repeat("s", 65), strings.Repeat("s", 70), "jo-mine"}
	for _, s := range good {
		if err := SnapshotName("name", s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range bad {
		wantInvalid(t, SnapshotName("name", s), "name")
	}
	if err := SnapshotName("name", strings.Repeat("s", 70)); !strings.Contains(err.Error(), "at most 64") {
		t.Errorf("%v", err)
	}
}

func TestStorageDatasetAndBudget(t *testing.T) {
	if err := StorageDataset("dataset", "tank/"+strings.Repeat("d", 86)); err != nil {
		t.Error(err)
	}
	wantInvalid(t, StorageDataset("dataset", "tank/"+strings.Repeat("d", 87)), "dataset")
	if err := DatasetBudget("name", "jail x", strings.Repeat("d", 190), SnapshotReserve); err != nil {
		t.Error(err)
	}
	wantInvalid(t, DatasetBudget("name", "jail x", strings.Repeat("d", 191), SnapshotReserve), "name")
}

// pfctl -a loads an anchor path of 63 characters and refuses one of 64 (FreeBSD 15.2).
func TestAnchorPath(t *testing.T) {
	if err := AnchorPath("name", "jailops/net."+strings.Repeat("n", 51)); err != nil {
		t.Error(err)
	}
	wantInvalid(t, AnchorPath("name", "jailops/net."+strings.Repeat("n", 52)), "name")
	// what the limits of new names give: jailops/<project>/<jail> and jailops/net.<network of a project>
	if n := len("jailops/") + MaxProjectName + 1 + MaxJailName; n > MaxAnchorPath {
		t.Errorf("a jail anchor at the limits has %d characters", n)
	}
}
