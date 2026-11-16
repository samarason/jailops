package validate

import (
	"jailops.net/jailops/sdk/api"
	"strings"
)

// Length limits of names given to new objects (design section 3.1). They apply when an object is created, renamed or
// copied, never when one is loaded: an installed system whose objects have longer names keeps working, and the doctor
// lists those names (check names.length).
//
// The limits leave room for what JailOps derives from a name. A project prefixes the OS-level name of each of its jails
// and may name a network (project create --new-network). The datasets of a jail are <storage>/projects/<project>/jails/<jail>/data/<volume>@<snapshot>, and ZFS refuses a
// name longer than 255 characters.
const (
	MaxProjectName   = 13
	MaxJailName      = 29
	MaxVolumeName    = 32
	MaxImageName     = 32
	MaxSnapshotName  = 64
	MaxWireGuardName = 12
	// MaxDatasetName is the longest ZFS dataset or snapshot name.
	MaxDatasetName = 255
	// datasetOverhead is what the layout adds to the storage dataset of a jail's deepest name:
	// "/projects/" "/jails/" "/data/" "@".
	datasetOverhead = 10 + 7 + 6 + 1
	// MaxStorageDataset is the longest dataset of a new storage: the deepest derived name of a jail with names at
	// their limits still fits, with two characters to spare.
	MaxStorageDataset = MaxDatasetName - datasetOverhead - (MaxProjectName + MaxJailName + MaxVolumeName + MaxSnapshotName) - 2
)

// NameLength refuses a name of a new object (kind "project", "jail", ...) that is longer than max.
func NameLength(kind, field, name string, max int) error {
	if len(name) > max {
		return Invalid(field, "%s name %q is %d characters long; a new %s name has at most %d", kind, name, len(name), kind, max).
			WithHint("choose a shorter name")
	}
	return nil
}

// SnapshotName validates the name of a new snapshot: lower case letters, digits and hyphens (api.NamePattern), at most 64
// characters, and not with "jo-" (the names JailOps takes itself).
func SnapshotName(field, s string) error {
	if !api.IsName(s, MaxSnapshotName) {
		if len(s) > MaxSnapshotName {
			return Invalid(field, "snapshot name %q is %d characters long; a snapshot name has at most %d", s, len(s), MaxSnapshotName)
		}
		return Invalid(field, "snapshot name %q must follow the name rule (lower case letters, digits and hyphens, starting with a letter)", s)
	}
	if strings.HasPrefix(s, "jo-") {
		return Invalid(field, "snapshot names starting with jo- are reserved for JailOps")
	}
	return nil
}

// StorageDataset refuses the dataset of a new storage that leaves no room for the names JailOps derives below it.
func StorageDataset(field, ds string) error {
	if len(ds) > MaxStorageDataset {
		return Invalid(field, "dataset %q is %d characters long; the dataset of a new storage has at most %d", ds, len(ds), MaxStorageDataset).
			WithHint("ZFS names are at most 255 characters and a jail's datasets add up to 162 to it (<dataset>/projects/<project>/jails/<jail>/data/<volume>@<snapshot>); choose a shorter dataset")
	}
	return nil
}

// DatasetBudget refuses a dataset name that, with a snapshot name of reserve characters ("@" included) appended,
// would be longer than ZFS allows. what says which object the name is derived from.
func DatasetBudget(field, what, dataset string, reserve int) error {
	if n := len(dataset) + reserve; n > MaxDatasetName {
		return Invalid(field, "%s would need the dataset %s, %d characters long, and %d more for its snapshots; ZFS allows %d", what, dataset, len(dataset), reserve, MaxDatasetName).
			WithHint("choose shorter names, or a storage with a shorter dataset")
	}
	return nil
}

// SnapshotReserve is what DatasetBudget keeps free for "@<snapshot>".
const SnapshotReserve = 1 + MaxSnapshotName

// AnchorPath refuses a PF anchor path that pfctl cannot load: `pfctl -a PATH` takes at most 63 characters for the
// whole path (FreeBSD 15.2: "jailops/" and 55 more load, 56 more fail with "pfctl_rules: strlcpy").
func AnchorPath(field, path string) error {
	if len(path) > MaxAnchorPath {
		return Invalid(field, "the firewall anchor %s would be %d characters long; pfctl loads at most %d", path, len(path), MaxAnchorPath).
			WithHint("choose a shorter name")
	}
	return nil
}

// MaxAnchorPath is the longest PF anchor path pfctl loads.
const MaxAnchorPath = 63
