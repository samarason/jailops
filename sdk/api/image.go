package api

import (
	"strings"
	"time"
)

// Image is a named line of immutable base generations, built from pkgbase.
// Images are ScopeFleet objects; generations are replicated as datasets.
type Image struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ImageSpec   `json:"spec"`
	Status   ImageStatus `json:"status"`
}

// ImageSpec is the desired definition of an image.
type ImageSpec struct {
	// Comment is what the object is for: one line of free text.
	Comment string `json:"comment,omitempty"`
	OS      OS     `json:"os"`
	Release string `json:"release"` // "15.0-RELEASE" for FreeBSD, "3.22" for Alpine
	Arch    string `json:"arch"`    // "amd64", "arm64"
	// Source describes where the base comes from.
	Source ImageSource `json:"source"`
	// Aliases are movable names such as "stable" or "latest".
	Aliases []string `json:"aliases,omitempty"`
	// Retention keeps generations that no jail uses for a while.
	Retention ImageRetention `json:"retention,omitempty"`
	// AutoUpgrade upgrades the image every night: the next generation is built (the patch levels of the release),
	// the thin jails of the image move to it, and the packages inside the jails are upgraded.
	AutoUpgrade *ImageAutoUpgrade `json:"auto_upgrade,omitempty"`
}

// DefaultAutoUpgradeAt is the time of day an image with auto upgrade is upgraded when At is empty.
const DefaultAutoUpgradeAt = "03:00"

// ImageAutoUpgrade is the nightly upgrade of one image (one release). It does what a person does by hand with
// 'jailops image upgrade IMAGE' and an update of the packages of each jail: a jail whose update strategy is
// manual or in place is left alone, a jail that fails stops the run, and the run is recorded in
// ImageStatus.AutoUpgrade.
type ImageAutoUpgrade struct {
	Enabled bool `json:"enabled"`
	// At is the time of day, HH:MM in the host's time zone; empty means DefaultAutoUpgradeAt. A host that was off
	// at that time runs the upgrade when it is back, within four hours; later it waits for the next night.
	At string `json:"at,omitempty"`
	// Packages also upgrades the packages inside the jails of the image (pkg upgrade, apk upgrade).
	Packages bool `json:"packages,omitempty"`
}

// Outcomes of an automatic upgrade run.
const (
	ImageUpgradeRunOK        = "ok"        // a generation was built and every jail moved
	ImageUpgradeRunUnchanged = "unchanged" // nothing new to install
	ImageUpgradeRunFailed    = "failed"    // see Detail
)

// ImageUpgradeRun is one automatic upgrade of an image.
type ImageUpgradeRun struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Result   string    `json:"result"`
	// Generation is the generation that was built; empty when nothing changed or the build failed.
	Generation string `json:"generation,omitempty"`
	// Jails counts the jails moved to the new generation and the jails whose packages were upgraded.
	JailsMoved    int `json:"jails_moved,omitempty"`
	JailsUpgraded int `json:"jails_upgraded,omitempty"`
	JailsFailed   int `json:"jails_failed,omitempty"`
	// Detail says what failed, in one line.
	Detail string `json:"detail,omitempty"`
}

// ImageAutoUpgradeStatus is what the daemon knows about the automatic upgrade of an image.
type ImageAutoUpgradeStatus struct {
	// Next is the time of the next run; zero when auto upgrade is off.
	Next time.Time `json:"next,omitempty"`
	// Recent holds the latest runs, newest first (up to ten).
	Recent []ImageUpgradeRun `json:"recent,omitempty"`
}

// ImageSource describes how a generation is built.
type ImageSource struct {
	Type string `json:"type"` // "pkgbase" (FreeBSD), "minirootfs" (Alpine), "debootstrap"
	// Repo is the package repository or rootfs mirror.
	Repo string `json:"repo,omitempty"`
	// Sets lists pkgbase sets, for example "FreeBSD-set-minimal-jail".
	Sets []string `json:"sets,omitempty"`
	// Keys pins the signing keys. FreeBSD pkgbase uses the keys under
	// /usr/share/keys/pkgbase-<major>.
	Keys string `json:"keys,omitempty"`
}

// ImageRetention is how long unused generations are kept.
type ImageRetention struct {
	KeepLast int `json:"keep_last,omitempty"`
	KeepDays int `json:"keep_days,omitempty"`
}

// ImageStatus is the observed state of an image on one host.
type ImageStatus struct {
	Generations []ImageGeneration `json:"generations,omitempty"`
	// Aliases maps alias to generation number.
	Aliases map[string]int `json:"aliases,omitempty"`
	// AutoUpgrade is the state of the nightly upgrade; nil when the image has none.
	AutoUpgrade *ImageAutoUpgradeStatus `json:"auto_upgrade,omitempty"`
}

// ImageGeneration is one immutable build of an image. Its dataset has an @ro
// snapshot that never changes. A generation is deleted only when nothing
// references it.
type ImageGeneration struct {
	Number int `json:"number"`
	// Name is "<image>#g<number>".
	Name string `json:"name"`
	// Parent is the generation this one was built from, if any.
	Parent int `json:"parent,omitempty"`
	// Manifest is a hash over the sorted installed package set and versions.
	Manifest string `json:"manifest"`
	Packages int    `json:"packages,omitempty"`
	// FreeBSDVersion is the FreeBSD version the base packages of the generation were built from, taken from the
	// version of its FreeBSD-runtime package when it was built: "15.1-RELEASE-p6" for a release and its patch level,
	// the package version as it is for a snapshot of a branch ("15.snap20261031190411"). Empty for a generation built
	// before JailOps recorded it, and for a Linux image.
	FreeBSDVersion string    `json:"freebsd_version,omitempty"`
	Dataset        string    `json:"dataset,omitempty"`
	CreatedAt      time.Time `json:"created_at,omitzero"`
	// Refs lists jails that use this generation.
	Refs []string `json:"refs,omitempty"`
	// Storages lists the storage whose pool holds a copy. Clones need the
	// generation on the jail's own pool, so each pool keeps its own copy.
	Storages []string `json:"storages,omitempty"`
}

// ImageBuild is the body of POST /api/v1/images/{name}/generations.
type ImageBuild struct {
	// FromGeneration builds the next generation from an earlier one by
	// upgrading its packages; zero builds from the source.
	FromGeneration int  `json:"from_generation,omitempty"`
	DryRun         bool `json:"dry_run,omitempty"`
	// Storage names the storage whose pool is built on; empty means the
	// storage named "default". Other pools receive the generation when a jail there
	// needs it.
	Storage string `json:"storage,omitempty"`
}

// ImageUpgrade is the body of POST /api/v1/images/{name}/upgrade: build the
// next generation from the newest one, then move the thin jails that use the
// image to it, one at a time, stopping at the first that fails.
type ImageUpgrade struct {
	// NoJails builds the generation and moves no jail.
	NoJails bool `json:"no_jails,omitempty"`
	// Project restricts the jails moved to one project; empty means every
	// project the caller may administer.
	Project string `json:"project,omitempty"`
	// DryRun plans the build and lists the jails that would move; nothing changes.
	DryRun bool `json:"dry_run,omitempty"`
	// Storage names the storage whose pool is built on; see ImageBuild.Storage.
	Storage string `json:"storage,omitempty"`
}

// Jail outcomes of an image upgrade.
const (
	ImageUpgradeUpgraded     = "upgraded"
	ImageUpgradeSkipped      = "skipped"
	ImageUpgradeFailed       = "failed"
	ImageUpgradeNotAttempted = "not_attempted"
	// ImageUpgradePlanned is the outcome of a dry run: the jail would move.
	ImageUpgradePlanned = "planned"
)

// ImageUpgradeJail is what an image upgrade did with one jail.
type ImageUpgradeJail struct {
	Jail    string `json:"jail"`
	Project string `json:"project"`
	// Status is upgraded, skipped, failed, not_attempted or planned.
	Status string `json:"status"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	// Reason says why the jail was skipped, failed or not attempted.
	Reason string `json:"reason,omitempty"`
	// Record is the id of the update history record the move wrote.
	Record string `json:"record,omitempty"`
}

// ImageUpgradeResult is the result of the image upgrade operation.
type ImageUpgradeResult struct {
	// From is the generation the build started from.
	From string `json:"from"`
	// Generation is the generation that was built (planned, for a dry run).
	// It is empty when the package set did not change.
	Generation *ImageGeneration `json:"generation,omitempty"`
	// Unchanged is true when the newest generation already holds the current
	// package set: no generation was kept and no jail was touched.
	Unchanged bool     `json:"unchanged,omitempty"`
	Plan      []string `json:"plan,omitempty"`
	DryRun    bool     `json:"dry_run,omitempty"`
	// Jails lists every jail that uses the image, with its outcome.
	Jails []ImageUpgradeJail `json:"jails"`
}

// ImageAliasSet is the body of PUT /api/v1/images/{name}/aliases/{alias}.
type ImageAliasSet struct {
	// Generation is the generation number the alias points at; zero means the newest.
	Generation int `json:"generation,omitempty"`
}

// BaseRelease is a FreeBSD release without its patch level: "15.1-RELEASE" for the kern.osrelease
// "15.1-RELEASE-p3". It is the release a new image of the host is created with.
func BaseRelease(osrelease string) string {
	if i := strings.Index(osrelease, "-p"); i > 0 {
		return osrelease[:i]
	}
	return osrelease
}

// ImageNameForRelease is the name of the image of a FreeBSD release: "freebsd-15-1" for "15.1-RELEASE" (or
// "15.1-RELEASE-p3"). An image is one release; its generations are the patch levels. It returns "" for a release
// that is not MAJOR.MINOR-something.
func ImageNameForRelease(release string) string {
	num, _, _ := strings.Cut(release, "-")
	major, minor, ok := strings.Cut(num, ".")
	if !ok || !digits(major) || !digits(minor) {
		return ""
	}
	return "freebsd-" + major + "-" + minor
}

func digits(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ImageCreateHint is the hint of a request that needs an image that does not exist: the two commands that make
// image name (what is how the hint calls it, "it" or "the base image"), with the alias only when the request named
// one, for the release given (the host's). An empty name is the image of the release; an empty release writes
// 15.1-RELEASE, the oldest release JailOps runs on.
func ImageCreateHint(what, name, alias, release string) string {
	if release == "" {
		release = "15.1-RELEASE"
	}
	if name == "" {
		name = ImageNameForRelease(release)
	}
	create := "jailops image create " + name + " --release " + release
	if alias != "" {
		create += " --alias " + alias
	}
	return "create " + what + " with '" + create + "', then build it with 'jailops image build " + name +
		"' (the console's Images page does both with Create image)"
}
