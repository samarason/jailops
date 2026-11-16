package apps

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// What the installer runs and writes, as data: the service issues exactly
// these argument vectors and paths, and the tests of the privileged helper
// check the same ones against its allow-list.

// SnapshotName is the snapshot the installer takes of the fresh installation.
const SnapshotName = "app-installed"

// JailopsRepo is the name of the host's pkg repository configuration for
// pkg.jailops.net (docs/install.md); packages with repo jailops come from it.
const JailopsRepo = "jailops"

// PkgInstallArgv is the host command that installs packages into a jail root
// from the FreeBSD repository (repo ports) or from pkg.jailops.net.
func PkgInstallArgv(root, repo string, names []string) []string {
	return PkgInstallCachedArgv(root, repo, "", names)
}

// PkgInstallCachedArgv is PkgInstallArgv with the download cache of pkg set to a directory the host shares between
// installs (pkg -r would otherwise keep a cache in every jail root and fetch the same packages again for each new
// jail). An empty cache leaves pkg's own default.
func PkgInstallCachedArgv(root, repo, cache string, names []string) []string {
	argv := []string{"pkg", "-r", root}
	if cache != "" {
		argv = append(argv, "-o", "PKG_CACHEDIR="+cache)
	}
	argv = append(argv, "install", "-y")
	if repo == JailopsRepo {
		argv = append(argv, "-r", JailopsRepo)
	}
	return append(argv, names...)
}

// PkgJailArgv is a pkg command that runs inside a running jail (pkg -j): pkg enters the jail first, so what it writes
// and the scripts it runs stay in the jail, and it reads the jail's own repository configuration.
func PkgJailArgv(jail string, args ...string) []string {
	return append([]string{"pkg", "-j", jail}, args...)
}

// PkgInstallInJailArgv installs packages from the repository the jail itself is configured for, inside a running jail.
func PkgInstallInJailArgv(jail string, names []string) []string {
	return PkgJailArgv(jail, append([]string{"install", "-y"}, names...)...)
}

// PkgVersionArgv is the host command that reports the installed version of
// one package of a jail root.
func PkgVersionArgv(root, name string) []string {
	return []string{"pkg", "-r", root, "query", "%v", name}
}

// ServiceArgv is the in-jail command that runs an rc.d action.
func ServiceArgv(service, action string) []string {
	return []string{"/usr/sbin/service", service, action}
}

// ServiceStartScript is the fixed shell text of ServiceStartArgv. The service
// name is its first positional parameter, never part of the text. The output
// of the rc script goes to a temporary file in the jail: a daemon the script
// starts inherits that file instead of the pipes of the in-jail exec, which
// would otherwise stay open and keep the caller waiting. The file is printed
// when the start fails and removed in any case.
const ServiceStartScript = `out=$(/usr/bin/mktemp -t jailops) || exit 1; /usr/sbin/service "$1" start </dev/null >"$out" 2>&1; rc=$?; [ $rc -eq 0 ] || /bin/cat "$out"; /bin/rm -f "$out"; exit $rc`

// ServiceStartName is $0 of ServiceStartScript, the name the shell reports in its errors.
const ServiceStartName = "jailops-start"

var serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ServiceStartArgv is the in-jail command that starts an rc.d service with
// its output detached from the caller (ServiceStartScript).
func ServiceStartArgv(service string) ([]string, error) {
	if !serviceNameRE.MatchString(service) {
		return nil, fmt.Errorf("%q is not an rc.d service name", service)
	}
	return []string{"/bin/sh", "-c", ServiceStartScript, ServiceStartName, service}, nil
}

// RcConfPath is the rc.conf of a jail root.
func RcConfPath(root string) string { return root + "/etc/rc.conf" }

// RcVar is one rc.conf variable; it converts to render.RcVar. The package
// does not import the renderer, so the client can link the validator.
type RcVar struct {
	Name, Value string
}

// RcVars lists what the installer writes into rc.conf: <name>_enable=YES
// and the knobs of every service, in the order of the definition.
func RcVars(svcs []api.AppService) []RcVar {
	var out []RcVar
	for _, s := range svcs {
		out = append(out, RcVar{Name: rcName(s.Name) + "_enable", Value: "YES"})
		for _, k := range sortedKeys(s.RC) {
			out = append(out, RcVar{Name: k, Value: s.RC[k]})
		}
	}
	return out
}

// PackageGroups returns the packages to install, grouped by repository in
// the order of the definition (ports first when both are present).
func PackageGroups(pkgs []api.AppPackage) (ports, jailops []string) {
	for _, p := range pkgs {
		if p.Repo == JailopsRepo {
			jailops = append(jailops, p.Name)
		} else {
			ports = append(ports, p.Name)
		}
	}
	return ports, jailops
}

// MaxVolumeName is the longest name of a volume (validate.MaxVolumeName).
const MaxVolumeName = 32

// Volumes turns the data paths into the volumes of the jail: one volume per path, named <jail>-<what the path is
// called>. The names are unique and match the volume name rule; a name that is too long is cut at a dash.
func Volumes(jail string, data []api.AppPath) []api.VolumeAttach {
	var out []api.VolumeAttach
	seen := map[string]bool{}
	for _, d := range data {
		base := VolumeName(d.Path)
		n := volumeFullName(jail, base, "")
		for i := 2; seen[n]; i++ {
			n = volumeFullName(jail, base, "-"+strconv.Itoa(i))
		}
		seen[n] = true
		out = append(out, api.VolumeAttach{Name: n, Mount: d.Path})
	}
	return out
}

// volumeFullName is <jail>-<base><suffix> within MaxVolumeName characters: the base gives way, the jail's name and
// the suffix stay.
func volumeFullName(jail, base, suffix string) string {
	room := MaxVolumeName - len(jail) - 1 - len(suffix)
	if room < 1 {
		return strings.TrimRight(jail[:min(len(jail), MaxVolumeName-len(suffix))], "-") + suffix
	}
	if len(base) > room {
		base = strings.TrimRight(base[:room], "-")
		if base == "" {
			base = "d"
		}
	}
	return jail + "-" + base + suffix
}

// VolumeName derives a dataset name from a data path: lower case letters
// and digits, everything else a dash, at most 40 characters.
func VolumeName(p string) string {
	var b strings.Builder
	dash := true // no leading dash
	for _, r := range strings.ToLower(strings.Trim(p, "/")) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	n := strings.TrimRight(b.String(), "-")
	if len(n) > 40 {
		n = strings.TrimRight(n[:40], "-")
	}
	if n == "" {
		n = "data"
	}
	return n
}

// Limits turns the resource hints of a definition into jail limits.
func Limits(r api.AppResources) api.Resources {
	out := api.Resources{Memory: r.Memory, Disk: r.Disk}
	if r.CPU != "" {
		if f, err := strconv.ParseFloat(r.CPU, 64); err == nil && f > 0 {
			out.CPU = int(math.Ceil(f))
		}
	}
	return out
}

// ReleaseAtLeast reports whether an image release ("15.1-RELEASE",
// "15.1-RELEASE-p3") is at least the definition's release_min ("15.1").
func ReleaseAtLeast(release, minimum string) (bool, error) {
	rel, ok := releaseNumbers(release)
	if !ok {
		return false, fmt.Errorf("%q is not a release", release)
	}
	mn, ok := releaseNumbers(minimum)
	if !ok {
		return false, fmt.Errorf("%q is not a release", minimum)
	}
	return rel[0] > mn[0] || rel[0] == mn[0] && rel[1] >= mn[1], nil
}

func releaseNumbers(s string) ([2]int, bool) {
	s, _, _ = strings.Cut(s, "-")
	maj, min, ok := strings.Cut(s, ".")
	if !ok {
		return [2]int{}, false
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	if err1 != nil || err2 != nil || a < 0 || b < 0 {
		return [2]int{}, false
	}
	return [2]int{a, b}, true
}
