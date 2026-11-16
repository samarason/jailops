package imagegen

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// Property names. The lifecycle package reads some of them from generation
// datasets and keeps its own copies of the strings.
const (
	PropManaged   = "jailops:managed"
	PropKind      = "jailops:kind"
	PropImage     = "jailops:image"
	PropGen       = "jailops:gen"
	PropParent    = "jailops:parent"
	PropManifest  = "jailops:manifest"
	PropPackages  = "jailops:packages"
	PropOSRelease = "jailops:osrelease"
	// PropFreeBSD is the FreeBSD version of the generation's base packages (FreeBSDVersion), set when it is built.
	PropFreeBSD = "jailops:freebsd_version"
	PropCreated = "jailops:created"
	PropSource  = "jailops:source"
	PropOS      = "jailops:os"
	PropDeleted = "jailops:deleted"
	PropAliases = "jailops:aliases"
	// PropLastGen records the highest generation number ever built, so numbers
	// are never reused after generations are deleted.
	PropLastGen = "jailops:last_gen"

	KindGeneration = "generation"
	KindStaging    = "generation-staging"
	KindImage      = "image"

	// HoldTag protects every @ro snapshot against accidental destruction.
	HoldTag = "jailops-ro"
	// ROSnap is the name of the immutable snapshot.
	ROSnap = "ro"
)

var (
	genRe = regexp.MustCompile(`^g([0-9]+)$`)
)

// GenerationName is "<image>#g<N>".
func GenerationName(image string, n int) string { return fmt.Sprintf("%s#g%d", image, n) }

// Ref is a parsed image reference: "<image>@<alias>", "<image>#g<N>" or a
// bare "<image>" (the newest generation).
type Ref struct {
	Image string
	Alias string
	Gen   int
}

// ParseRef parses an image reference.
func ParseRef(s string) (Ref, error) {
	if img, a, ok := strings.Cut(s, "@"); ok {
		if !validImage(img) || !validAlias(a) {
			return Ref{}, api.Errorf(api.CodeInvalid, "bad image reference %q", s)
		}
		return Ref{Image: img, Alias: a}, nil
	}
	if img, g, ok := strings.Cut(s, "#"); ok {
		m := genRe.FindStringSubmatch(g)
		if !validImage(img) || m == nil {
			return Ref{}, api.Errorf(api.CodeInvalid, "bad image reference %q", s)
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 {
			return Ref{}, api.Errorf(api.CodeInvalid, "bad generation in %q", s)
		}
		return Ref{Image: img, Gen: n}, nil
	}
	if !validImage(s) {
		return Ref{}, api.Errorf(api.CodeInvalid, "bad image reference %q", s)
	}
	return Ref{Image: s}, nil
}

// Layout holds the dataset and mount paths of the image tree.
type Layout struct {
	Root      string // "<pool>/jailops"
	MountBase string // "/usr/local/jailops" (directory under which images are mounted)
}

func (l Layout) ImageDS(image string) string { return path.Join(l.Root, "images", image) }
func (l Layout) GenDS(image string, n int) string {
	return fmt.Sprintf("%s/g%d", l.ImageDS(image), n)
}
func (l Layout) StagingDS(image string, n int) string {
	return fmt.Sprintf("%s/staging-g%d", l.ImageDS(image), n)
}

// CacheDS is the dataset of the package cache every image build and upgrade shares: a package of the base is
// downloaded once, not into every generation's /var/cache/pkg.
func (l Layout) CacheDS() string { return path.Join(l.Root, "cache") }

// CacheMount is where CacheDS is mounted; PkgCache is the directory pkg(8) keeps its downloads in.
func (l Layout) CacheMount() string { return path.Join(l.MountBase, "cache") }
func (l Layout) PkgCache() string   { return path.Join(l.CacheMount(), "pkg") }

func (l Layout) DeletedParent() string { return path.Join(l.Root, "deleted") }
func (l Layout) DeletedDS(image string, n int) string {
	return fmt.Sprintf("%s/%s-g%d", l.DeletedParent(), image, n)
}
func (l Layout) GenMount(image string, n int) string {
	return fmt.Sprintf("%s/images/%s/g%d", l.MountBase, image, n)
}
func (l Layout) StagingMount(image string, n int) string {
	return fmt.Sprintf("%s/images/%s/staging-g%d", l.MountBase, image, n)
}

// validImage and validAlias follow api.NamePattern (an alias has at most 32 characters).
func validImage(s string) bool { return api.IsName(s, api.MaxName) }
func validAlias(s string) bool { return api.IsName(s, 32) }
