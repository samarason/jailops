package api

import "regexp"

// NamePattern is the one rule for every name a user chooses (jail, project, network, storage, image, volume, policy,
// address set, profile, user, ...): lower case letters, digits and hyphens, starting with a letter and not ending in a
// hyphen. No underscore, no dot, no upper case. Each kind has a length limit of its own where a derived name needs one
// (see the Max constants) and 63 characters elsewhere. The console mirrors the pattern (web/shared/src/lib/names.ts).
const NamePattern = `^[a-z]([a-z0-9-]*[a-z0-9])?$`

// MaxName is the longest name where no derived name sets a shorter limit.
const MaxName = 63

var nameRule = regexp.MustCompile(NamePattern)

// IsName reports whether s follows NamePattern and has at most max characters (max 0 means MaxName).
func IsName(s string, max int) bool {
	if max <= 0 {
		max = MaxName
	}
	return len(s) <= max && nameRule.MatchString(s)
}
