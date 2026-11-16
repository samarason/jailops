package cli

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Completion of a firewall reference, in two levels. Where a reference is expected, Tab offers the kinds (jail:, set:,
// tag:, any, host, as far as the place takes them); after a kind it offers the names that exist in the project. A
// reference is always kind:name: there is no sigil to type.

// refPlace says which references a place takes.
type refPlace struct {
	tag, any, host bool
	// noSet leaves address sets out: a place that takes jails and addresses only.
	noSet bool
	// flat offers the names at once (jail:web, host and the addresses of the jails) instead of the kinds first:
	// worth it where there are two or three kinds and a short list of jails.
	flat bool
	// self is a name that is left out of its own kind: the address set being made, the app being allowed.
	selfKind string
	selfName func(args []string) string
}

var (
	// placeRule is a from or to of a firewall rule.
	placeRule = refPlace{tag: true, any: true}
	// placeMember is a member of an address set.
	placeMember = refPlace{selfKind: "set", selfName: firstArg}
	// placeSource is the source of app allow and app deny.
	placeSource = refPlace{host: true, selfKind: "jail", selfName: firstArg}
	// placeEnd is one end of a firewall test: a jail, an address or the host, never an address set.
	placeEnd = refPlace{host: true, noSet: true, flat: true}
)

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// refNames are the names a reference can use in the project.
type refNames struct{ jails, sets, tags, addrs []string }

// loadRefNames asks the server for the jails, the address sets and the firewall tags of the project; nothing is
// offered when no server answers.
func (a *app) loadRefNames(cmd *cobra.Command, kinds ...string) refNames {
	var rn refNames
	ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
	defer cancel()
	c, err := a.connect(ctx)
	if err != nil {
		return rn
	}
	if slices.Contains(kinds, "jail") || slices.Contains(kinds, "tag") {
		tags := map[string]bool{}
		for j, err := range c.Jails().List(ctx) {
			if err != nil {
				break
			}
			rn.jails = append(rn.jails, j.Metadata.Name)
			for _, ad := range j.Status.Addresses {
				ip, _, _ := strings.Cut(ad, "/")
				rn.addrs = append(rn.addrs, ip)
			}
			for _, t := range j.Spec.Firewall.Tags {
				tags[t] = true
			}
		}
		for t := range tags {
			rn.tags = append(rn.tags, t)
		}
		slices.Sort(rn.tags)
	}
	if slices.Contains(kinds, "set") {
		for s, err := range c.Firewall().AddressSets().List(ctx) {
			if err != nil {
				break
			}
			rn.sets = append(rn.sets, s.Metadata.Name)
		}
	}
	return rn
}

// refWords are the references that complete word in a place: the kinds while no kind is typed, the names after one.
func refWords(word string, p refPlace, rn refNames, self string) []string {
	kinds := []string{"jail:", "set:"}
	if p.noSet {
		kinds = []string{"jail:"}
	}
	if p.tag {
		kinds = append(kinds, "tag:")
	}
	if p.any {
		kinds = append(kinds, "any")
	}
	if p.host {
		kinds = append(kinds, "host")
	}
	for _, k := range []struct {
		prefix string
		names  []string
	}{{"jail:", rn.jails}, {"set:", rn.sets}, {"tag:", rn.tags}} {
		if !strings.HasPrefix(word, k.prefix) || !slices.Contains(kinds, k.prefix) {
			continue
		}
		var out []string
		for _, n := range k.names {
			if self != "" && k.prefix == p.selfKind+":" && n == self {
				continue
			}
			if strings.HasPrefix(k.prefix+n, word) {
				out = append(out, k.prefix+n)
			}
		}
		return out
	}
	var out []string
	if p.flat && !strings.Contains(word, ":") {
		for _, n := range rn.jails {
			if strings.HasPrefix("jail:"+n, word) {
				out = append(out, "jail:"+n)
			}
		}
		if p.host && strings.HasPrefix("host", word) {
			out = append(out, "host")
		}
		for _, ad := range slices.Compact(slices.Sorted(slices.Values(rn.addrs))) {
			if strings.HasPrefix(ad, word) {
				out = append(out, ad)
			}
		}
		return out
	}
	for _, k := range kinds {
		if strings.HasPrefix(k, word) {
			out = append(out, k)
		}
	}
	return out
}

// kindNames are the kinds of a place that need the server's names.
func (p refPlace) kindNames() []string {
	k := []string{"jail", "set"}
	if p.noSet {
		k = []string{"jail"}
	}
	if p.tag {
		k = append(k, "tag")
	}
	return k
}

// noSpaceIfKind keeps the cursor next to a kind that was just completed (jail:), where a name follows.
func noSpaceIfKind(words []string) cobra.ShellCompDirective {
	d := cobra.ShellCompDirectiveNoFileComp
	for _, w := range words {
		if strings.HasSuffix(w, ":") {
			d |= cobra.ShellCompDirectiveNoSpace
			break
		}
	}
	return d
}

// refCompleter completes one reference where a flag value or an argument is that reference.
func (a *app) refCompleter(p refPlace) completer {
	return func(cmd *cobra.Command, args []string, word string) ([]string, cobra.ShellCompDirective) {
		self := ""
		if p.selfName != nil {
			self = p.selfName(args)
		}
		words := refWords(word, p, a.loadRefNames(cmd, p.kindNames()...), self)
		return words, noSpaceIfKind(words)
	}
}
