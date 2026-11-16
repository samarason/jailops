package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The members of an address set are changed one at a time, like the rules of a policy: every command reads the set,
// changes its list and writes it back with the version it read, so a change made by someone else in between is
// refused, not lost.

// checkMember says whether s can be a member of an address set: an address, a CIDR, jail:NAME or set:NAME.
func checkMember(s string) error {
	k, _, err := validate.ParseEndpoint(s)
	if err != nil {
		return err
	}
	if k != validate.EndpointAddr && k != validate.EndpointJail && k != validate.EndpointSet {
		return fmt.Errorf("a member is an address, a CIDR, jail:NAME or set:NAME")
	}
	return nil
}

func (a *app) writeAddressSet(ctx context.Context, c *sdk.Client, set api.AddressSet, etag, action string) error {
	name := set.Metadata.Name
	if ok, err := a.dry("change address set "+name+": "+action, map[string]any{"addresses": set.Spec.Addresses}); ok || err != nil {
		return err
	}
	out, err := c.Firewall().AddressSets().Update(ctx, name, set, etag)
	if err != nil {
		return err
	}
	if a.format != fmtTable {
		return a.emit(out.Spec.Addresses, nil, nil, nil)
	}
	a.say("address set/%s: %s\n", name, action)
	return nil
}

func memberIndex(set api.AddressSet, member string) int {
	return slices.IndexFunc(set.Spec.Addresses, func(e api.AddressEntry) bool { return e.Address == member })
}

func (a *app) addrSetAdd() *cobra.Command {
	var comment string
	cmd := &cobra.Command{
		Use:   "add SET MEMBER...",
		Short: "Add members to an address set",
		Long: `Add one or more members to an address set: an address, a CIDR, jail:NAME or set:NAME. A member that is already in the
set is left as it is and named in the answer. --comment says what the members are and is kept next to each of them: a
reviewer of the firewall reads it beside the address.`,
		Example: "jailops firewall address-set add office 192.0.2.0/24 --comment \"the office network\"\njailops firewall address-set add admins 198.51.100.7 2001:db8::7",
		Args:    cobra.MinimumNArgs(2),
	}
	cmd.Flags().StringVar(&comment, "comment", "", "what the members are (one line, at most 200 characters, no double quotes or backslashes)")
	_ = cmd.RegisterFlagCompletionFunc("comment", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return cobra.AppendActiveHelp(nil, "what these addresses are, in one line"), cobra.ShellCompDirectiveNoFileComp
	})
	member := a.completeMember()
	cmd.ValidArgsFunction = completeArgs(completeKind(a, addrSetDesc()), member)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		for _, m := range args[1:] {
			if err := checkMember(m); err != nil {
				return usagef("%v", err)
			}
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		set, etag, err := c.Firewall().AddressSets().GetETag(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		var added, had []string
		for _, m := range args[1:] {
			if memberIndex(set, m) >= 0 || slices.Contains(added, m) {
				had = append(had, m)
				continue
			}
			set.Spec.Addresses = append(set.Spec.Addresses, api.AddressEntry{Address: m, Comment: comment})
			added = append(added, m)
		}
		if len(added) == 0 {
			a.say("address set/%s: already a member: %s\n", args[0], strings.Join(had, ", "))
			return nil
		}
		action := "added " + strings.Join(added, ", ")
		if len(had) > 0 {
			action += " (already a member: " + strings.Join(had, ", ") + ")"
		}
		return a.writeAddressSet(cmd.Context(), c, set, etag, action)
	}
	return cmd
}

func (a *app) addrSetRemove() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove SET MEMBER...",
		Aliases: []string{"rm"},
		Short:   "Remove members from an address set",
		Long:    "Remove one or more members from an address set. A member that is not in the set is an error and nothing is removed.",
		Example: "jailops firewall address-set remove office 192.0.2.0/24",
		Args:    cobra.MinimumNArgs(2),
	}
	cmd.ValidArgsFunction = completeArgs(completeKind(a, addrSetDesc()), a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		set, err := c.Firewall().AddressSets().Get(ctx, args[0])
		if err != nil {
			return nil, err
		}
		var out []string
		for _, e := range set.Spec.Addresses {
			if e.Comment != "" {
				out = append(out, e.Address+"\t"+e.Comment)
			} else {
				out = append(out, e.Address)
			}
		}
		return out, nil
	}))
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		set, etag, err := c.Firewall().AddressSets().GetETag(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		for _, m := range args[1:] {
			if memberIndex(set, m) < 0 {
				return usagef("%s is not a member of address set %s (jailops firewall address-set show %s)", m, args[0], args[0])
			}
		}
		set.Spec.Addresses = slices.DeleteFunc(set.Spec.Addresses, func(e api.AddressEntry) bool { return slices.Contains(args[1:], e.Address) })
		return a.writeAddressSet(cmd.Context(), c, set, etag, "removed "+strings.Join(args[1:], ", "))
	}
	return cmd
}
