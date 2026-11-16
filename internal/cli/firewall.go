package cli

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func policyDesc() *kindDesc[api.FirewallPolicy] {
	d := newDesc("firewall policy", "firewall policies", api.KindFirewallPolicy,
		func(p *api.FirewallPolicy) *api.ObjectMeta { return &p.Metadata },
		func(p *api.FirewallPolicy) *api.FirewallPolicySpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.FirewallPolicy] { return c.Firewall().Policies() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.FirewallPolicy] { return c.Firewall().Policies() })
	d.renameLong = renameLong("firewall policy", `the jails and the profiles of the project that use it and, for the
project's mandatory policy (renamed by a global administrator), the project`)
	d.show = func(a *app, p api.FirewallPolicy) error { return a.showPolicy(p) }
	d.head = []string{"NAME", "DEFAULT-IN", "DEFAULT-OUT", "RULES", "RAW"}
	d.row = func(_ time.Time, p api.FirewallPolicy) []string {
		raw := "no"
		if p.Spec.Raw != "" {
			raw = "yes"
		}
		return []string{p.Metadata.Name, dash(p.Spec.DefaultIn), dash(p.Spec.DefaultOut), strconv.Itoa(len(p.Spec.Rules)), raw}
	}
	return &d
}

func addrSetDesc() *kindDesc[api.AddressSet] {
	d := newDesc("address set", "address sets", api.KindAddressSet,
		func(p *api.AddressSet) *api.ObjectMeta { return &p.Metadata },
		func(p *api.AddressSet) *api.AddressSetSpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.AddressSet] { return c.Firewall().AddressSets() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.AddressSet] { return c.Firewall().AddressSets() })
	d.renameLong = renameLong("address set", `the rules (set:NAME) of the policies of the project, the sets that
name it as a member (set:NAME) and the app access grants made from it. Its PF table is renamed too, which ends the
connections that rules using it passed once; they are made again`)
	d.show = func(a *app, p api.AddressSet) error { return a.showAddressSet(p) }
	d.head = []string{"NAME", "ADDRESSES"}
	d.row = func(_ time.Time, p api.AddressSet) []string {
		return []string{p.Metadata.Name, strconv.Itoa(len(p.Spec.Addresses))}
	}
	return &d
}

func (a *app) firewallCmd() *cobra.Command {
	fc := group("firewall", "Manage firewall policies and address sets",
		`A firewall policy is a declarative list of rules rendered into one PF anchor per
jail; jailops never owns the host's pf.conf. A rule refers to an address set of the
project as set:NAME, to a jail of the project as jail:NAME (by its addresses) and to the
jails with a tag as tag:NAME. 'jailops firewall validate' checks files offline before
they are applied.`,
		`jailops firewall policy list
jailops firewall address-set create office --comment "the office"
jailops firewall address-set add office 192.0.2.0/24
jailops firewall validate -f policy.yaml`, "fw")
	pd := policyDesc()
	pc := group("policy", "Manage firewall policies", "Create, inspect, edit and delete firewall policies.",
		"jailops firewall policy list\njailops firewall policy show web", "policies")
	crudCommands(a, pc, pd, `Create a firewall policy, empty or from a file. A policy is made of rules, added one at a time with
'jailops firewall rule add' (or all at once from a file with -f). --comment is what the policy is for. Without
--default-in and --default-out the policy denies inbound and allows outbound traffic; both are written into the policy.
A deny rule wins over every allow rule, whatever the order of the policies.`,
		`jailops firewall policy create web --comment "the public web server"
jailops firewall rule add web in --action allow --proto tcp --port 80,443 --comment "the site"
jailops firewall policy create -f web.yaml`,
		func(cmd *cobra.Command) func(string) (api.FirewallPolicy, error) {
			var din, dout, comment string
			cmd.Flags().StringVar(&comment, "comment", "", "what the policy is for (one line, at most 200 characters, no double quotes or backslashes)")
			cmd.Flags().StringVar(&din, "default-in", "deny", "default for inbound traffic: allow or deny")
			cmd.Flags().StringVar(&dout, "default-out", "allow", "default for outbound traffic: allow or deny")
			return func(name string) (api.FirewallPolicy, error) {
				return api.FirewallPolicy{Metadata: api.ObjectMeta{Name: name}, Spec: api.FirewallPolicySpec{DefaultIn: din, DefaultOut: dout, Comment: comment}}, nil
			}
		})
	ad := addrSetDesc()
	ac := group("address-set", "Manage address sets", "Create, inspect, edit and delete address sets, referenced as set:NAME in rules. A member is an address, a CIDR, jail:NAME or set:NAME. Every entry, set, rule and policy has a `comment`: what it is or why it is there. `show` lists them and the rendered rules carry them as comment lines: comments are what a reviewer of the firewall reads.",
		"jailops firewall address-set list\njailops firewall address-set show office", "address-sets", "set")
	crudCommands(a, ac, ad, `Create an address set, empty or from a file. Members are added one at a time with 'jailops firewall
address-set add' (or with --address here, or all at once from a file with -f). A member may be jail:NAME (a jail of the
project) or set:NAME (another set); cycles are rejected. --comment is what the set is for. A set with one address is a
perfectly good alias: say in its comment what it is. A rule that names an empty set matches nothing.`,
		`jailops firewall address-set create office --comment "the office"
jailops firewall address-set add office 192.0.2.0/24 --comment "the office network"
jailops firewall address-set create -f office.yaml`,
		func(cmd *cobra.Command) func(string) (api.AddressSet, error) {
			var addrs []string
			var comment string
			cmd.Flags().StringArrayVar(&addrs, "address", nil, "a first member: address, CIDR, jail:NAME or set:NAME (repeatable; more come with 'address-set add')")
			_ = cmd.RegisterFlagCompletionFunc("address", a.completeMember())
			cmd.Flags().StringVar(&comment, "comment", "", "what the set is for (one line, at most 200 characters, no double quotes or backslashes)")
			return func(name string) (api.AddressSet, error) {
				for _, m := range addrs {
					if err := checkMember(m); err != nil {
						return api.AddressSet{}, usagef("--address %q: %v", m, err)
					}
				}
				return api.AddressSet{Metadata: api.ObjectMeta{Name: name}, Spec: api.AddressSetSpec{Comment: comment, Addresses: api.Entries(addrs...)}}, nil
			}
		})
	ac.AddCommand(a.addrSetAdd(), a.addrSetRemove())
	fc.AddCommand(pc, a.ruleCmd(), ac, a.firewallValidate(), a.firewallTest())
	return fc
}

// validation ---------------------------------------------------------------

type finding struct {
	Doc     string `json:"document"`
	Level   string `json:"level"` // error or warning
	Message string `json:"message"`
}

func validPort(p string) bool {
	lo, hi, isRange := strings.Cut(p, "-")
	l, err := strconv.Atoi(lo)
	if err != nil || l < 1 || l > 65535 {
		return false
	}
	if !isRange {
		return true
	}
	h, err := strconv.Atoi(hi)
	return err == nil && h >= l && h <= 65535
}

func validatePolicy(doc string, p api.FirewallPolicySpec, sets func(string) bool) []finding {
	var out []finding
	bad := func(f string, a ...any) { out = append(out, finding{doc, "error", fmt.Sprintf(f, a...)}) }
	for _, d := range [][2]string{{"default_in", p.DefaultIn}, {"default_out", p.DefaultOut}} {
		switch d[1] {
		case "allow", "deny":
		case "":
			bad("%s is required: allow or deny", d[0])
		default:
			bad("%s must be allow or deny, not %q", d[0], d[1])
		}
	}
	for i, r := range p.Rules {
		at := fmt.Sprintf("rules[%d]", i)
		if r.Name != "" {
			at += " (" + r.Name + ")"
		}
		if r.Action != "allow" && r.Action != "deny" {
			bad("%s: action must be allow or deny, not %q", at, r.Action)
		}
		if r.Direction != "in" && r.Direction != "out" {
			bad("%s: direction must be in or out, not %q", at, r.Direction)
		}
		if r.Proto != "" && !slices.Contains([]string{"tcp", "udp", "icmp", "icmp6"}, r.Proto) {
			bad("%s: unknown protocol %q", at, r.Proto)
		}
		if len(r.Ports) > 0 && r.Proto != "tcp" && r.Proto != "udp" {
			bad("%s: ports need proto tcp or udp", at)
		}
		for _, port := range r.Ports {
			if !validPort(port) {
				bad("%s: invalid port %q", at, port)
			}
		}
		for _, addr := range slices.Concat(r.From, r.To) {
			k, n, err := validate.ParseEndpoint(addr)
			switch {
			case err != nil:
				bad("%s: %v", at, err)
			case k == validate.EndpointSet && !sets(n):
				bad("%s: unknown address set %q", at, n)
			}
		}
		if r.Redirect != nil {
			if r.Direction != "in" {
				bad("%s: a redirect is allowed on inbound rules only", at)
			}
			if r.Redirect.HostPort < 1 || r.Redirect.HostPort > 65535 || r.Redirect.JailPort < 1 || r.Redirect.JailPort > 65535 {
				bad("%s: redirect ports must be 1-65535", at)
			}
		}
	}
	if p.Raw != "" {
		out = append(out, finding{doc, "warning", "raw PF needs the admin role; the server checks it with pfctl -n when applied"})
	}
	return out
}

func validateAddrSets(sets map[string]api.AddressSetSpec, docs map[string]bool) []finding {
	var out []finding
	for _, name := range sortedKeys(sets) {
		doc := "address-set/" + name
		if !docs[name] {
			continue
		}
		s := sets[name]
		for _, e := range s.Addresses {
			if k, _, err := validate.ParseEndpoint(e.Address); err != nil {
				out = append(out, finding{doc, "error", fmt.Sprintf("member %q: %v", e.Address, err)})
			} else if k != validate.EndpointAddr && k != validate.EndpointJail && k != validate.EndpointSet {
				out = append(out, finding{doc, "error", fmt.Sprintf("member %q must be an address, a CIDR, jail:NAME or set:NAME", e.Address)})
			}
		}
		// cycle search from this set
		var walk func(n string, path []string) []string
		walk = func(n string, path []string) []string {
			if slices.Contains(path, n) {
				return append(path, n)
			}
			for _, e := range sets[n].Addresses {
				if inc, ok := strings.CutPrefix(e.Address, "set:"); ok {
					if _, isSet := sets[inc]; isSet {
						if p := walk(inc, append(slices.Clone(path), n)); p != nil {
							return p
						}
					}
				}
			}
			return nil
		}
		if p := walk(name, nil); p != nil && p[len(p)-1] == name {
			out = append(out, finding{doc, "error", "address set cycle: " + strings.Join(p, " -> ")})
		}
	}
	return out
}

func (a *app) firewallValidate() *cobra.Command {
	var file string
	var offline, review bool
	cmd := &cobra.Command{
		Use:   "validate -f FILE",
		Short: "Check firewall policies and address sets without applying them",
		Long: `Check the FirewallPolicy and AddressSet documents of a file: actions, directions,
protocols, ports, address syntax, redirects, references (jail:NAME, set:NAME, tag:NAME)
and set cycles. Address sets defined in the same file count, and the ones on
the server are looked up unless --offline is given.

The exit status is 2 when an error was found. Raw PF fragments are not parsed
here; the server checks them with pfctl -n when they are applied.

--review adds the warnings a reviewer of the firewall would raise: a policy, a rule, an
address set or one of its members without a comment, a rule that is disabled or very
broad (allow from or to any address with no port), an address set no rule refers to,
a policy no jail or project uses, and a jail:NAME that does not exist. Warnings never
change the exit status. Without a server it says what it could not check.`,
		Example: "jailops firewall validate -f policy.yaml\njailops firewall validate -f policy.yaml --review\ncat policy.yaml | jailops firewall validate -f - --offline",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if file == "" {
				return usagef("-f FILE is required")
			}
			b, err := a.readInput(file)
			if err != nil {
				return err
			}
			docs, err := readDocs(b)
			if err != nil {
				return err
			}
			type pol struct {
				name string
				spec api.FirewallPolicySpec
			}
			var pols []pol
			sets := map[string]api.AddressSetSpec{}
			inFile := map[string]bool{}
			for _, doc := range docs {
				switch k, _ := doc["kind"].(string); api.Kind(k) {
				case api.KindFirewallPolicy:
					m, s, err := parseObject[api.FirewallPolicySpec](doc, api.KindFirewallPolicy, "")
					if err != nil {
						return err
					}
					pols = append(pols, pol{m.Name, s})
				case api.KindAddressSet:
					m, s, err := parseObject[api.AddressSetSpec](doc, api.KindAddressSet, "")
					if err != nil {
						return err
					}
					sets[m.Name], inFile[m.Name] = s, true
				default:
					return usagef("validate handles FirewallPolicy and AddressSet documents, not %q", k)
				}
			}
			rv := reviewInput{pols: map[string]api.FirewallPolicySpec{}, sets: map[string]api.AddressSetSpec{}, allPols: map[string]api.FirewallPolicySpec{}}
			for _, p := range pols {
				rv.pols[p.name], rv.allPols[p.name] = p.spec, p.spec
			}
			for n := range inFile {
				rv.sets[n] = sets[n]
			}
			if !offline {
				if c, err := a.connect(cmd.Context()); err == nil {
					if review {
						loadReview(cmd.Context(), c, &rv)
					}
					if remote, err := collect(c.Firewall().AddressSets().List(cmd.Context())); err == nil {
						for _, r := range remote {
							if _, dup := sets[r.Metadata.Name]; !dup {
								sets[r.Metadata.Name] = r.Spec
							}
						}
					}
				}
			}
			known := func(n string) bool { _, ok := sets[n]; return ok }
			if offline {
				known = func(string) bool { return true }
			}
			var all []finding
			for _, p := range pols {
				all = append(all, validatePolicy("policy/"+p.name, p.spec, known)...)
			}
			all = append(all, validateAddrSets(sets, inFile)...)
			if review {
				rv.allSets = sets
				all = append(all, reviewFindings(rv)...)
			}
			errs := 0
			for _, f := range all {
				if f.Level == "error" {
					errs++
				}
			}
			if a.format != fmtTable {
				if err := a.emit(nonNil(all), nil, nil, nil); err != nil {
					return err
				}
			} else if len(all) == 0 {
				fprintf(a.env.Stdout, "valid: %d documents checked\n", len(docs))
			} else {
				a.printTable(a.env.Stdout, []string{"DOCUMENT", "LEVEL", "PROBLEM"}, func() [][]string {
					var rows [][]string
					for _, f := range all {
						rows = append(rows, []string{f.Doc, f.Level, f.Message})
					}
					return rows
				}(), nil)
			}
			if errs > 0 {
				return api.Errorf(api.CodeInvalid, "%d problem(s) found in %s", errs, file).WithHint("fix the listed rules and run validate again")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "file with FirewallPolicy and AddressSet documents, or - for standard input")
	cmd.Flags().BoolVar(&offline, "offline", false, "do not look up address sets on the server")
	cmd.Flags().BoolVar(&review, "review", false, "add the warnings a reviewer would raise: missing comments, disabled or very broad rules, unused sets and policies, jails that do not exist")
	return cmd
}
