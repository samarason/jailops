package cli

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// The rules of a policy are changed one at a time, by number or by name: the number is the one `policy show` and
// `rule list` print and the rendered anchor carries. Every command reads the policy, changes its list of rules and
// writes it back with the version it read, so a change made by someone else in between is refused, not lost.

// commonPorts are the ports Tab offers after --port, with what they are.
var commonPorts = []string{
	"22\tssh", "25\tsmtp", "53\tdns", "80\thttp", "123\tntp", "143\timap", "443\thttps", "465\tsmtps", "587\tsubmission",
	"993\timaps", "3306\tmysql", "5432\tpostgresql", "6379\tredis", "8080\thttp alternate", "9100\tnode exporter",
}

func (a *app) ruleCmd() *cobra.Command {
	rc := group("rule", "Manage the rules of a firewall policy",
		`Add, list, change, move, switch on and off and remove the rules of a policy, one at a time. A rule is
addressed by its number (the # column of 'jailops firewall rule list' and of 'policy show') or by its name. A rule that
sits earlier in the list has a lower number; a deny rule wins over every allow rule whatever the order. The rules
of a policy that app access manages, and of a mandatory policy of the project (unless you are a global administrator),
are not changed here.`,
		`jailops firewall rule list web
jailops firewall rule add web in --action allow --proto tcp --port 22 --from set:office --comment "ssh from the office"
jailops firewall rule disable web 2
jailops firewall rule move web 3 --to 1
jailops firewall rule remove web 4`)
	rc.AddCommand(a.ruleAdd(), a.ruleList(), a.ruleEdit(), a.ruleRemove(), a.ruleMove(), a.ruleSwitch(true), a.ruleSwitch(false))
	return rc
}

// ruleOpts are the flags that describe a rule, the same on add and on edit.
type ruleOpts struct {
	action, direction, proto, name, comment, redirect string
	from, to, ports                                   []string
	log, disabled                                     bool
}

func (a *app) ruleFlags(cmd *cobra.Command, forAdd bool) *ruleOpts {
	o := &ruleOpts{}
	f := cmd.Flags()
	f.StringVar(&o.action, "action", "", "allow or deny")
	if !forAdd {
		f.StringVar(&o.direction, "direction", "", "change the direction: in (to the jail) or out (from the jail)")
		enumFlag(cmd, "direction", "in\tto the jail", "out\tfrom the jail")
	}
	f.StringVar(&o.proto, "proto", "", "tcp, udp, icmp or icmp6 (empty: any protocol)")
	f.StringSliceVar(&o.from, "from", nil, "who it comes from: jail:NAME, set:NAME, tag:NAME, an address, a CIDR or any (repeatable, or comma separated; outbound rules cannot name one: the jail is the source)")
	f.StringSliceVar(&o.to, "to", nil, "where it goes: the same references (inbound rules cannot name one: the jail is the destination; host is the host itself)")
	f.StringSliceVar(&o.ports, "port", nil, "destination port: 80, a range 8000-8100, or a list 80,443 (tcp and udp)")
	f.StringVar(&o.name, "name", "", "a short name to address the rule by instead of its number")
	f.StringVar(&o.comment, "comment", "", "why the rule is there (one line, at most 200 characters, no double quotes or backslashes): what a reviewer of the firewall reads")
	f.BoolVar(&o.log, "log", false, "log the packets the rule decides")
	f.StringVar(&o.redirect, "redirect", "", "forward a port of the host to the jail: HOSTPORT:JAILPORT (inbound rules only; the redirect names the ports, so leave --port out)")
	if forAdd {
		f.BoolVar(&o.disabled, "disabled", false, "add the rule switched off: it keeps its number and loads nothing")
	}
	enumFlag(cmd, "action", "allow\tlet it through", "deny\tblock it (wins over every allow)")
	enumFlag(cmd, "proto", "tcp", "udp", "icmp", "icmp6")
	for _, n := range []string{"from", "to"} {
		_ = cmd.RegisterFlagCompletionFunc(n, a.refListCompleter(placeRule))
	}
	_ = cmd.RegisterFlagCompletionFunc("port", portCompleter)
	_ = cmd.RegisterFlagCompletionFunc("name", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return cobra.AppendActiveHelp(nil, "a short name such as ssh or web, to address the rule by"), cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("comment", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return cobra.AppendActiveHelp(nil, "why the rule is there, in one line"), cobra.ShellCompDirectiveNoFileComp
	})
	_ = cmd.RegisterFlagCompletionFunc("redirect", completeNone)
	return o
}

// apply sets the fields of the rule that were given on the command line.
func (o *ruleOpts) apply(cmd *cobra.Command, r *api.FirewallRule) error {
	ch := cmd.Flags().Changed
	if ch("action") {
		r.Action = o.action
	}
	if ch("direction") {
		r.Direction = o.direction
	}
	if ch("proto") {
		r.Proto = o.proto
	}
	if ch("from") {
		r.From = splitNonEmpty(o.from)
	}
	if ch("to") {
		r.To = splitNonEmpty(o.to)
	}
	if ch("port") {
		r.Ports = splitNonEmpty(o.ports)
	}
	if ch("name") {
		r.Name = o.name
	}
	if ch("comment") {
		r.Comment = o.comment
	}
	if ch("log") {
		r.Log = o.log
	}
	if ch("disabled") {
		r.Disabled = o.disabled
	}
	if ch("redirect") {
		if o.redirect == "" {
			r.Redirect = nil
		} else {
			h, j, ok := strings.Cut(o.redirect, ":")
			hp, e1 := strconv.Atoi(h)
			jp, e2 := strconv.Atoi(j)
			if !ok || e1 != nil || e2 != nil {
				return usagef("--redirect %q must be HOSTPORT:JAILPORT, for example 8080:80", o.redirect)
			}
			r.Redirect = &api.Redirect{HostPort: hp, JailPort: jp}
		}
	}
	for _, e := range append(slices.Clone(r.From), r.To...) {
		if err := validate.ValidateEndpoint(e); err != nil {
			return usagef("%v", err)
		}
	}
	return nil
}

// splitNonEmpty drops the empty entries of a list: --from "" clears it.
func splitNonEmpty(in []string) []string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ruleText is what a rule says, in words, without its name and comment.
func ruleSummary(r api.FirewallRule) string { return ruleText(r) }

// loadPolicy reads the policy a rule command changes; a policy that something else manages is refused here, which the
// server refuses too.
func (a *app) loadPolicy(ctx context.Context, c *sdk.Client, name string) (api.FirewallPolicy, string, error) {
	p, etag, err := c.Firewall().Policies().GetETag(ctx, name)
	if err != nil {
		return p, "", err
	}
	return p, etag, nil
}

func refuseManaged(p api.FirewallPolicy) error {
	if p.Metadata.ManagedBy != "" {
		return usagef("firewall policy %q is managed by %s: its rules are not changed here", p.Metadata.Name, p.Metadata.ManagedBy)
	}
	return nil
}

// ruleIndex resolves a rule given by number (1-based, as printed) or by name.
func ruleIndex(p api.FirewallPolicy, ref string) (int, error) {
	n := len(p.Spec.Rules)
	if k, err := strconv.Atoi(ref); err == nil {
		if k < 1 || k > n {
			return 0, usagef("policy %s has %s; there is no rule %d", p.Metadata.Name, plural(n, "rule"), k)
		}
		return k - 1, nil
	}
	at := -1
	for i, r := range p.Spec.Rules {
		if r.Name == ref {
			if at >= 0 {
				return 0, usagef("policy %s has two rules named %q: use the number", p.Metadata.Name, ref)
			}
			at = i
		}
	}
	if at < 0 {
		return 0, usagef("policy %s has no rule named %q (list them with 'jailops firewall rule list %s')", p.Metadata.Name, ref, p.Metadata.Name)
	}
	return at, nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// checkRules refuses a list of rules the policy would not take, before anything is sent: a name used twice, and
// whatever the policy validation says (an inbound rule that names a destination, a port without a protocol, ...).
func checkRules(p api.FirewallPolicy) error {
	seen := map[string]int{}
	for i, r := range p.Spec.Rules {
		if r.Name == "" {
			continue
		}
		if j, dup := seen[r.Name]; dup {
			return usagef("the name %q is used by rule %d and rule %d: a name addresses one rule", r.Name, j, i+1)
		}
		seen[r.Name] = i + 1
	}
	if _, err := validate.FirewallPolicySpec(p.Spec); err != nil {
		return err
	}
	return nil
}

// writePolicy sends the changed policy and says in one line what happened.
func (a *app) writePolicy(ctx context.Context, c *sdk.Client, p api.FirewallPolicy, etag, action string) error {
	name := p.Metadata.Name
	if err := checkRules(p); err != nil {
		return err
	}
	if ok, err := a.dry("change firewall policy "+name+": "+action, map[string]any{"rules": p.Spec.Rules}); ok || err != nil {
		return err
	}
	out, err := c.Firewall().Policies().Update(ctx, name, p, etag)
	if err != nil {
		return err
	}
	if a.format != fmtTable {
		return a.emit(out.Spec.Rules, nil, nil, nil)
	}
	a.say("firewall policy/%s: %s\n", name, action)
	return nil
}

func rulePositionCompleter(a *app) completer {
	return a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		p, err := c.Firewall().Policies().Get(ctx, args[0])
		if err != nil {
			return nil, err
		}
		var out []string
		for i, r := range p.Spec.Rules {
			desc := ruleSummary(r)
			if r.Comment != "" {
				desc += ": " + r.Comment
			}
			out = append(out, fmt.Sprintf("%d\t%s", i+1, desc))
			if r.Name != "" {
				out = append(out, r.Name+"\t"+desc)
			}
		}
		return out, nil
	})
}

func (a *app) ruleAdd() *cobra.Command {
	var at int
	cmd := &cobra.Command{
		Use:   "add POLICY in|out [flags]",
		Short: "Add a rule to a firewall policy",
		Long: `Add a rule at the end of the policy, or at a position with --at. The direction is the second word: in is
traffic to the jail, out is traffic from it. The rule allows unless --action deny says otherwise; everything else
narrows the rule: without --proto it matches every protocol (with --port it is tcp), without --from or --to every
address, without --port every port. Say why the rule is there
with --comment: it shows in 'policy show' and as a comment line in the rendered anchor. An inbound rule names the
source with --from; an outbound rule names the destination with --to. A rule with --redirect HOSTPORT:JAILPORT
forwards a port of the host to the jail.`,
		Example: `jailops firewall rule add web in --action allow --proto tcp --port 80,443 --comment "the site"
jailops firewall rule add web in --action allow --proto tcp --from set:office --port 22 --comment "ssh from the office"
jailops firewall rule add db out --action allow --proto tcp --to jail:cache --port 6379 --name cache --comment "the cache"
jailops firewall rule add web in --action allow --proto tcp --redirect 8080:80 --comment "the test site"`,
		Args: cobra.ExactArgs(2),
	}
	o := a.ruleFlags(cmd, true)
	cmd.Flags().IntVar(&at, "at", 0, "insert as rule N (the rule that was there moves down); default: at the end")
	_ = cmd.RegisterFlagCompletionFunc("at", completeNone)
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"in\ttraffic to the jail", "out\ttraffic from the jail"}, cobra.ShellCompDirectiveNoFileComp
	}, completeNone)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if args[1] != "in" && args[1] != "out" {
			return usagef("the direction is in (to the jail) or out (from the jail), not %q", args[1])
		}
		o.direction = args[1]
		var r api.FirewallRule
		r.Direction = args[1]
		r.Action = "allow" // the default; --action deny says otherwise
		if err := o.apply(cmd, &r); err != nil {
			return err
		}
		if r.Proto == "" && cmd.Flags().Changed("port") {
			r.Proto = "tcp" // a port needs a protocol, and tcp is the one everything else defaults to
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, etag, err := a.loadPolicy(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := refuseManaged(p); err != nil {
			return err
		}
		pos := len(p.Spec.Rules)
		if cmd.Flags().Changed("at") {
			if at < 1 || at > len(p.Spec.Rules)+1 {
				return usagef("--at %d: the policy has %s, so the new rule goes at 1 to %d", at, plural(len(p.Spec.Rules), "rule"), len(p.Spec.Rules)+1)
			}
			pos = at - 1
		}
		p.Spec.Rules = slices.Insert(p.Spec.Rules, pos, r)
		if err := a.writePolicy(cmd.Context(), c, p, etag, fmt.Sprintf("rule %d added: %s", pos+1, ruleSummary(r))); err != nil {
			return err
		}
		if r.Comment == "" && !a.quiet && !a.dryRun {
			fprintf(a.env.Stderr, "note: the rule has no comment; say why it is there with: jailops firewall rule edit %s %d --comment TEXT\n", args[0], pos+1)
		}
		return nil
	}
	return cmd
}

func (a *app) ruleList() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list POLICY",
		Aliases: []string{"ls"},
		Short:   "List the rules of a firewall policy, numbered",
		Long: `List the rules of a policy in the order they are rendered, with the number that addresses each one.
-o json and -o yaml give the rules as data.`,
		Example: "jailops firewall rule list web\njailops firewall rule list web -o json",
		Args:    cobra.ExactArgs(1),
	}
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), completeNone)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, err := c.Firewall().Policies().Get(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		head := []string{"#", "NAME", "ACTION", "DIRECTION", "PROTO", "FROM", "TO", "PORT", "ON", "COMMENT"}
		rows := make([][]string, 0, len(p.Spec.Rules))
		for i, r := range p.Spec.Rules {
			on := "yes"
			if r.Disabled {
				on = "no"
			}
			port := strings.Join(r.Ports, ",")
			if r.Redirect != nil {
				port = strings.TrimSpace(port + " rdr " + fmt.Sprintf("%d:%d", r.Redirect.HostPort, r.Redirect.JailPort))
			}
			rows = append(rows, []string{strconv.Itoa(i + 1), dash(r.Name), r.Action, r.Direction, dash(r.Proto),
				dash(strings.Join(r.From, ",")), dash(strings.Join(r.To, ",")), dash(port), on, dash(r.Comment)})
		}
		return a.emit(p.Spec.Rules, nil, func() ([]string, [][]string) { return head, rows }, func() []string {
			names := make([]string, 0, len(rows))
			for _, r := range rows {
				names = append(names, r[0])
			}
			return names
		})
	}
	return cmd
}

func (a *app) ruleEdit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit POLICY RULE [flags]",
		Short: "Change fields of one rule of a firewall policy",
		Long: `Change the fields of a rule that you give; the others stay. RULE is a number or a name. To clear a field give it an
empty value (--from "", --port "", --redirect ""). To switch a rule off or on use 'rule disable' and 'rule enable'.`,
		Example: "jailops firewall rule edit web 2 --port 22,2222\njailops firewall rule edit web ssh --from set:office --comment \"ssh from the office only\"",
		Args:    cobra.ExactArgs(2),
	}
	o := a.ruleFlags(cmd, false)
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), rulePositionCompleter(a))
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().NFlag() == 0 {
			return usagef("nothing to change: give at least one of --action, --direction, --proto, --from, --to, --port, --name, --comment, --log, --redirect")
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, etag, err := a.loadPolicy(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := refuseManaged(p); err != nil {
			return err
		}
		i, err := ruleIndex(p, args[1])
		if err != nil {
			return err
		}
		if err := o.apply(cmd, &p.Spec.Rules[i]); err != nil {
			return err
		}
		return a.writePolicy(cmd.Context(), c, p, etag, fmt.Sprintf("rule %d changed: %s", i+1, ruleSummary(p.Spec.Rules[i])))
	}
	return cmd
}

func (a *app) ruleRemove() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:     "remove POLICY [RULE]",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a rule from a firewall policy",
		Long: `Remove one rule, given by number or name (or with --name). The rules after it move up by one, so list them
again before the next change by number. To keep a rule but stop it from doing anything use 'rule disable'.`,
		Example: "jailops firewall rule remove web 3\njailops firewall rule remove web --name ssh",
		Args:    cobra.RangeArgs(1, 2),
	}
	cmd.Flags().StringVar(&name, "name", "", "the name of the rule, instead of its number")
	_ = cmd.RegisterFlagCompletionFunc("name", completeNone)
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), rulePositionCompleter(a))
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ref := name
		switch {
		case len(args) == 2 && name != "":
			return usagef("give the rule as a number or a name, or with --name, not both")
		case len(args) == 2:
			ref = args[1]
		case name == "":
			return usagef("say which rule: a number or a name (jailops firewall rule list %s)", args[0])
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, etag, err := a.loadPolicy(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := refuseManaged(p); err != nil {
			return err
		}
		i, err := ruleIndex(p, ref)
		if err != nil {
			return err
		}
		gone := p.Spec.Rules[i]
		p.Spec.Rules = slices.Delete(p.Spec.Rules, i, i+1)
		return a.writePolicy(cmd.Context(), c, p, etag, fmt.Sprintf("rule %d removed: %s", i+1, ruleSummary(gone)))
	}
	return cmd
}

func (a *app) ruleMove() *cobra.Command {
	var to int
	var before, after string
	cmd := &cobra.Command{
		Use:   "move POLICY RULE (--to N | --before RULE | --after RULE)",
		Short: "Move a rule to another position in a firewall policy",
		Long: `Move a rule to position N, or in front of or behind another rule. The numbers of the rules in between change by
one. The order matters only among allow rules and for the reader: a deny rule wins over every allow rule.`,
		Example: "jailops firewall rule move web 3 --to 1\njailops firewall rule move web ssh --before 2\njailops firewall rule move web 4 --after ssh",
		Args:    cobra.ExactArgs(2),
	}
	cmd.Flags().IntVar(&to, "to", 0, "the new number of the rule")
	cmd.Flags().StringVar(&before, "before", "", "put the rule in front of this one (number or name)")
	cmd.Flags().StringVar(&after, "after", "", "put the rule behind this one (number or name)")
	_ = cmd.RegisterFlagCompletionFunc("to", a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		p, err := c.Firewall().Policies().Get(ctx, args[0])
		if err != nil {
			return nil, err
		}
		var out []string
		for i := range p.Spec.Rules {
			out = append(out, strconv.Itoa(i+1))
		}
		return out, nil
	}))
	for _, n := range []string{"before", "after"} {
		_ = cmd.RegisterFlagCompletionFunc(n, rulePositionCompleter(a))
	}
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), rulePositionCompleter(a))
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ch := cmd.Flags().Changed
		n := 0
		for _, f := range []string{"to", "before", "after"} {
			if ch(f) {
				n++
			}
		}
		if n != 1 {
			return usagef("say where: exactly one of --to N, --before RULE or --after RULE")
		}
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, etag, err := a.loadPolicy(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := refuseManaged(p); err != nil {
			return err
		}
		from, err := ruleIndex(p, args[1])
		if err != nil {
			return err
		}
		r := p.Spec.Rules[from]
		rest := slices.Delete(slices.Clone(p.Spec.Rules), from, from+1)
		dest := 0
		switch {
		case ch("to"):
			if to < 1 || to > len(p.Spec.Rules) {
				return usagef("--to %d: the policy has %s", to, plural(len(p.Spec.Rules), "rule"))
			}
			dest = to - 1
		default:
			ref := before
			if ch("after") {
				ref = after
			}
			k, err := ruleIndex(p, ref)
			if err != nil {
				return err
			}
			if k == from {
				return usagef("a rule cannot be moved next to itself")
			}
			if k > from {
				k-- // the rule left the list in front of it
			}
			dest = k
			if ch("after") {
				dest++
			}
		}
		if dest == from {
			a.say("firewall policy/%s: rule %d stays where it is\n", p.Metadata.Name, from+1)
			return nil
		}
		p.Spec.Rules = slices.Insert(rest, dest, r)
		return a.writePolicy(cmd.Context(), c, p, etag, fmt.Sprintf("rule %d moved to %d: %s", from+1, dest+1, ruleSummary(r)))
	}
	return cmd
}

// ruleSwitch builds enable (on) and disable (!on).
func (a *app) ruleSwitch(on bool) *cobra.Command {
	use, short, verb := "disable POLICY RULE...", "Switch rules of a firewall policy off without removing them", "disabled"
	long := `Switch a rule off: it keeps its number and its place, shows in 'policy show' and as a comment line of the
anchor, and loads nothing, so it lets nothing through and stops nothing. RULE is a number or a name; give several to
switch several.`
	if on {
		use, short, verb = "enable POLICY RULE...", "Switch rules of a firewall policy on", "enabled"
		long = "Switch a disabled rule on again. RULE is a number or a name; give several to switch several."
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Args: cobra.MinimumNArgs(2),
		Example: fmt.Sprintf("jailops firewall rule %s web 2\njailops firewall rule %s web ssh 4", strings.Fields(use)[0], strings.Fields(use)[0]),
	}
	cmd.ValidArgsFunction = completeArgs(completeKind(a, policyDesc()), rulePositionCompleter(a))
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := a.connect(cmd.Context())
		if err != nil {
			return err
		}
		p, etag, err := a.loadPolicy(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := refuseManaged(p); err != nil {
			return err
		}
		var nums []string
		for _, ref := range args[1:] {
			i, err := ruleIndex(p, ref)
			if err != nil {
				return err
			}
			p.Spec.Rules[i].Disabled = !on
			if n := strconv.Itoa(i + 1); !slices.Contains(nums, n) {
				nums = append(nums, n)
			}
		}
		noun := "rule " + nums[0]
		if len(nums) > 1 {
			noun = "rules " + strings.Join(nums, ", ")
		}
		return a.writePolicy(cmd.Context(), c, p, etag, noun+" "+verb)
	}
	return cmd
}

// refListCompleter completes a comma separated list of references: what is before the last comma stays as typed.
func (a *app) refListCompleter(p refPlace) completer {
	return func(cmd *cobra.Command, args []string, typed string) ([]string, cobra.ShellCompDirective) {
		done, cur := "", typed
		if i := strings.LastIndex(typed, ","); i >= 0 {
			done, cur = typed[:i+1], typed[i+1:]
		}
		self := ""
		if p.selfName != nil {
			self = p.selfName(args)
		}
		words := refWords(cur, p, a.loadRefNames(cmd, p.kindNames()...), self)
		out := make([]string, 0, len(words))
		for _, w := range words {
			out = append(out, done+w)
		}
		return out, noSpaceIfKind(words)
	}
}

// portCompleter offers common ports after --port, also after a comma.
func portCompleter(_ *cobra.Command, _ []string, typed string) ([]string, cobra.ShellCompDirective) {
	done, cur := "", typed
	if i := strings.LastIndex(typed, ","); i >= 0 {
		done, cur = typed[:i+1], typed[i+1:]
	}
	var out []string
	for _, p := range commonPorts {
		if strings.HasPrefix(p, cur) {
			out = append(out, done+p)
		}
	}
	if len(out) == 0 && cur != "" && strings.Trim(cur, "0123456789-") == "" {
		out = []string{typed}
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}
