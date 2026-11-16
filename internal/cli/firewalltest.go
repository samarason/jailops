package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

// The exit status of 'firewall test': 0 when the connection would pass, 1 when it would be blocked, and
// ExitUndecided when the test cannot say (a raw PF fragment, an ICMP type, a packet no rule of the anchor matches).
const ExitUndecided = 8

func (a *app) firewallTest() *cobra.Command {
	var from, to, proto, icmpType, family string
	var verbose bool
	var port int
	cmd := &cobra.Command{
		Use:   "test --from SOURCE --to DESTINATION [--port N]",
		Short: "Say whether a connection would pass the firewall, and which rule decides",
		Long: `Say whether a new connection from one end to the other would pass the firewall, and
which rule decides at each anchor it meets. SOURCE and DESTINATION are a jail of the
project (jail:web), one address, or host (the host's address on the gateway of the other end's
network). A set is not an end: name a jail or an address. An address that belongs to a
jail of the project is that jail. Another project is an external host: its jails are
addresses here.

The test walks the anchors JailOps renders and loads: what the source jail sends is judged
on its own port, what reaches the destination jail leaves the host on the gateway interface
of its network. Each hop prints the rule that decided: the policy, the number of the rule,
its name and comment, and the rendered pf line. For a connection between two jails both
hops must pass.

It does not cover what it cannot know, and says so: a connection that is already open (pf
keeps its state), the host's own pf.conf, NAT, and a raw PF fragment, which makes the answer
unknown. The ICMP tests default to an echo request (ping); --icmp-type names another.

Exit status: 0 the connection would pass, 1 it would be blocked, 8 the test cannot say.`,
		Example: `jailops firewall test --from jail:web --to jail:db --port 5432
jailops firewall test --from jail:web --to jail:db --port 5433
jailops firewall test --from 192.0.2.7 --to jail:web --port 443
jailops firewall test --from host --to @db --proto icmp
jailops firewall test --from jail:web --to 198.51.100.9 --proto udp --port 53 -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if from == "" || to == "" {
				return usagef("--from and --to are required")
			}
			if (proto == "tcp" || proto == "udp") && port == 0 {
				return usagef("--port is required: the protocol is %s unless --proto says otherwise (for example --port 5432, or --proto icmp to test ping)", proto)
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			res, err := c.Firewall().Test(cmd.Context(), api.FirewallTestRequest{From: from, To: to, Proto: proto, Port: port, ICMPType: icmpType, Family: family})
			if err != nil {
				return err
			}
			if a.format != fmtTable {
				if err := a.emit(res, nil, nil, nil); err != nil {
					return err
				}
			} else {
				printFirewallTest(a, res, verbose)
			}
			switch res.Verdict {
			case api.TestPass:
				return nil
			case api.TestBlock:
				return &exitError{code: ExitFailure}
			}
			return &exitError{code: ExitUndecided}
		},
	}
	f := cmd.Flags()
	f.StringVar(&from, "from", "", "where the connection starts: jail:NAME, an address or host")
	f.StringVar(&to, "to", "", "where it goes: jail:NAME, an address or host")
	f.StringVar(&proto, "proto", "tcp", "tcp, udp, icmp or icmp6")
	f.IntVar(&port, "port", 0, "destination port of tcp and udp")
	f.StringVar(&icmpType, "icmp-type", "", "ICMP type as pf names it, such as echoreq (default for icmp and icmp6)")
	f.BoolVarP(&verbose, "verbose", "v", false, "show the rendered pf rules, the rules that were skipped and what the test does not cover")
	f.StringVar(&family, "family", "", "test only IPv4 (4) or IPv6 (6); default: every family the two ends have in common")
	enumFlag(cmd, "proto", "tcp", "udp", "icmp", "icmp6")
	enumFlag(cmd, "family", "4", "6")
	ends := a.refCompleter(placeEnd)
	for _, name := range []string{"from", "to"} {
		_ = cmd.RegisterFlagCompletionFunc(name, func(c *cobra.Command, args []string, t string) ([]string, cobra.ShellCompDirective) {
			return ends(c, args, t)
		})
	}
	return cmd
}

// stageText names what a rule of a stage is, for the line of a hop.
var stageText = map[string]string{
	"ipv6-control":  "the IPv6 control rules",
	"antispoof":     "the anti-spoofing rule",
	"neighbour":     "the neighbour discovery rules",
	"own-addresses": "the rule that only the jail's own addresses reach it",
	"isolation":     "the isolation of projects",
	"default":       "the default of the anchor",
	"closed":        "the closed link of a jail without an address",
	"gateway":       "the rules of the gateway interface",
	"raw":           "a raw PF fragment",
}

// printFirewallTest says whether the connection passes and which rule decides at each end, in a few lines; verbose
// adds the rendered pf rules, the rules that were skipped and what the test does not cover.
func printFirewallTest(a *app, res api.FirewallTestResult, verbose bool) {
	if verbose {
		printFirewallTestVerbose(a, res)
		return
	}
	w := a.env.Stdout
	for i, c := range res.Cases {
		if i > 0 {
			fprintf(w, "\n")
		}
		what := c.Proto
		if c.Port > 0 {
			what += " port " + fmt.Sprint(c.Port)
		}
		if c.ICMPType != "" {
			what += " " + c.ICMPType
		}
		fprintf(w, "%s %s -> %s (%s): %s\n", what, c.From, c.To, c.Family, strings.ToUpper(c.Verdict))
		for _, h := range c.Hops {
			who := "takes"
			if h.Side == "source" {
				who = "sends"
			}
			switch {
			case h.DecidedBy != nil:
				word := map[string]string{"pass": "allowed", "block": "blocked"}[h.Verdict]
				if word == "" {
					word = h.Verdict
				}
				fprintf(w, "  %s %s: %s by %s\n", h.Jail, who, word, describeRule(h.DecidedBy))
			case h.Why != "":
				fprintf(w, "  %s %s: %s: %s\n", h.Jail, who, h.Verdict, h.Why)
			default:
				fprintf(w, "  %s %s: %s\n", h.Jail, who, h.Verdict)
			}
			if h.LoadedMatchesRendered == "false" {
				fprintf(w, "  note: the rules loaded in pf for %s differ from the rendered ones; the daemon will load them again\n", h.Anchor)
			}
		}
	}
	if len(res.Cases) > 1 {
		fprintf(w, "\nVerdict: %s\n", strings.ToUpper(res.Verdict))
	}
	fprintf(w, "\n(-v shows the rendered pf rules and what the test does not cover)\n")
}

func printFirewallTestVerbose(a *app, res api.FirewallTestResult) {
	w := a.env.Stdout
	for i, c := range res.Cases {
		if i > 0 {
			fprintf(w, "\n")
		}
		what := c.Proto
		if c.Port > 0 {
			what += " port " + fmt.Sprint(c.Port)
		}
		if c.ICMPType != "" {
			what += " " + c.ICMPType
		}
		fprintf(w, "%s %s -> %s (%s)\n", what, c.From, c.To, c.Family)
		for _, h := range c.Hops {
			side := "into"
			if h.Side == "source" {
				side = "out of"
			}
			fprintf(w, "  %s %s (%s, %s): %s", side, h.Jail, h.Anchor, h.Direction, strings.ToUpper(h.Verdict))
			switch {
			case h.DecidedBy != nil:
				fprintf(w, " by %s\n", describeRule(h.DecidedBy))
				fprintf(w, "      %s\n", h.DecidedBy.PF)
			case h.Why != "":
				fprintf(w, ": %s\n", h.Why)
			default:
				fprintf(w, "\n")
			}
			for _, sk := range h.Skipped {
				fprintf(w, "      skipped: %s: %s\n", describeRule(&sk.Rule), sk.Why)
			}
			if h.LoadedMatchesRendered == "false" {
				fprintf(w, "      note: the rules loaded in pf for %s differ from the rendered ones; the daemon will load them again\n", h.Anchor)
			}
		}
		fprintf(w, "  Verdict: %s\n", strings.ToUpper(c.Verdict))
	}
	if len(res.Cases) > 1 {
		fprintf(w, "\nVerdict: %s\n", strings.ToUpper(res.Verdict))
	}
	if len(res.Caveats) > 0 {
		fprintf(w, "\nNot covered:\n")
		for _, c := range res.Caveats {
			fprintf(w, "  - %s\n", c)
		}
	}
}

func describeRule(r *api.FirewallTestRule) string {
	if r.Stage != "policy" && r.Stage != "raw" {
		if s, ok := stageText[r.Stage]; ok {
			return s
		}
		return r.Stage
	}
	kind := "policy"
	switch {
	case r.ProjectPolicy:
		kind = "project policy"
	case r.Managed:
		kind = "managed policy"
	}
	s := fmt.Sprintf("%s %s", kind, r.Policy)
	if r.Rule > 0 {
		s += fmt.Sprintf(" rule %d", r.Rule)
		if r.Name != "" {
			s += " " + r.Name
		}
		if r.Comment != "" {
			s += fmt.Sprintf(" %q", r.Comment)
		}
	}
	return s
}
