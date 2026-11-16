package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func networkDesc() *kindDesc[api.Network] {
	d := newDesc("network", "networks", api.KindNetwork,
		func(n *api.Network) *api.ObjectMeta { return &n.Metadata },
		func(n *api.Network) *api.NetworkSpec { return &n.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Network] { return c.Networks().Resource })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Network] { return c.Networks().Resource })
	d.renameLong = renameLong("network", `the projects it is granted to, the jails attached to it (running
ones too: nothing of their traffic changes), the profiles and WireGuard tunnels that name it, its firewall
anchor and the descriptions of its interfaces`)
	d.head = []string{"NAME", "IPV4", "GATEWAY", "RANGE", "USED", "FREE", "UPLINK"}
	d.row = func(_ time.Time, n api.Network) []string {
		sub, gw, rng := "-", "-", "-"
		if v4 := n.Spec.IPv4; v4 != nil {
			sub, gw, rng = v4.Subnet, v4.Gateway, v4.Range
		}
		return []string{n.Metadata.Name, sub, gw, rng,
			fmt.Sprint(n.Status.Allocated), fmt.Sprint(n.Status.Free), dash(n.Spec.Uplink)}
	}
	// On a terminal: both address families, and the range on its own line under the subnet.
	d.brief = &listView[api.Network]{
		head: []string{"NAME", "IPV4", "IPV6", "USED", "FREE", "UPLINK"},
		drop: []int{5, 4, 3, 2},
		row: func(_ time.Time, n api.Network) []string {
			v4, v6 := "-", "-"
			if a := n.Spec.IPv4; a != nil {
				v4 = a.Subnet + "\n" + a.Range
			}
			if a := n.Spec.IPv6; a != nil && a.Mode != api.IPv6None {
				v6 = a.Subnet + " (" + string(a.Mode) + ")\n" + a.Range
			}
			return []string{n.Metadata.Name, v4, v6, fmt.Sprint(n.Status.Allocated), fmt.Sprint(n.Status.Free), dash(n.Spec.Uplink)}
		},
	}
	d.show = func(a *app, n api.Network) error { return a.showNetwork(n) }
	d.emptyHint = "jailops network create NAME --ipv4 10.50.0.1/24 --uplink IFACE --nat"
	d.warnings = func(n api.Network) []string { return n.Status.Warnings }
	d.updated = func(a *app, n api.Network) {
		for _, w := range n.Status.Warnings {
			fprintf(a.env.Stderr, "warning: %s\n", w)
		}
		if dn := n.Status.DNS; dn != nil {
			if len(dn.Updated) > 0 {
				fprintf(a.env.Stderr, "resolv.conf rewritten in the running jails %s (no restart needed)\n", strings.Join(dn.Updated, ", "))
			}
			for _, f := range dn.NotUpdated {
				fprintf(a.env.Stderr, "warning: resolv.conf not rewritten in %s\n", f)
			}
		}
	}
	return &d
}

func (a *app) networkCmd() *cobra.Command {
	d := networkDesc()
	nc := group("network", "Manage VNET networks and their addresses",
		`A network is an address range with an uplink policy. Each jail attaches to it with a virtual
interface of its own, a routed link to the host: the host is the router, and jails never share a segment. JailOps
allocates addresses from the network's range deterministically and writes them into the jail specification;
there is no DHCP.`,
		`jailops network create lan --ipv4 10.77.0.1/24 --uplink em0 --nat
jailops network create web --ipv4 10.50.0.1/24 --ipv6 fd50::1/64
jailops network create lan --subnet 10.20.0.0/24 --gateway 10.20.0.1 --range 10.20.0.10-10.20.0.250 --nat --uplink em0
jailops network list
jailops network leases lan`, "networks", "net")
	crudCommands(a, nc, d, `Create a network. IPv4 is described by --subnet, --gateway and --range; the
gateway is an address of the host inside the subnet, which every jail of the network finds on its own link. IPv6 is
--ipv6 PREFIX (the jails' default gateway is the link-local fe80::1 on every link); --ipv6-mode proxy is for a prefix
on a shared segment (switched), routed is for a prefix the provider routes to you. A jail's addresses are /32 and
/128 host routes: nothing in the subnet that no jail has is reachable.`,
		`jailops network create lan --ipv4 10.77.0.1/24 --uplink em0 --nat
jailops network create lan --subnet 10.20.0.0/24 --gateway 10.20.0.1 --range 10.20.0.10-10.20.0.250 --nat --uplink em0
jailops network create -f lan.yaml`,
		func(cmd *cobra.Command) func(string) (api.Network, error) {
			var uplink, subnet, gw, rng, v4cidr, v6cidr, v6mode, comment string
			var exclude, dns []string
			var nat bool
			var mtu int
			f := cmd.Flags()
			f.StringVar(&comment, "comment", "", "what the network is for")
			f.StringVar(&uplink, "uplink", "", "physical interface used for NAT or routing")
			f.StringVar(&v4cidr, "ipv4", "", "IPv4 gateway address and prefix, for example 10.50.0.1/24; the rest of the subnet becomes the range")
			f.StringVar(&v6cidr, "ipv6", "", "IPv6 prefix, for example fd50::/64; with --ipv6-mode proxy, the prefix your provider put on the shared segment, for example 2001:db8:1:2:100::/80")
			f.StringVar(&v6mode, "ipv6-mode", "routed", "routed: the provider routes the prefix to this host; proxy: the prefix sits on a shared segment and jailops answers neighbor discovery for each jail address")
			f.StringVar(&subnet, "subnet", "", "IPv4 subnet, for example 10.20.0.0/24 (required without -f)")
			f.StringVar(&gw, "gateway", "", "IPv4 gateway address (an address of the host inside the subnet)")
			f.StringVar(&rng, "range", "", "allocation range a-b")
			f.StringArrayVar(&exclude, "exclude", nil, "address or span to keep out of the range (repeatable)")
			f.BoolVar(&nat, "nat", false, "masquerade traffic leaving through the uplink")
			f.StringArrayVar(&dns, "dns", nil, "DNS server handed to jails (repeatable)")
			f.IntVar(&mtu, "mtu", 0, "MTU of the jails' interfaces")
			enumFlag(cmd, "ipv6-mode", "routed", "proxy")
			return func(name string) (api.Network, error) {
				spec := api.NetworkSpec{Comment: comment, Uplink: uplink, DNS: dns, MTU: mtu}
				switch {
				case v4cidr != "" && (subnet != "" || gw != "" || rng != ""):
					return api.Network{}, usagef("--ipv4 replaces --subnet, --gateway and --range: use one form")
				case v4cidr != "":
					v4, err := cidrNetwork(v4cidr)
					if err != nil {
						return api.Network{}, err
					}
					v4.NAT, v4.Exclude = nat, append(v4.Exclude, exclude...)
					spec.IPv4 = v4
				case subnet != "" || gw != "" || rng != "":
					if (subnet == "" || gw == "" || rng == "") && !a.partial {
						return api.Network{}, usagef("--subnet, --gateway and --range go together (or use --ipv4)")
					}
					spec.IPv4 = &api.IPv4Net{Subnet: subnet, Gateway: gw, Range: rng, Exclude: exclude, NAT: nat}
				}
				if v6cidr != "" {
					var v6 *api.IPv6Net
					var err error
					switch v6mode {
					case "routed":
						v6, err = cidr6Network(v6cidr)
					case "proxy":
						v6, err = cidr6Proxy(v6cidr)
					default:
						err = usagef("--ipv6-mode %q must be routed or proxy", v6mode)
					}
					if err != nil {
						return api.Network{}, err
					}
					spec.IPv6 = v6
				} else if cmd.Flags().Changed("ipv6-mode") {
					if !a.partial {
						return api.Network{}, usagef("--ipv6-mode needs --ipv6")
					}
					spec.IPv6 = &api.IPv6Net{Mode: api.IPv6Mode(v6mode)}
				}
				if a.partial && spec.IPv4 == nil && (cmd.Flags().Changed("nat") || cmd.Flags().Changed("exclude")) {
					spec.IPv4 = &api.IPv4Net{NAT: nat, Exclude: exclude}
				}
				if spec.IPv4 == nil && spec.IPv6 == nil && !a.partial {
					return api.Network{}, usagef("give --ipv4 and/or --ipv6, or --subnet, --gateway and --range (or use -f FILE)")
				}
				return api.Network{Metadata: api.ObjectMeta{Name: name}, Spec: spec}, nil
			}
		})
	nc.AddCommand(a.networkGrantCmds(d)...)
	nc.AddCommand(&cobra.Command{
		Use:               "leases NETWORK",
		Short:             "List the addresses allocated on a network",
		Long:              "List the addresses allocated on a network and the jail that holds each. Leases are derived from the jail specifications.",
		Example:           "jailops network leases lan\njailops network leases lan -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			ls, err := collect(c.Networks().Leases(cmd.Context(), args[0]))
			if err != nil {
				return err
			}
			return a.emit(nonNil(ls), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, l := range ls {
					rows = append(rows, []string{l.Address, l.Jail, l.Network})
				}
				return []string{"ADDRESS", "JAIL", "NETWORK"}, rows
			}, func() []string {
				var n []string
				for _, l := range ls {
					n = append(n, l.Address)
				}
				return n
			})
		},
	})
	return nc
}
