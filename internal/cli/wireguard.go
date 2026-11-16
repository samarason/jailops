package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func wireguardDesc() *kindDesc[api.WireGuard] {
	d := newDesc("wireguard", "wireguard tunnels", api.KindWireGuard,
		func(w *api.WireGuard) *api.ObjectMeta { return &w.Metadata },
		func(w *api.WireGuard) *api.WireGuardSpec { return &w.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.WireGuard] { return c.WireGuard().Resource })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.WireGuard] { return c.WireGuard().Resource })
	d.renameLong = renameLong("WireGuard tunnel", `the directory of its keys, which the helper moves, and its firewall anchor, which is loaded again under the new name. The interface keeps its name and stays up`)
	d.head = []string{"NAME", "MODE", "INTERFACE", "ADDRESS", "PORT", "ENDPOINT", "PEERS", "STATE", "PUBLIC KEY"}
	d.row = func(_ time.Time, w api.WireGuard) []string {
		port := "-"
		if w.Spec.ListenPort != 0 {
			port = strconv.Itoa(w.Spec.ListenPort)
		}
		peers := strconv.Itoa(len(w.Spec.Peers))
		if w.Spec.Mode == api.WireGuardClient {
			peers = "-"
		}
		return []string{w.Metadata.Name, string(w.Spec.Mode), w.Spec.Interface, joinOrDash(w.Spec.Address), port, dash(w.Spec.Endpoint),
			peers, wgState(w), dash(w.Status.PublicKey)}
	}
	d.brief = &listView[api.WireGuard]{
		head: []string{"NAME", "MODE", "INTERFACE", "ADDRESS", "PEERS", "STATE"},
		drop: []int{4, 2},
		row: func(_ time.Time, w api.WireGuard) []string {
			peers := strconv.Itoa(len(w.Spec.Peers))
			if w.Spec.Mode == api.WireGuardClient {
				peers = "-"
			}
			return []string{w.Metadata.Name, string(w.Spec.Mode), w.Spec.Interface, linesOrDash(w.Spec.Address), peers, wgState(w)}
		},
	}
	d.show = func(a *app, w api.WireGuard) error { return a.showObject(w.Metadata, nil, w.Spec, w.Status) }
	d.warnings = func(w api.WireGuard) []string { return w.Status.Warnings }
	return &d
}

func wgState(w api.WireGuard) string {
	switch {
	case w.Spec.Down:
		return "down"
	case w.Status.Up:
		return "up"
	}
	return "pending"
}

func (a *app) wireguardCmd() *cobra.Command {
	d := wireguardDesc()
	wc := group("wireguard", "Manage WireGuard tunnels and their peers",
		`A WireGuard tunnel is a server that peers join, or a client of a server. The
keys are made on the host and stay there (root only); the API never shows a
private key. A server enrolls a peer with one command, which prints a join
token once: on another JailOps host 'jailops wireguard join NAME --token-file TOKEN-FILE' makes the
client and brings it up, and --format conf prints the same as a configuration
file for phones and laptops.

A server may name JailOps networks its peers reach (--network): JailOps loads
a pf anchor that passes the tunnel's traffic to them and nothing else.
Forwarding and the pf rule for the listen port stay with the administrator.`,
		`jailops wireguard create office --address 10.99.0.1/24 --network web
jailops wireguard peer add office laptop
jailops wireguard peer add office phone --format conf > phone.conf
jailops wireguard join office --token-file token.txt
jailops wireguard status office`, "wireguard tunnels", "wg")
	crudCommands(a, wc, d, `Create a WireGuard server: an interface (default wg-NAME) with the
given address, listening on --listen-port (default 51820). Peers get addresses from
--pool (default the subnet of --address). --endpoint is what peers dial and goes
into their tokens (default this host's name and the port). A client is made from a
token with 'jailops wireguard join'. Without --interface the name has at most
12 characters, so that wg-NAME fits the 15 characters of an interface name.`,
		`jailops wireguard create office --address 10.99.0.1/24
jailops wireguard create office --address 10.99.0.1/24 --address fd99::1/64 --network web --endpoint vpn.example.com:51820
jailops wireguard create -f office.yaml`,
		func(cmd *cobra.Command) func(string) (api.WireGuard, error) {
			var mode, iface, endpoint, comment string
			var addr, pool, dns, nets []string
			var port int
			f := cmd.Flags()
			f.StringVar(&comment, "comment", "", "what the tunnel is for")
			f.StringVar(&mode, "mode", "server", "server (a client is made with 'wireguard join')")
			f.StringArrayVar(&addr, "address", nil, "address of the interface with its prefix, IPv4 and/or IPv6 (repeatable; required)")
			f.IntVar(&port, "listen-port", 0, "UDP port the server listens on (default 51820)")
			f.StringVar(&endpoint, "endpoint", "", "host:port peers dial, written into their tokens (default this host's name and the port)")
			f.StringArrayVar(&pool, "pool", nil, "prefix peer addresses are taken from (repeatable; default the subnet of --address)")
			f.StringArrayVar(&dns, "dns", nil, "DNS server written into the peers' tokens (repeatable)")
			f.StringArrayVar(&nets, "network", nil, "JailOps network the peers may reach (repeatable)")
			f.StringVar(&iface, "interface", "", "interface name (default wg-NAME; at most 15 characters, starting with wg)")
			enumFlag(cmd, "mode", "server")
			_ = cmd.RegisterFlagCompletionFunc("network", completeKind(a, networkDesc()))
			return func(name string) (api.WireGuard, error) {
				if mode != string(api.WireGuardServer) {
					return api.WireGuard{}, usagef("a client is made from a join token: jailops wireguard join NAME --token-file TOKEN-FILE")
				}
				if len(addr) == 0 && !a.partial {
					return api.WireGuard{}, usagef("--address is required, for example --address 10.99.0.1/24")
				}
				return api.WireGuard{Metadata: api.ObjectMeta{Name: name}, Spec: api.WireGuardSpec{Comment: comment, Mode: api.WireGuardServer, Interface: iface,
					Address: addr, ListenPort: port, Endpoint: endpoint, AllowedIPs: pool, DNS: dns, Networks: nets}}, nil
			}
		})
	wc.AddCommand(a.wgUpDown(d, true), a.wgUpDown(d, false), a.wgStatusCmd(d), a.wgRotateCmd(d), a.wgJoinCmd(), a.wgPeerCmd(d))
	return wc
}

func (a *app) wgUpDown(d *kindDesc[api.WireGuard], up bool) *cobra.Command {
	verb, short, long := "down", "Take a tunnel down (the keys stay)", "Remove the tunnel's interface and keep the object and its keys; 'up' brings it back."
	if up {
		verb, short, long = "up", "Bring a tunnel up", "Create the tunnel's interface again after 'down'. The reconcile loop keeps it up from then on, across reboots."
	}
	return &cobra.Command{
		Use:               verb + " NAME",
		Aliases:           map[bool][]string{true: {"start"}, false: {"stop"}}[up],
		Short:             short,
		Long:              long,
		Example:           "jailops wireguard " + verb + " office",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("bring wireguard "+args[0]+" "+verb, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			call := c.WireGuard().Down
			if up {
				call = c.WireGuard().Up
			}
			w, err := call(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if err := a.finishOp(cmd.Context(), nil, "wireguard", args[0], map[bool]string{true: "is up", false: "is down"}[up], w); err != nil {
				return err
			}
			for _, x := range w.Status.Warnings {
				fprintf(a.env.Stderr, "warning: %s\n", x)
			}
			return nil
		},
	}
}

func (a *app) wgStatusCmd(d *kindDesc[api.WireGuard]) *cobra.Command {
	return &cobra.Command{
		Use:   "status NAME",
		Short: "Show the peers of a tunnel: handshake, transfer, endpoint",
		Long: `Show what the kernel reports for each peer of a tunnel (wg show): the latest
handshake, the bytes received and sent, and the endpoint the peer was last seen
at. A peer that never completed a handshake shows "never".`,
		Example:           "jailops wireguard status office\njailops wireguard status office -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			w, err := c.WireGuard().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			now := a.env.Now()
			return a.emit(w.Status, nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, p := range w.Status.Peers {
					name := p.Name
					if name == "" && w.Spec.Mode == api.WireGuardClient {
						name = "(server)"
					}
					rows = append(rows, []string{dash(name), joinOrDash(p.AllowedIPs), handshake(now, p.LatestHandshake),
						humanBytes(p.RxBytes) + " / " + humanBytes(p.TxBytes), dash(p.Endpoint)})
				}
				return []string{"PEER", "ADDRESS", "HANDSHAKE", "RECEIVED / SENT", "ENDPOINT"}, rows
			}, func() []string {
				var n []string
				for _, p := range w.Status.Peers {
					n = append(n, p.PublicKey)
				}
				return n
			})
		},
	}
}

func handshake(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return age(now, t) + " ago"
}

func (a *app) wgRotateCmd(d *kindDesc[api.WireGuard]) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-keys NAME",
		Short: "Give a tunnel a new key pair",
		Long: `Make a new private key for the tunnel on this host and apply it. The new public
key is printed. Every peer of a server needs it afterwards (issue new tokens), and
a client's server must enroll the client again. Asks for confirmation unless -y.`,
		Example:           "jailops wireguard rotate-keys office",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("rotate the keys of wireguard "+args[0], nil); ok || err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Rotate the keys of wireguard %q? Its peers lose the connection until they have the new public key.", args[0])); err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			k, err := c.WireGuard().RotateKeys(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if k.Warning != "" {
				fprintf(a.env.Stderr, "warning: %s\n", k.Warning)
			}
			return a.emit(k, nil, func() ([]string, [][]string) {
				return []string{"PUBLIC KEY"}, [][]string{{k.PublicKey}}
			}, func() []string { return []string{k.PublicKey} })
		},
	}
}

func (a *app) wgJoinCmd() *cobra.Command {
	var iface, endpoint, tokenFile string
	var addr, allowed []string
	cmd := &cobra.Command{
		Use:   "join NAME --token-file FILE",
		Short: "Join a WireGuard server with a token",
		Long: `Make a client tunnel called NAME from a join token ('jailops wireguard peer add' on the
server prints it) and bring it up. The token holds the client's private key and
the preshared key: they go to this host's helper and are not kept anywhere
else. The token is read from the file --token-file names, or from standard input
with --token-file -: it is never an argument, because on the command line other
users of the host can read it and the shell keeps it in its history.
The overrides replace what the token says: --endpoint when this host
reaches the server under another address, --address and --allowed-ips when the
token's addresses do not fit here.`,
		Example: `jailops wireguard join office --token-file token.txt
jailops wireguard join office --token-file - < token.txt
jailops wireguard join office --token-file token.txt --endpoint 203.0.113.10:51820`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if tokenFile == "" {
				return usagef("--token-file is required: the file with the join token, or - for standard input")
			}
			b, err := a.readInput(tokenFile)
			if err != nil {
				return err
			}
			tok := strings.TrimSpace(string(b))
			q := api.WireGuardJoin{Token: tok, Name: name, Interface: iface, Endpoint: endpoint, Address: addr, AllowedIPs: allowed}
			if a.dryRun {
				shown := q
				shown.Token = "(token, not shown)"
				_, err := a.dry("join a wireguard server", shown)
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			w, err := c.WireGuard().Join(cmd.Context(), q)
			if err != nil {
				return err
			}
			if err := a.finishOp(cmd.Context(), nil, "wireguard", w.Metadata.Name, "joined", w); err != nil {
				return err
			}
			for _, x := range w.Status.Warnings {
				fprintf(a.env.Stderr, "warning: %s\n", x)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&tokenFile, "token-file", "", "file with the join token, or - for standard input (required)")
	_ = cmd.RegisterFlagCompletionFunc("token-file", completeFiles)
	f.StringVar(&iface, "interface", "", "interface name (default wg-NAME)")
	f.StringVar(&endpoint, "endpoint", "", "host:port of the server, instead of the token's")
	f.StringArrayVar(&addr, "address", nil, "address of this end, instead of the token's (repeatable)")
	f.StringArrayVar(&allowed, "allowed-ips", nil, "prefix routed into the tunnel, instead of the token's (repeatable)")
	return cmd
}

func (a *app) wgPeerCmd(d *kindDesc[api.WireGuard]) *cobra.Command {
	pc := group("peer", "Enroll, list and remove the peers of a WireGuard server",
		`A peer is enrolled on the server with 'peer add': the host makes its key pair
and a preshared key, gives it the next free address of the pool, applies it at
once, and prints a join token once. The server keeps only the peer's public key
and the preshared key.`,
		`jailops wireguard peer add office laptop
jailops wireguard peer list office
jailops wireguard peer remove office laptop`)
	server := completeKind(a, d)
	peerNames := a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		w, err := c.WireGuard().Get(ctx, args[0])
		if err != nil {
			return nil, err
		}
		var out []string
		for _, p := range w.Spec.Peers {
			out = append(out, p.Name)
		}
		return out, nil
	})
	serverThenPeer := func(cmd *cobra.Command, args []string, s string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return server(cmd, args, s)
		}
		if len(args) == 1 {
			return peerNames(cmd, args, s)
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var addr []string
	var keepalive int
	var format string
	add := &cobra.Command{
		Use:   "add SERVER PEER",
		Short: "Enroll a peer and print its join token once",
		Long: `Enroll a peer of a server: the host makes the peer's key pair and a preshared
key, assigns the next free address of the pool (or --address), applies the peer
at once, and prints the join token ONCE. The token holds the peer's private key:
pass it on over a channel you trust; it is not stored anywhere. --format conf
prints the configuration file the WireGuard apps read instead (phones, laptops).`,
		Example: `jailops wireguard peer add office laptop
jailops wireguard peer add office phone --format conf > phone.conf
jailops wireguard peer add office ci --address 10.99.0.50 --keepalive 0`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: serverThenPeer,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "token" && format != "conf" {
				return usagef("--format %q must be token or conf", format)
			}
			q := api.WireGuardPeerAdd{Name: args[1], Address: addr, Keepalive: keepalive}
			if ok, err := a.dry("enroll peer "+args[1]+" of wireguard "+args[0], q); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			res, err := c.WireGuard().AddPeer(cmd.Context(), args[0], q)
			if err != nil {
				return err
			}
			if a.format == fmtJSON || a.format == fmtYAML {
				return a.emit(res, nil, nil, nil)
			}
			fprintf(a.env.Stderr, "Peer %s of wireguard %s enrolled with %s.\nwarning: %s\n", res.Peer.Name, args[0], strings.Join(res.Peer.AllowedIPs, ", "), res.Warning)
			if format == "conf" {
				_, err = fmt.Fprint(a.env.Stdout, termText(res.Config, true))
				return err
			}
			fprintln(a.env.Stdout, res.Token)
			return nil
		},
	}
	add.Flags().StringArrayVar(&addr, "address", nil, "address of the peer instead of the next free one (repeatable: one IPv4, one IPv6)")
	add.Flags().IntVar(&keepalive, "keepalive", 0, "persistent keepalive written into the token, in seconds (default 25)")
	add.Flags().StringVar(&format, "format", "token", "what to print: token (for 'wireguard join') or conf (a configuration file)")
	enumFlag(add, "format", "token", "conf")

	remove := &cobra.Command{
		Use:               "remove SERVER PEER",
		Aliases:           []string{"rm"},
		Short:             "Remove a peer of a server",
		Long:              "Remove a peer: it can no longer connect, and its preshared key is deleted. Asks for confirmation unless -y.",
		Example:           "jailops wireguard peer remove office laptop",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: serverThenPeer,
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("remove peer "+args[1]+" of wireguard "+args[0], nil); ok || err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Remove peer %q of wireguard %q?", args[1], args[0])); err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			w, err := c.WireGuard().RemovePeer(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "peer", args[0]+"/"+args[1], "removed", w)
		},
	}

	list := &cobra.Command{
		Use:               "list SERVER",
		Aliases:           []string{"ls"},
		Short:             "List the peers of a server",
		Long:              "List the enrolled peers of a server with their addresses, public keys and latest handshake.",
		Example:           "jailops wireguard peer list office\njailops wireguard peer list office -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: server,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			w, err := c.WireGuard().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			now := a.env.Now()
			peers := nonNil(w.Spec.Peers)
			return a.emit(peers, nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, p := range peers {
					st := peerStatus(w, p.PublicKey)
					rows = append(rows, []string{p.Name, joinOrDash(p.AllowedIPs), handshake(now, st.LatestHandshake), p.PublicKey, age(now, p.Created)})
				}
				return []string{"NAME", "ADDRESS", "HANDSHAKE", "PUBLIC KEY", "AGE"}, rows
			}, func() []string {
				var n []string
				for _, p := range peers {
					n = append(n, p.Name)
				}
				return n
			})
		},
	}

	show := &cobra.Command{
		Use:               "show SERVER PEER",
		Short:             "Show one peer of a server",
		Long:              "Show a peer's public key, addresses and what the kernel reports about it. Secrets are never shown.",
		Example:           "jailops wireguard peer show office laptop",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: serverThenPeer,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			w, err := c.WireGuard().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			for _, p := range w.Spec.Peers {
				if p.Name != args[1] {
					continue
				}
				st := peerStatus(w, p.PublicKey)
				out := struct {
					Peer   api.WireGuardPeer       `json:"peer"`
					Status api.WireGuardPeerStatus `json:"status"`
				}{p, st}
				if a.format == fmtJSON || a.format == fmtYAML {
					return a.emit(out, nil, nil, nil)
				}
				now := a.env.Now()
				wr := a.env.Stdout
				fprintf(wr, "Name:        %s\n", p.Name)
				fprintf(wr, "Server:      %s\n", w.Metadata.Name)
				fprintf(wr, "Public key:  %s\n", p.PublicKey)
				fprintf(wr, "Address:     %s\n", joinOrDash(p.AllowedIPs))
				fprintf(wr, "Handshake:   %s\n", handshake(now, st.LatestHandshake))
				fprintf(wr, "Transfer:    %s received, %s sent\n", humanBytes(st.RxBytes), humanBytes(st.TxBytes))
				fprintf(wr, "Endpoint:    %s\n", dash(st.Endpoint))
				fprintf(wr, "Preshared:   %s\n", map[bool]string{true: "yes", false: "no"}[st.PresharedKey])
				fprintf(wr, "Age:         %s\n", age(now, p.Created))
				return nil
			}
			return api.Errorf(api.CodeNotFound, "peer %q of wireguard %q not found", args[1], args[0])
		},
	}
	pc.AddCommand(add, remove, list, show)
	return pc
}

func peerStatus(w api.WireGuard, pub string) api.WireGuardPeerStatus {
	for _, s := range w.Status.Peers {
		if s.PublicKey == pub {
			return s
		}
	}
	return api.WireGuardPeerStatus{}
}
