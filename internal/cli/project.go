package cli

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func (a *app) projectDesc() *kindDesc[api.Project] {
	d := newDesc("project", "projects", api.KindProject,
		func(p *api.Project) *api.ObjectMeta { return &p.Metadata },
		func(p *api.Project) *api.ProjectSpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Project] { return c.Projects().Resource })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Project] { return c.Projects().Resource })
	d.renameLong = renameLong("project", `its policies, address sets, backup policies and profiles, its
datasets on every storage with the mountpoints of its jails, their records and state, its firewall anchor,
its provisioning files, the project lists of users, tokens, trust tokens and certificates, and the stored
log sinks that select it. Every jail of the project must be stopped`)
	d.head = []string{"", "NAME", "HOSTS", "NETWORKS", "STORAGE", "JAILS", "COMMENT"}
	d.style = func(col int, v string) string {
		if col == 0 && v == "*" {
			return "32"
		}
		return ""
	}
	d.row = func(_ time.Time, p api.Project) []string {
		mark := ""
		if p.Metadata.Name == a.conn.CurrentProject() {
			mark = "*"
		}
		var nets, stor []string
		for _, n := range p.Spec.Networks {
			nets = append(nets, n.Network)
		}
		for _, s := range p.Spec.Storage {
			stor = append(stor, s.Storage)
		}
		jails := strconv.Itoa(p.Status.Jails)
		if q := p.Spec.Quotas.Jails; q > 0 {
			jails += "/" + strconv.Itoa(q)
		}
		return []string{mark, p.Metadata.Name, joinOrDash(p.Spec.Hosts), joinOrDash(nets), joinOrDash(stor), jails, dash(p.Spec.Comment)}
	}
	d.show = func(a *app, p api.Project) error { return a.showProject(p) }
	d.emptyHint = "jailops project create NAME --new-network"
	return &d
}

// projectOpts holds the flags that describe a project; create and set share them.
type projectOpts struct {
	comment, maxMemory                  string
	images, hosts                       []string
	firewall                            []string
	maxJails, maxCPU, maxPIDs, maxAddrs int
	clearImages, newNetwork             bool
}

func projectFlags(cmd *cobra.Command, forSet bool) *projectOpts {
	o := &projectOpts{}
	f := cmd.Flags()
	f.StringVar(&o.comment, "comment", "", "what the project is for")
	f.IntVar(&o.maxJails, "max-jails", 0, "quota: number of jails (0 = unlimited)")
	f.IntVar(&o.maxCPU, "max-cpu", 0, "quota: total CPU cores (0 = unlimited)")
	f.StringVar(&o.maxMemory, "max-memory", "", "quota: total memory, for example 16G")
	f.IntVar(&o.maxPIDs, "max-pids", 0, "quota: total processes (0 = unlimited)")
	f.IntVar(&o.maxAddrs, "max-addresses", 0, "quota: total addresses (0 = unlimited)")
	f.StringArrayVar(&o.firewall, "firewall-policy", nil, "mandatory firewall policy rendered before every jail's own (repeatable, in order; an empty value clears the list; global admins only)")
	f.StringArrayVar(&o.images, "image", nil, "image allow-list entry (repeatable; empty allows every image)")
	f.StringSliceVar(&o.hosts, "hosts", nil, "hosts a fleet project spans, comma separated (managed by a hub)")
	if forSet {
		f.BoolVar(&o.clearImages, "any-image", false, "remove the image allow-list")
	} else {
		f.BoolVar(&o.newNetwork, "new-network", false, "also create a dedicated network with a subnet and grant it to the project")
	}
	return o
}

// apply changes spec according to the flags that were given.
func (o *projectOpts) apply(cmd *cobra.Command, spec *api.ProjectSpec) error {
	ch := cmd.Flags().Changed
	if ch("comment") {
		spec.Comment = o.comment
	}
	if ch("max-jails") {
		spec.Quotas.Jails = o.maxJails
	}
	if ch("max-cpu") {
		spec.Quotas.CPU = o.maxCPU
	}
	if ch("max-memory") {
		spec.Quotas.Memory = o.maxMemory
	}
	if ch("max-pids") {
		spec.Quotas.PIDs = o.maxPIDs
	}
	if ch("max-addresses") {
		spec.Quotas.Addresses = o.maxAddrs
	}
	if ch("firewall-policy") {
		spec.FirewallPolicies = nil
		for _, n := range o.firewall { // an empty value clears the list
			if n != "" {
				spec.FirewallPolicies = append(spec.FirewallPolicies, n)
			}
		}
	}
	if o.clearImages {
		spec.Images = nil
	}
	if ch("image") {
		spec.Images = o.images
	}
	if ch("hosts") {
		spec.Hosts = o.hosts
	}
	if o.newNetwork {
		spec.NewNetwork = true
	}
	return nil
}

func (a *app) completeProjects() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		items, err := collect(c.Projects().List(ctx))
		var n []string
		for _, p := range items {
			n = append(n, p.Metadata.Name)
		}
		return n, err
	})
}

// completeFlag completes the value of a flag from a list on the server.
func (a *app) completeFlag(cmd *cobra.Command, flag string, list func(ctx context.Context, c *sdk.Client) ([]string, error)) {
	fn := a.completeNames(list)
	_ = cmd.RegisterFlagCompletionFunc(flag, func(c *cobra.Command, _ []string, t string) ([]string, cobra.ShellCompDirective) {
		return fn(c, nil, t)
	})
}

func (a *app) projectCmd() *cobra.Command {
	d := a.projectDesc()
	pc := group("project", "Manage projects and choose the current one",
		`A project is a namespace that owns jails, volumes, firewall policies, address
sets and backup policies. It is granted networks and storage, which are
separate host resources, and it has quotas. A network belongs to one project and
is never shared. There is no default project: a new host has none, and every
command that works in a project needs one (--project, JAILOPS_PROJECT or the
current project chosen with 'project switch').

The current project is client-side state: 'project switch' stores it per remote
in the client configuration, so switching remotes and switching projects are
independent and each remote remembers its last project. --project and
JAILOPS_PROJECT override it for one command.`,
		`jailops network create web --ipv4 10.50.0.1/24
jailops storage create fast --dataset tank/jailops
jailops project create web
jailops network grant web --project web
jailops storage grant fast --project web --quota 500G
jailops project switch web`, "projects")
	d.noSet = true // project set also grants and revokes
	crudCommands(a, pc, d, `Create a project. Networks and storage are granted afterwards ('jailops network grant',
'jailops storage grant'); --new-network creates a dedicated network with a subnet from the
server's pool and grants it. Only global admins create projects.

A project name has at most 13 characters. --new-network names the network after
the project.`,
		`jailops project create web
jailops project create web --max-jails 20 --max-memory 32G
jailops project create shop --new-network --hosts freebsd01,freebsd02`,
		func(cmd *cobra.Command) func(string) (api.Project, error) {
			o := projectFlags(cmd, false)
			return func(name string) (api.Project, error) {
				p := api.Project{Metadata: api.ObjectMeta{Name: name}}
				return p, o.apply(cmd, &p.Spec)
			}
		})
	pc.AddCommand(a.projectSet(d), a.projectSwitch(d), a.projectFleet(d))
	return pc
}

type iterNames func(yield func(string, error) bool)

func namesOf[T any](seq func(func(T, error) bool), f func(T) string) iterNames {
	return func(yield func(string, error) bool) {
		for v, err := range seq {
			if !yield(f(v), err) {
				return
			}
		}
	}
}

func netName(n api.Network) string  { return n.Metadata.Name }
func storName(n api.Storage) string { return n.Metadata.Name }
func imageName2(n api.Image) string { return n.Metadata.Name }
func projName(n api.Project) string { return n.Metadata.Name }
func listNames(f func(context.Context, *sdk.Client) iterNames) func(context.Context, *sdk.Client) ([]string, error) {
	return func(ctx context.Context, c *sdk.Client) ([]string, error) {
		var out []string
		for n, err := range f(ctx, c) {
			if err != nil {
				return out, err
			}
			out = append(out, n)
		}
		return out, nil
	}
}

func (a *app) projectSet(d *kindDesc[api.Project]) *cobra.Command {
	var o *projectOpts
	cmd := &cobra.Command{
		Use:   "set NAME",
		Short: "Change a project's quotas and settings",
		Long: `Change a project in place: set quotas, the mandatory firewall policies, the image
allow-list or the hosts of a fleet project. Only the flags you give change anything.
The update carries the ETag of the version it read, and is retried on a conflict.
Networks and storage are granted with 'jailops network grant' and 'jailops storage grant'.
Only global admins change projects.`,
		Example: `jailops project set web --max-jails 20 --max-memory 32G
jailops project set web --firewall-policy default
jailops project set web --hosts freebsd01,freebsd02`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeProjects(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			var applyErr error
			change := func(p *api.Project) { applyErr = o.apply(cmd, &p.Spec) }
			if ok, err := a.dry("update project "+args[0], nil); ok || err != nil {
				return err
			}
			if err := sdk.Modify(cmd.Context(), c.Projects(), args[0], change); err != nil {
				return err
			}
			if applyErr != nil {
				return applyErr
			}
			return a.finishOp(cmd.Context(), nil, "project", args[0], "updated", nil)
		},
	}
	o = projectFlags(cmd, true)
	// the policies are the ones of the project that is being changed (its name is the argument), not of the current project
	_ = cmd.RegisterFlagCompletionFunc("firewall-policy", a.completeWith(func(ctx context.Context, c *sdk.Client, args []string) ([]string, error) {
		if len(args) == 0 {
			return nil, nil
		}
		items, err := collect(c.Project(args[0]).Firewall().Policies().List(ctx))
		var n []string
		for _, p := range items {
			n = append(n, p.Metadata.Name)
		}
		return n, err
	}))
	return cmd
}

// followProjectRename makes the renamed project the current one again where the user configuration chose it.
func (a *app) followProjectRename(from, to string) error {
	if a.conn == nil || a.conn.Project != from {
		return nil
	}
	if src := a.conn.Sources["project"]; src == "env JAILOPS_PROJECT" || src == "flag --project" {
		fprintf(a.env.Stderr, "note: %s names the old project %s; use %s from now on\n", src, from, to)
		return nil
	}
	path := a.userConfigPath()
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cfg.Projects[keyOf(a.conn.Name)] != from {
		return nil
	}
	cfg.Projects[keyOf(a.conn.Name)] = to
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	a.say("remote %s now uses project %s\n", keyOf(a.conn.Name), to)
	return nil
}

// projectSwitch stores the current project of the current remote.
func (a *app) projectSwitch(d *kindDesc[api.Project]) *cobra.Command {
	return &cobra.Command{
		Use:   "switch [NAME]",
		Short: "Make a project the current one of this remote",
		Long: `Store NAME as the current project of the current remote in the client
configuration. Nothing changes on the server. Each remote remembers its own
last project, and 'remote switch' does not touch it. --project and
JAILOPS_PROJECT override the stored value for a single command.

Without NAME the command prints the current project and where it came from. A new
client has none: there is no default project.`,
		Example:           "jailops project switch web\njailops project switch\njailops --remote prod project switch web",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: a.completeProjects(),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := a.resolveConnection()
			if err != nil {
				return err
			}
			a.conn = conn
			if len(args) == 0 {
				src := conn.Sources["project"]
				if conn.Project == "" {
					fprintf(a.env.Stderr, "no project chosen on remote %s: choose one with 'jailops project switch NAME'\n", keyOf(conn.Name))
					if a.format != fmtTable {
						return a.emit(map[string]string{"project": "", "remote": keyOf(conn.Name), "source": ""}, nil, nil, func() []string { return nil })
					}
					return nil
				}
				if a.format != fmtTable {
					return a.emit(map[string]string{"project": conn.CurrentProject(), "remote": keyOf(conn.Name), "source": src}, nil, nil, func() []string { return []string{conn.CurrentProject()} })
				}
				fprintln(a.env.Stdout, conn.CurrentProject())
				fprintf(a.env.Stderr, "(remote %s, from %s)\n", keyOf(conn.Name), src)
				return nil
			}
			name := args[0]
			if ok, err := a.dry(fmt.Sprintf("switch remote %s to project %s", keyOf(conn.Name), name), nil); ok || err != nil {
				return err
			}
			// Check the project exists, so a typo is caught now and not on
			// the next command.
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			if _, _, err := d.get(cmd.Context(), c, name); err != nil {
				return err
			}
			path := a.userConfigPath()
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			if cfg.Projects == nil {
				cfg.Projects = map[string]string{}
			}
			cfg.Projects[keyOf(conn.Name)] = name
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			a.say("remote %s now uses project %s\n", keyOf(conn.Name), name)
			if conn.Sources["project"] == "env JAILOPS_PROJECT" || conn.Sources["project"] == "flag --project" {
				fprintf(a.env.Stderr, "note: %s still overrides it for this shell or command\n", conn.Sources["project"])
			}
			return nil
		},
	}
}

// projectFleet shows a fleet project across the hosts of a hub.
func (a *app) projectFleet(d *kindDesc[api.Project]) *cobra.Command {
	return &cobra.Command{
		Use:   "fleet NAME",
		Short: "Show a fleet project on every host it spans",
		Long: `On a hub, show the definition of a fleet project and its state on each host it
lists: whether the host is online, whether it holds the project, whether its copy
equals the definition, and its usage. The totals sum the hosts that answered.`,
		Example:           "jailops project fleet shop\njailops project fleet shop -o json",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeProjects(),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			ag, err := c.Projects().Aggregate(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.emit(ag, nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, h := range ag.Hosts {
					jails, errText := "-", ""
					if h.Status != nil {
						jails = strconv.Itoa(h.Status.Jails)
					}
					if h.Error != nil {
						errText = string(h.Error.Code) + ": " + h.Error.Message
					}
					rows = append(rows, []string{h.Host, yesno(h.Online), yesno(h.Applied), yesno(h.InSync), jails, dash(errText)})
				}
				rows = append(rows, []string{"total", "", "", "", strconv.Itoa(ag.Total.Jails), ""})
				return []string{"HOST", "ONLINE", "APPLIED", "IN SYNC", "JAILS", "ERROR"}, rows
			}, func() []string {
				var n []string
				for _, h := range ag.Hosts {
					n = append(n, h.Host)
				}
				return n
			})
		},
	}
}

// storage -----------------------------------------------------------------

func storageDesc() *kindDesc[api.Storage] {
	d := newDesc("storage", "storage locations", api.KindStorage,
		func(p *api.Storage) *api.ObjectMeta { return &p.Metadata },
		func(p *api.Storage) *api.StorageSpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Storage] { return c.Storage() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Storage] { return c.Storage() })
	d.renameLong = renameLong("storage", `the projects it is granted to, the volumes and the jails on it (running ones too: nothing moves, the datasets stay where they are) and the profiles that name it. The default storage keeps its name`)
	d.head = []string{"NAME", "DATASET", "POOL", "HEALTH", "USED", "AVAILABLE"}
	d.row = func(_ time.Time, s api.Storage) []string {
		return []string{s.Metadata.Name, s.Spec.Dataset, dash(s.Status.Pool), dash(s.Status.Health), humanBytes(s.Status.Used), humanBytes(s.Status.Available)}
	}
	d.style = stateStyle(3)
	d.show = func(a *app, s api.Storage) error { return a.showStorage(s) }
	d.emptyHint = "jailops storage create NAME --dataset POOL/jailops"
	return &d
}

func (a *app) storageCmd() *cobra.Command {
	d := storageDesc()
	sc := group("storage", "Manage storage locations on ZFS",
		`A storage is a named ZFS dataset root on a host. Jail and volume datasets are
created below it, so one pool can serve several storages and one storage many
projects, each project with its own dataset and quota. Storage is ZFS only.
Deleting a storage never destroys data; it is refused while a project grants it
or a jail uses it. Only global admins write storage.`,
		"jailops storage create fast --dataset tank/jailops\njailops storage list\njailops storage show fast", "storages")
	crudCommands(a, sc, d, "Register an existing ZFS dataset as a storage. The dataset must exist and be empty or already owned by JailOps.\nThe dataset name has at most 88 characters: the datasets of jails, volumes and snapshots are named below it, and ZFS allows 255.",
		"jailops storage create fast --dataset tank/jailops\njailops storage create slow --dataset hdd/jailops --compression zstd",
		func(cmd *cobra.Command) func(string) (api.Storage, error) {
			var dataset, desc, comp string
			cmd.Flags().StringVar(&dataset, "dataset", "", "ZFS dataset, for example tank/jailops (required without -f)")
			cmd.Flags().StringVar(&desc, "comment", "", "what the storage is for")
			cmd.Flags().StringVar(&comp, "compression", "", "compression for new datasets: zstd or lz4")
			enumFlag(cmd, "compression", "zstd", "lz4")
			return func(name string) (api.Storage, error) {
				if dataset == "" && !a.partial {
					return api.Storage{}, usagef("--dataset is required (or use -f FILE)")
				}
				return api.Storage{Metadata: api.ObjectMeta{Name: name}, Spec: api.StorageSpec{Dataset: dataset, Comment: desc, Compression: comp}}, nil
			}
		})
	sc.AddCommand(a.storageGrantCmds(d)...)
	return sc
}

// network additions: grants -----------------------------------------------------

func (a *app) networkGrantCmds(nd *kindDesc[api.Network]) []*cobra.Command {
	// project is the project to change: the global --project, JAILOPS_PROJECT or the current project.
	project := func() (string, error) {
		if err := a.requireProject(); err != nil {
			return "", err
		}
		conn, err := a.resolveConnection()
		if err != nil {
			return "", err
		}
		return conn.CurrentProject(), nil
	}
	grant := &cobra.Command{
		Use:   "grant NETWORK",
		Short: "Grant a network to a project",
		Long: `Grant a network to a project: --project, JAILOPS_PROJECT or the current project
('project switch'). A network belongs to one project: it is used whole by that
project and is never shared, so the server refuses to grant a network that another
project already holds. Only global admins change projects.`,
		Example:           "jailops network grant web --project web\njailops network grant web",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, nd),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := project()
			if err != nil {
				return err
			}
			if ok, err := a.dry("grant network "+args[0]+" to project "+p, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			err = sdk.Modify(cmd.Context(), c.Projects(), p, func(pr *api.Project) {
				if !slices.ContainsFunc(pr.Spec.Networks, func(x api.ProjectNetwork) bool { return x.Network == args[0] }) {
					pr.Spec.Networks = append(pr.Spec.Networks, api.ProjectNetwork{Network: args[0]})
				}
			})
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "network", args[0], "granted to project "+p, nil)
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke NETWORK",
		Short: "Withdraw a network grant from a project",
		Long: `Withdraw the grant of a network from a project: --project, JAILOPS_PROJECT or the
current project. The server refuses while a jail of the project still uses the network.`,
		Example:           "jailops network revoke web --project web",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, nd),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := project()
			if err != nil {
				return err
			}
			if ok, err := a.dry("revoke network "+args[0]+" from project "+p, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			err = sdk.Modify(cmd.Context(), c.Projects(), p, func(pr *api.Project) {
				pr.Spec.Networks = slices.DeleteFunc(pr.Spec.Networks, func(x api.ProjectNetwork) bool { return x.Network == args[0] })
			})
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "network", args[0], "revoked from project "+p, nil)
		},
	}
	return []*cobra.Command{grant, revoke}
}

// cidrNetwork turns --ipv4 ADDR/LEN into the pieces of an IPv4Net: the host
// address is the gateway and the rest of the usable addresses is the range.
func cidrNetwork(s string) (*api.IPv4Net, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Bits() > 30 {
		return nil, usagef("--ipv4 %q must look like 10.50.0.1/24", s)
	}
	gw := p.Addr()
	net := p.Masked()
	first := net.Addr().Next()
	last := lastAddr(net)
	n := &api.IPv4Net{Subnet: net.String(), Gateway: gw.String()}
	if gw == first {
		first = first.Next()
	}
	n.Range = first.String() + "-" + last.String()
	if gw != net.Addr().Next() && !gw.Less(first) && !last.Less(gw) {
		n.Exclude = []string{gw.String()}
	}
	return n, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	v-- // the broadcast address is not usable
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func cidr6Network(s string) (*api.IPv6Net, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Bits() > 120 {
		return nil, usagef("--ipv6 %q must look like fd50::/64", s)
	}
	p = p.Masked()
	lo := p.Addr().Next()
	hi := lo
	for i := 0; i < 0xfffe; i++ {
		nx := hi.Next()
		if !p.Contains(nx) {
			break
		}
		hi = nx
	}
	return &api.IPv6Net{Mode: api.IPv6Routed, Subnet: p.String(), Range: lo.String() + "-" + hi.String()}, nil
}

// cidr6Proxy describes a proxy-mode IPv6 network from the prefix the provider put on the shared segment: the range
// starts a few addresses in, so the low addresses stay free for the operator.
func cidr6Proxy(s string) (*api.IPv6Net, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Bits() > 126 {
		return nil, usagef("--ipv6 %q must be a prefix such as 2001:db8:1:2:100::/80", s)
	}
	p = p.Masked()
	lo := p.Addr().Next()
	if p.Bits() <= 123 {
		for i := 0; i < 15; i++ {
			lo = lo.Next()
		}
	}
	hi := lo
	for i := 0; i < 0xfffe; i++ {
		nx := hi.Next()
		if !p.Contains(nx) {
			break
		}
		hi = nx
	}
	return &api.IPv6Net{Mode: api.IPv6Proxy, Subnet: p.String(), Range: lo.String() + "-" + hi.String()}, nil
}

// storage additions: grants -----------------------------------------------------

func (a *app) storageGrantCmds(sd *kindDesc[api.Storage]) []*cobra.Command {
	project := func() (string, error) {
		if err := a.requireProject(); err != nil {
			return "", err
		}
		conn, err := a.resolveConnection()
		if err != nil {
			return "", err
		}
		return conn.CurrentProject(), nil
	}
	var quota string
	grant := &cobra.Command{
		Use:   "grant STORAGE",
		Short: "Grant a storage to a project",
		Long: `Grant a storage to a project: --project, JAILOPS_PROJECT or the current project
('project switch'). The project gets its own datasets below the storage; --quota limits
the space they may use (for example 500G; without it the project is not limited).
Granting again changes the quota. Only global admins change projects.`,
		Example:           "jailops storage grant fast --project web\njailops storage grant fast --project web --quota 500G",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, sd),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := project()
			if err != nil {
				return err
			}
			if ok, err := a.dry("grant storage "+args[0]+" to project "+p, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			err = sdk.Modify(cmd.Context(), c.Projects(), p, func(pr *api.Project) {
				g := api.ProjectStorage{Storage: args[0], Quota: quota}
				if i := slices.IndexFunc(pr.Spec.Storage, func(x api.ProjectStorage) bool { return x.Storage == args[0] }); i >= 0 {
					if !cmd.Flags().Changed("quota") {
						g.Quota = pr.Spec.Storage[i].Quota
					}
					pr.Spec.Storage[i] = g
				} else {
					pr.Spec.Storage = append(pr.Spec.Storage, g)
				}
			})
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "storage", args[0], "granted to project "+p, nil)
		},
	}
	grant.Flags().StringVar(&quota, "quota", "", "space the project may use of the storage, for example 500G (default: no limit)")
	_ = grant.RegisterFlagCompletionFunc("quota", completeNone)
	revoke := &cobra.Command{
		Use:   "revoke STORAGE",
		Short: "Withdraw a storage grant from a project",
		Long: `Withdraw the grant of a storage from a project: --project, JAILOPS_PROJECT or the
current project. The server refuses while a jail or a volume of the project still lives on the storage.`,
		Example:           "jailops storage revoke fast --project web",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, sd),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := project()
			if err != nil {
				return err
			}
			if ok, err := a.dry("revoke storage "+args[0]+" from project "+p, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			err = sdk.Modify(cmd.Context(), c.Projects(), p, func(pr *api.Project) {
				pr.Spec.Storage = slices.DeleteFunc(pr.Spec.Storage, func(x api.ProjectStorage) bool { return x.Storage == args[0] })
			})
			if err != nil {
				return err
			}
			return a.finishOp(cmd.Context(), nil, "storage", args[0], "revoked from project "+p, nil)
		},
	}
	return []*cobra.Command{grant, revoke}
}
