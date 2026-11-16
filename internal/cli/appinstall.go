package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

func (a *app) appInstall(d *kindDesc[api.AppSummary]) *cobra.Command {
	var jail, network, storage, image, memory, disk string
	var cpu int
	cmd := &cobra.Command{
		Use:   "install APP [JAIL]",
		Short: "Install an app of the catalog as a new jail",
		Long: `Create a jail that runs an app of the catalog, as one operation on the server:
a thin jail from the image with the app's data paths as persistent datasets,
started, the packages installed from the host with pkg -r, the services enabled
in rc.conf, the setup commands and the services run in the jail, the health
check, and a snapshot named app-installed of the fresh installation. The jail
carries the labels jailops.app, jailops.app.hash and jailops.app.version.

The image is the one --image names, such as freebsd-15-1 (its newest
generation). Without it the server takes the FreeBSD image of the highest
release the host runs, the first by name when two have that release; when
there is none it refuses and says how to create one.

The jail is named after the app unless JAIL is given, and goes into the
project of the request; --network and --storage name what it is created with
(the project's only grant of a kind is the default). --memory, --disk and --cpu
replace the definition's resource hints as the jail's limits.

A failure before the jail's first start deletes the jail again; a failure after
it (a package that does not install, a health check that does not pass) leaves
the jail stopped for inspection, with its labels, and the error says so.
--dry-run asks the server for the steps and creates nothing. After a
successful installation the report says how to reach the app, where its data,
configuration and logs are, and the notes of the definition. The new jail is
closed: its firewall policy app-JAIL lets nothing in until 'jailops app allow
JAIL --from SOURCE' allows a source (the health check runs before it closes).
Ports marked expose in the definition are listed; forwarding them is a later
feature.`,
		Example: `jailops app install nginx --project web
jailops app install postgresql db --project web --network lan --storage default
jailops app install nginx --project web --image freebsd-15-1 --memory 512M
jailops app install nginx --project web --dry-run`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: completeArgs(completeKind(a, d), completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) == 2 {
				jail = args[1]
			}
			req := api.AppInstall{Jail: jail, Network: network, Storage: storage, Image: image, DryRun: a.dryRun}
			if cmd.Flags().Changed("memory") || cmd.Flags().Changed("disk") || cmd.Flags().Changed("cpu") {
				req.Limits = &api.Resources{Memory: memory, Disk: disk, CPU: cpu}
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := handle(c.Apps().Install(ctx, args[0], req))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(ctx, h, "app", args[0], "installing", nil)
			}
			v, _, err := a.await(ctx, h)
			if err != nil {
				return err
			}
			res, _ := v.(api.AppInstallResult)
			if a.format != fmtTable {
				return a.emit(res, nil, nil, func() []string { return []string{res.Jail.Metadata.Name} })
			}
			a.printAppInstalled(a.env.Stdout, args[0], req.Jail, res)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&network, "network", "", "network the jail is attached to, one granted to the project (default: the project's only network)")
	f.StringVar(&storage, "storage", "", "storage the jail is created on, one granted to the project (default: the project's only storage)")
	f.StringVar(&image, "image", "", "image reference, NAME or NAME#gN (default: the FreeBSD image of the highest release the host runs); its release must be at least the app's release_min")
	f.StringVar(&memory, "memory", "", "memory limit, for example 512M (replaces the definition's hints)")
	f.StringVar(&disk, "disk", "", "disk quota, for example 10G (replaces the definition's hints)")
	f.IntVar(&cpu, "cpu", 0, "CPU limit in cores (replaces the definition's hints)")
	a.completeFlag(cmd, "network", listNames(func(ctx context.Context, c *sdk.Client) iterNames { return namesOf(c.Networks().List(ctx), netName) }))
	a.completeFlag(cmd, "storage", listNames(func(ctx context.Context, c *sdk.Client) iterNames { return namesOf(c.Storage().List(ctx), storName) }))
	a.completeFlag(cmd, "image", imageRefs)
	return cmd
}

// printAppInstalled writes the report of an installation, or the steps of a
// dry run.
func (a *app) printAppInstalled(w io.Writer, name, jail string, res api.AppInstallResult) {
	if jail == "" {
		jail = name
	}
	if res.DryRun {
		fprintf(w, "Dry run: nothing was created. Installing app %s as jail %s would do:\n", name, jail)
		for _, s := range res.Steps {
			fprintln(w, "  "+s)
		}
		return
	}
	j := res.Jail
	kv := func(k string, v string) { fprintf(w, "  %-10s %s\n", k+":", v) }
	fprintf(w, "App %s installed as jail %s (%s)\n", res.App, j.Metadata.Name, dash(string(j.Status.Power)))
	kv("Version", dash(res.Version))
	kv("Addresses", dash(strings.Join(res.Addresses, ", ")))
	if len(res.Ports) == 0 {
		kv("Ports", "none")
	}
	for i, p := range res.Ports {
		k := ""
		if i == 0 {
			k = "Ports:"
		}
		line := fmt.Sprintf("%s %d/%s", p.Name, p.Port, p.Proto)
		if p.Endpoint != "" {
			line += " at " + p.Endpoint
		}
		if p.Expose {
			line += " (expose: forwarding is not set up yet)"
		}
		if p.Description != "" {
			line += " " + p.Description
		}
		fprintf(w, "  %-10s %s\n", k, line)
	}
	if len(res.Ports) > 0 {
		kv("Access", "closed: nothing reaches it until jailops app allow "+j.Metadata.Name+" --from SOURCE")
	}
	listed := func(k string, rows []string) {
		if len(rows) == 0 {
			kv(k, "none")
			return
		}
		for i, r := range rows {
			if i == 0 {
				kv(k, r)
			} else {
				fprintf(w, "  %-10s %s\n", "", r)
			}
		}
	}
	var rows []string
	for _, d := range res.Data {
		rows = append(rows, strings.TrimSpace(d.Path+" "+d.Description))
	}
	listed("Data", rows)
	rows = nil
	for _, c := range res.Config {
		r := c.Path
		if c.Restart != "" {
			r += " (restart " + c.Restart + ")"
		}
		rows = append(rows, strings.TrimSpace(r+" "+c.Description))
	}
	listed("Config", rows)
	rows = nil
	for _, l := range res.Logs {
		rows = append(rows, strings.TrimSpace(l.Name+" "+l.Path+" "+l.Description))
	}
	listed("Logs", rows)
	if res.Snapshot != "" {
		kv("Snapshot", res.Snapshot+" (jailops jail rollback "+j.Metadata.Name+" --all --snapshot "+res.Snapshot+" goes back to it)")
	}
	kv("Steps", strconv.Itoa(len(res.Steps))+" done")
	if res.Notes != "" {
		fprintln(w, "Notes:")
		for _, l := range strings.Split(strings.TrimRight(res.Notes, "\n"), "\n") {
			if l == "" {
				fprintln(w)
			} else {
				fprintln(w, "  "+l)
			}
		}
	}
}

// installedApp is one row of 'app installed'.
type installedApp struct {
	api.Jail
	// App and Version are the labels of the installation.
	App     string `json:"app"`
	Version string `json:"version,omitempty"`
	// Ports are the ports of the definition as the catalog has it now
	// ("port/proto"); empty when the definition is gone or invalid.
	Ports []string `json:"ports,omitempty"`
}

func (a *app) appInstalled() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "installed [PATTERN...]",
		Short: "List the jails that run an app of the catalog",
		Long: `List the jails of the project that an app installation created: those with the
label jailops.app. The columns are the jail, the app and the version that was
installed (the labels), the state and addresses of the jail, and the ports of
the app's definition as the catalog has it now. Name patterns such as 'web*'
narrow the list. -o json and -o yaml print the jails with the app, version and
ports; -o name prints the jail names.`,
		Example: "jailops app installed --project web\njailops app installed --project web -o json",
		Args:    cobra.ArbitraryArgs,
		ValidArgsFunction: a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
			jails, err := c.Apps().Installed(ctx)
			var n []string
			for _, j := range jails {
				n = append(n, j.Metadata.Name)
			}
			return n, err
		}),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			jails, err := c.Apps().Installed(ctx)
			if err != nil {
				return err
			}
			defs := map[string][]string{}
			items := []installedApp{}
			for _, j := range jails {
				if !matchesAny(args, j.Metadata.Name) {
					continue
				}
				name := j.Metadata.Labels[api.LabelApp]
				if _, ok := defs[name]; !ok {
					var ports []string
					if det, err := c.Apps().Get(ctx, name); err == nil {
						for _, p := range det.Definition.Ports {
							ports = append(ports, strconv.Itoa(p.Port)+"/"+p.Proto)
						}
					}
					defs[name] = ports
				}
				items = append(items, installedApp{Jail: j, App: name, Version: j.Metadata.Labels[api.LabelAppVersion], Ports: defs[name]})
			}
			return a.emitList(items, stateStyle(3), func() ([]string, [][]string) {
				var rows [][]string
				for _, it := range items {
					var addrs []string
					for _, n := range it.Spec.Network {
						for _, ad := range []string{n.IPv4, n.IPv6} {
							if x := fixedAddr(ad); x != "" {
								addrs = append(addrs, x)
							}
						}
					}
					rows = append(rows, []string{it.Metadata.Name, it.App, dash(it.Version), dash(string(it.Status.Power)), linesOrDash(addrs), dash(strings.Join(it.Ports, ","))})
				}
				return []string{"JAIL", "APP", "VERSION", "STATE", "ADDRESSES", "PORTS"}, rows
			}, nil, func() []string {
				var n []string
				for _, it := range items {
					n = append(n, it.Metadata.Name)
				}
				return n
			})
		},
	}
	return cmd
}
