package cli

import (
	"context"
	"fmt"
	"io"
	"iter"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// appCategoryNames are the values of --category, for completion and checks.
func appCategoryNames() []string {
	var out []string
	for _, c := range api.AppCategories {
		out = append(out, string(c))
	}
	return out
}

// appDesc describes the catalog to the generic list: a read-only kind whose
// name is the app name.
func appDesc() *kindDesc[api.AppSummary] {
	d := kindDesc[api.AppSummary]{noun: "app", plural: "apps",
		meta: func(s *api.AppSummary) *api.ObjectMeta { return &api.ObjectMeta{Name: s.Name} }}
	d.list = func(ctx context.Context, c *sdk.Client, _ ...sdk.ListOption) iter.Seq2[api.AppSummary, error] {
		return func(yield func(api.AppSummary, error) bool) {
			items, err := c.Apps().List(ctx)
			if err != nil {
				yield(api.AppSummary{}, err)
				return
			}
			for _, it := range items {
				if !yield(it, nil) {
					return
				}
			}
		}
	}
	d.head = []string{"NAME", "CATEGORY", "VERSION", "SOURCE", "STATUS", "SUMMARY"}
	d.row = func(_ time.Time, s api.AppSummary) []string {
		status, text := "valid", s.Summary
		if !s.Valid {
			status, text = "invalid", s.Error
		}
		return []string{s.Name, dash(string(s.Category)), dash(s.Version), appSource(s.Source, s.Overrides), status, dash(text)}
	}
	d.brief = &listView[api.AppSummary]{head: []string{"NAME", "CATEGORY", "SUMMARY"}, drop: []int{1},
		row: func(_ time.Time, s api.AppSummary) []string {
			text := s.Summary
			if !s.Valid {
				text = "invalid: " + s.Error
			}
			if s.Source == api.AppSourceLocal {
				text = "(local) " + text
			}
			return []string{s.Name, dash(string(s.Category)), dash(text)}
		}}
	d.filters = func(cmd *cobra.Command) func() (func(api.AppSummary) bool, error) {
		var category, source string
		sources := []string{string(api.AppSourceCatalog), string(api.AppSourceLocal)}
		cmd.Flags().StringVar(&category, "category", "", "only apps of this category: "+strings.Join(appCategoryNames(), ", "))
		cmd.Flags().StringVar(&source, "source", "", "only apps read from this directory: catalog (the jailops-apps package) or local (apps.local_dir)")
		enumFlag(cmd, "category", appCategoryNames()...)
		enumFlag(cmd, "source", sources...)
		return func() (func(api.AppSummary) bool, error) {
			if category != "" && !slices.Contains(appCategoryNames(), category) {
				return nil, usagef("unknown category %q (categories: %s)", category, strings.Join(appCategoryNames(), ", "))
			}
			if source != "" && !slices.Contains(sources, source) {
				return nil, usagef("unknown source %q (sources: %s)", source, strings.Join(sources, ", "))
			}
			if category == "" && source == "" {
				return nil, nil
			}
			return func(s api.AppSummary) bool {
				return (category == "" || string(s.Category) == category) && (source == "" || string(s.Source) == source)
			}, nil
		}
	}
	return &d
}

// appSource says where a definition was read from, for a person.
func appSource(src, overrides api.AppSource) string {
	switch {
	case src == "":
		return "-"
	case overrides != "":
		return string(src) + ", overrides " + string(overrides)
	}
	return string(src)
}

func (a *app) appCmd() *cobra.Command {
	d := appDesc()
	ac := group("app", "Browse the application catalog and install apps",
		`The application catalog describes jails that run one or more packages from the
FreeBSD repository or the JailOps repository: which packages, which services,
which ports, where the data, the configuration and the logs live, and how to
check that it runs. The catalog is a set of local files on the host, installed
by the jailops-apps package (/usr/local/share/jailops/apps), and the host's own
definitions in /usr/local/etc/jailops/apps (apps.local_dir), which win over a
packaged one of the same name; the daemon never fetches anything. A definition
that does not validate is listed as invalid with the reason. See docs/apps.md
for the format.

'install' creates a jail that runs an app, as one operation; 'installed' lists
the jails that came from the catalog. An installed app is closed to every
source until 'allow' lets one in; 'deny' takes it back and 'access' shows who
may connect. 'new' writes a starter definition and
'export' drafts one from a running jail; 'validate' checks definition files on
this machine, without a server.`,
		`jailops app list
jailops app list --category database
jailops app list --source local
jailops app info postgresql
jailops app install nginx --project web
jailops app installed --project web
jailops app new memcached --package memcached --service memcached --port 11211/tcp
jailops app export cache --file cache.yaml
jailops app validate ./apps
jailops app allow db --from jail:web
jailops app access db`, "apps")
	addList(a, ac, d, "\njailops app list --category database\njailops app list --source local")
	ac.AddCommand(a.appInfo(d), a.appInstall(d), a.appInstalled(), a.appValidate(), a.appNew(), a.appExport(),
		a.appAllow(), a.appDeny(), a.appAccessCmd())
	return ac
}

// appValidateReport is the -o json and -o yaml answer of app validate.
type appValidateReport struct {
	Definitions int            `json:"definitions"`
	Icons       int            `json:"icons"`
	Problems    []apps.Problem `json:"problems"`
}

func (a *app) appValidate() *cobra.Command {
	return &cobra.Command{
		Use:   "validate PATH...",
		Short: "Check catalog definitions offline, with the daemon's rules",
		Long: `Check app definitions as the daemon reads them, on this machine: no server,
no network and no root are needed. A PATH is a catalog directory (every *.yaml
in it, as 'app list' reads them) or one definition file. Each definition is
parsed and validated with the daemon's own code, and the icon it names must be
next to it and readable.

Every problem is printed as FILE: reason. The exit status is 2 when there is
one, 0 with a one-line summary otherwise. -o json and -o yaml print the counts
and the problems.`,
		Example: "jailops app validate /usr/local/share/jailops/apps\njailops app validate main/jailops-apps/apps -o json\njailops app validate nginx.yaml postgresql.yaml",
		Args:    cobra.MinimumNArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if a.format != fmtTable && a.format != fmtJSON && a.format != fmtYAML {
				return usagef("app validate prints a table, json or yaml")
			}
			rep := appValidateReport{Problems: []apps.Problem{}}
			for _, p := range args {
				r := apps.Check(p)
				rep.Definitions += r.Definitions
				rep.Icons += r.Icons
				rep.Problems = append(rep.Problems, r.Problems...)
			}
			if a.format != fmtTable {
				if err := a.emit(rep, nil, nil, nil); err != nil {
					return err
				}
			} else {
				for _, p := range rep.Problems {
					fprintf(a.env.Stdout, "%s: %s\n", p.File, p.Reason)
				}
				if len(rep.Problems) == 0 {
					fprintf(a.env.Stdout, "valid: %d definition(s), %d icon(s)\n", rep.Definitions, rep.Icons)
				}
			}
			if n := len(rep.Problems); n > 0 {
				return api.Errorf(api.CodeInvalid, "%d problem(s) in %d definition(s) checked", n, rep.Definitions).
					WithHint("fix the files listed and run 'jailops app validate' again; docs/apps.md has the format")
			}
			return nil
		},
	}
}

func (a *app) appInfo(d *kindDesc[api.AppSummary]) *cobra.Command {
	return &cobra.Command{
		Use:   "info NAME",
		Short: "Describe one app of the catalog",
		Long: `Print the definition of one app for a person: what it is, its packages and
services, the ports it listens on and whether the installer exposes them, its
data paths, configuration files and logs, the setup commands, the health
check, the resource hints and the notes shown after an installation. -o json
and -o yaml print the definition with the hash of its file. An invalid
definition is an error that says what is wrong with it.`,
		Example:           "jailops app info postgresql\njailops app info postgresql -o yaml",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			det, err := c.Apps().Get(ctx, args[0])
			if err != nil {
				return err
			}
			if a.format != fmtTable {
				return a.emit(det, nil, nil, func() []string { return []string{det.Definition.Name} })
			}
			a.printAppInfo(a.env.Stdout, det)
			return nil
		},
	}
}

// printAppInfo writes the human report of one definition.
func (a *app) printAppInfo(w io.Writer, det api.AppDetail) {
	d := det.Definition
	kv := func(k string, v any) { fprintf(w, "  %-11s %v\n", k+":", v) }
	section := func(title string) { fprintf(w, "\n%s\n", title) }
	// table prints aligned columns under a section, two spaces in.
	table := func(rows [][]string) {
		width := map[int]int{}
		for _, r := range rows {
			for i, c := range r {
				width[i] = max(width[i], len(c))
			}
		}
		for _, r := range rows {
			var b strings.Builder
			b.WriteString(" ")
			for i, c := range r {
				b.WriteString(" " + c)
				if i < len(r)-1 {
					b.WriteString(strings.Repeat(" ", width[i]-len(c)+1))
				}
			}
			fprintln(w, strings.TrimRight(b.String(), " "))
		}
	}
	yes := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}

	fprintf(w, "App %s: %s\n", d.Name, d.Title)
	kv("Summary", d.Summary)
	kv("Category", d.Category)
	kv("License", dash(d.License))
	kv("Homepage", dash(d.Homepage))
	kv("Image", fmt.Sprintf("FreeBSD %s or later, thin jail", d.Image.ReleaseMin))
	kv("File", fmt.Sprintf("%s (%s)", det.File, det.Hash))
	if det.Source == api.AppSourceLocal {
		src := "local (the host's apps.local_dir)"
		if det.Overrides != "" {
			src += "; it overrides the catalog's definition of the same name"
		}
		kv("Source", src)
	} else if det.Source != "" {
		kv("Source", string(det.Source))
	}
	if det.Icon != "" {
		kv("Icon", d.Icon)
	}
	if d.Description != "" {
		section("Description")
		for _, l := range strings.Split(strings.TrimRight(d.Description, "\n"), "\n") {
			if l == "" {
				fprintln(w)
			} else {
				fprintln(w, "  "+l)
			}
		}
	}

	section("Packages")
	var rows [][]string
	for _, p := range d.Packages {
		rows = append(rows, []string{p.Name, p.Repo, dash(p.Version)})
	}
	table(rows)

	section("Services")
	if len(d.Services) == 0 {
		fprintln(w, "  none")
	}
	rows = nil
	for _, s := range d.Services {
		start := "started after the installation"
		if s.Start != nil && !*s.Start {
			start = "enabled, not started"
		}
		var knobs []string
		for _, k := range sortedKeys(s.RC) {
			knobs = append(knobs, k+"="+s.RC[k])
		}
		rc := "rc.conf: " + s.Name + "_enable=YES"
		if len(knobs) > 0 {
			rc += ", " + strings.Join(knobs, ", ")
		}
		rows = append(rows, []string{s.Name, start, rc})
	}
	table(rows)

	section("Ports")
	if len(d.Ports) == 0 {
		fprintln(w, "  none")
	} else {
		rows = [][]string{{"NAME", "PORT", "EXPOSED", "DESCRIPTION"}}
		for _, p := range d.Ports {
			rows = append(rows, []string{p.Name, strconv.Itoa(p.Port) + "/" + p.Proto, yes(p.Expose), dash(p.Description)})
		}
		table(rows)
	}

	section("Data")
	if len(d.Data) == 0 {
		fprintln(w, "  none")
	}
	rows = nil
	for _, p := range d.Data {
		rows = append(rows, []string{p.Path, dash(p.Description)})
	}
	table(rows)

	section("Configuration")
	if len(d.Config) == 0 {
		fprintln(w, "  none")
	}
	rows = nil
	for _, c := range d.Config {
		restart := "no restart"
		if c.Restart != "" {
			restart = "restart " + c.Restart
		}
		rows = append(rows, []string{c.Path, restart, dash(c.Description)})
	}
	table(rows)

	section("Logs")
	if len(d.Logs) == 0 {
		fprintln(w, "  none")
	}
	rows = nil
	for _, l := range d.Logs {
		rows = append(rows, []string{l.Name, l.Path, dash(l.Description)})
	}
	table(rows)

	if len(d.Setup) > 0 {
		section("Setup")
		for _, argv := range d.Setup {
			fprintln(w, "  "+strings.Join(argv, " "))
		}
	}

	section("Health")
	switch h := d.Health; {
	case h == nil:
		fprintln(w, "  none declared: the services must report running")
	case h.TCP != 0:
		fprintf(w, "  tcp port %d answers, within %ds\n", h.TCP, h.WaitSeconds)
	case h.HTTP != nil:
		fprintf(w, "  http port %d %s answers %d, within %ds\n", h.HTTP.Port, h.HTTP.Path, h.HTTP.Status, h.WaitSeconds)
	default:
		fprintf(w, "  %s exits 0, within %ds\n", strings.Join(h.Exec, " "), h.WaitSeconds)
	}

	if ac := d.Access; ac != nil {
		section("Access")
		fprintf(w, "  %s: jailops app allow makes a role and a database per grant and a line in %s (port %s, service %s)\n", ac.Type, ac.HBAFile, ac.Port, ac.Service)
	}

	var hints []string
	if d.Resources.Memory != "" {
		hints = append(hints, "memory "+d.Resources.Memory)
	}
	if d.Resources.Disk != "" {
		hints = append(hints, "disk "+d.Resources.Disk)
	}
	if d.Resources.CPU != "" {
		hints = append(hints, "cpu "+d.Resources.CPU)
	}
	if len(hints) > 0 {
		section("Resources")
		fprintln(w, "  "+strings.Join(hints, ", ")+" (hints, not limits)")
	}

	if d.Notes != "" {
		section("Notes")
		for _, l := range strings.Split(strings.TrimRight(d.Notes, "\n"), "\n") {
			if l == "" {
				fprintln(w)
			} else {
				fprintln(w, "  "+l)
			}
		}
	}
}
