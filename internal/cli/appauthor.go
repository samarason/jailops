package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/apps"
	"jailops.net/jailops/sdk/api"
)

// Writing app definitions (docs/apps.md, "Write your own app"): 'app new'
// writes a commented starter offline, 'app export' asks the server for a
// draft made from a running jail. Both write a file that parses and
// validates, with TODO markers that 'app validate' lists until they are
// replaced.

// appNewReport is the -o json and -o yaml answer of app new.
type appNewReport struct {
	File string `json:"file"`
	// Icon is the icon file; IconWritten is false when one was there already.
	Icon        string `json:"icon"`
	IconWritten bool   `json:"icon_written"`
	// Todo are the lines that hold a TODO marker.
	Todo []int `json:"todo"`
}

func (a *app) appNew() *cobra.Command {
	var packages, services, ports []string
	var category, dir string
	var force bool
	cmd := &cobra.Command{
		Use:   "new NAME",
		Short: "Write a starter definition for a new app, offline",
		Long: `Write DIR/NAME.yaml, a starter app definition with every key of the format,
a short comment on each that says what it does and what usually goes wrong, and
TODO markers where you have to decide. The flags fill in what you already know:
the packages, the rc.d services, the ports (N, N/tcp or N/udp) and the category.
No server is needed.

The file parses and validates as it is, so it can be installed while you work
on it; 'jailops app validate' reports each line that still holds a TODO
marker, and a definition is ready for the packages repository when it reports
nothing. NAME.svg, a neutral placeholder icon, is written next to it unless an
icon of that name is there. An existing NAME.yaml is not overwritten without
--overwrite.

To try it on a FreeBSD host, copy both files into /usr/local/etc/jailops/apps
(apps.local_dir) and run 'jailops app install NAME'. docs/apps.md, "Write your
own app", has the whole loop.`,
		Example: `jailops app new memcached --package memcached --service memcached --port 11211/tcp --category database
jailops app new mysite --package nginx --service nginx --port 80 --port 443 --dir ./apps
jailops app new tool`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if a.format != fmtTable && a.format != fmtJSON && a.format != fmtYAML {
				return usagef("app new prints a table, json or yaml")
			}
			name := args[0]
			d, err := apps.Starter(apps.StarterOptions{Name: name, Packages: packages, Services: services, Ports: ports, Category: category})
			if err != nil {
				return usagef("%v", err)
			}
			if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
				return api.Errorf(api.CodeNotFound, "directory %s does not exist", dir).WithHint("create it, or name another with --dir")
			}
			file := filepath.Join(dir, name+".yaml")
			if _, err := os.Lstat(file); err == nil && !force {
				return api.Errorf(api.CodeAlreadyExists, "%s exists", file).WithHint("keep it, or write over it with --overwrite")
			}
			data := d.YAML()
			if err := os.WriteFile(file, data, 0o644); err != nil {
				return err
			}
			rep := appNewReport{File: file, Icon: filepath.Join(dir, d.App.Icon), Todo: apps.TodoLines(data)}
			if _, err := os.Lstat(rep.Icon); errors.Is(err, fs.ErrNotExist) {
				if err := os.WriteFile(rep.Icon, apps.StarterIcon(name), 0o644); err != nil {
					return err
				}
				rep.IconWritten = true
			}
			if a.format != fmtTable {
				return a.emit(rep, nil, nil, nil)
			}
			icon := rep.Icon + " (a placeholder icon)"
			if !rep.IconWritten {
				icon = rep.Icon + " (there already)"
			}
			a.say("Wrote %s with %d line(s) marked TODO, and %s.\n", file, len(rep.Todo), icon)
			a.say("Next:\n")
			a.say("  1. Fill in each line marked TODO; 'jailops app validate %s' lists the ones left.\n", file)
			a.say("  2. On a FreeBSD host, copy both files into %s and run 'jailops app install %s'.\n", apps.DefaultLocalDir, name)
			a.say("  3. Send them to the packages repository (main/jailops-apps/apps/): docs/apps.md, \"Write your own app\".\n")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&packages, "package", nil, "package to install, from the FreeBSD repository (repeat, or separate with commas)")
	f.StringSliceVar(&services, "service", nil, "rc.d service to enable and start, in start order (repeat, or separate with commas)")
	f.StringSliceVar(&ports, "port", nil, "port the app listens on: N, N/tcp or N/udp (repeat, or separate with commas)")
	f.StringVar(&category, "category", "", "category: "+strings.Join(appCategoryNames(), ", "))
	f.StringVar(&dir, "dir", ".", "directory to write NAME.yaml and NAME.svg into")
	f.BoolVar(&force, "overwrite", false, "write over an existing NAME.yaml")
	enumFlag(cmd, "category", appCategoryNames()...)
	_ = cmd.MarkFlagDirname("dir")
	return cmd
}

func (a *app) appExport() *cobra.Command {
	var out string
	var force bool
	cmd := &cobra.Command{
		Use:   "export JAIL",
		Short: "Draft an app definition from a running jail",
		Long: `Ask the server to draft an app definition from a running FreeBSD jail of the
project, one you set up by hand until the app worked, and write it as a
commented definition to FILE (--to) or to the standard output. -o json and
-o yaml print the server's draft as data instead (the definition with its
TODO list), for programs.

The draft holds what the jail shows: the packages installed on purpose (their
dependencies come with them), the services enabled in its rc.conf and their
knobs, the ports something listens on now, the jail's volumes as data paths,
the names of the files below /usr/local/etc and /var/log changed after the
packages were installed, and setup lines that give the app's directories the
owners they have in the jail. It leaves out what belongs to the base system
(sshd, syslogd, cron...). It never holds a secret: configuration files are
listed by name and never read, and an rc.conf knob whose name looks like a
secret is written as TODO. The comment at the top says what was found and what
was left out.

What a jail cannot tell (the summary, the description, the license, the health
check to trust, the notes) is marked TODO; 'jailops app validate' lists each
marked line until it is replaced. Nothing in the jail changes; the server runs
read-only commands in it, which needs the operator role.

The file is named after the jail: write it as JAIL.yaml, or change name: to
match the file name.`,
		Example: `jailops app export cache --file cache.yaml
jailops app export web --project shop
jailops app export cache --file ./apps/cache.yaml --overwrite
jailops app export cache -o json`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, a.jailDesc()),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if a.format != fmtTable && a.format != fmtJSON && a.format != fmtYAML {
				return usagef("-o %s is not available here: the draft is YAML (the default), -o json or -o yaml", a.format)
			}
			if out != "" && out != "-" && !force {
				if _, err := os.Lstat(out); err == nil {
					return api.Errorf(api.CodeAlreadyExists, "%s exists", out).WithHint("keep it, or write over it with --overwrite")
				}
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			d, err := c.Jails().AppDraft(ctx, args[0])
			if err != nil {
				return err
			}
			if a.format != fmtTable && out == "" {
				return a.emit(d, nil, nil, nil)
			}
			data := apps.Draft{App: d.Definition, Todo: d.Todo, Header: apps.ExportHeader(d)}.YAML()
			if out == "" || out == "-" {
				_, err := a.env.Stdout.Write(data)
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			a.say("Wrote %s, drafted from jail %s, with %d line(s) marked TODO.\n", out, args[0], len(apps.TodoLines(data)))
			if want := d.Definition.Name + ".yaml"; filepath.Base(out) != want {
				a.say("The definition is named %s: rename the file to %s, or change name: to match the file name.\n", d.Definition.Name, want)
			}
			a.say("Next: fill in the marked lines and run 'jailops app validate %s'.\n", out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "file", "f", "", "file to write the definition to (default: the standard output)")
	cmd.Flags().BoolVar(&force, "overwrite", false, "write over an existing FILE")
	_ = cmd.MarkFlagFilename("file", "yaml", "yml")
	return cmd
}
