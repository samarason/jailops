package cli

import (
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/manpage"
	"jailops.net/jailops/sdk/api"
)

const helpTemplate = `NAME
    {{.CommandPath}} - {{.Short}}

SYNOPSIS
{{- if .Runnable}}
    {{.UseLine}}{{end}}
{{- if .HasAvailableSubCommands}}
    {{.CommandPath}} <command> [flags]{{end}}

DESCRIPTION
{{indent .Long}}
{{- if .HasAvailableSubCommands}}

COMMANDS
{{- range .Commands}}{{if .IsAvailableCommand}}
    {{rpad .Name .NamePadding}}  {{.Short}}{{end}}{{end}}
{{- end}}
{{- if .HasAvailableLocalFlags}}

OPTIONS
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{- end}}
{{- if .HasAvailableInheritedFlags}}

GLOBAL OPTIONS
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}
{{- end}}
{{- if not .HasParent}}

ENVIRONMENT
{{section .Annotations "manpage:environment"}}

EXIT STATUS
{{section .Annotations "manpage:exit-status"}}
{{- end}}
{{- if .HasExample}}

EXAMPLES
{{indent .Example}}
{{- end}}
`

// environment and exitStatus are the ENVIRONMENT and EXIT STATUS of the root help and of every man page: one
// entry per line, the name, a tab, the text.
const environment = `JAILOPS_PROJECT	the project to act in, like --project
JAILOPS_REMOTE	the remote to use, like --remote
JAILOPS_HOST	the host behind a hub, like --host
JAILOPS_URL	the https URL of a daemon, instead of a named remote
JAILOPS_TOKEN	the API token to send
JAILOPS_FINGERPRINT	the SHA-256 fingerprint of the server certificate to pin
JAILOPS_CERT	the client certificate file (mTLS), with JAILOPS_KEY
JAILOPS_KEY	the key file of the client certificate
JAILOPS_CA	the CA bundle that signed the server certificate
JAILOPS_SOCKET	the unix socket of the local daemon (default /var/run/jailops/jailops.sock)
JAILOPS_CONFIG	the user configuration file, like --config
JAILOPS_OUTPUT	the default output format, like -o
JAILOPS_EDITOR	the editor of the edit commands, before VISUAL and EDITOR
NO_COLOR	no colour when set`

const exitStatus = `0	success
1	failure: the daemon cannot be reached, a confirmation was declined, anything else
2	usage error or a request the server found invalid
3	authentication: unauthorized, forbidden, rate limited
4	not found
5	conflict: already exists, changed meanwhile, busy, in use
6	unsupported, or not managed by JailOps on this host
7	internal error of the server
N	jailops exec: the exit status of the command it ran`

// section renders an annotation of name-tab-text lines as an indented two-column list.
func section(ann map[string]string, key string) string {
	var lines []string
	width := 0
	for _, l := range strings.Split(ann[key], "\n") {
		k, _, _ := strings.Cut(l, "\t")
		width = max(width, len(k))
	}
	for _, l := range strings.Split(ann[key], "\n") {
		k, v, _ := strings.Cut(l, "\t")
		lines = append(lines, "    "+k+strings.Repeat(" ", width-len(k)+2)+v)
	}
	return strings.Join(lines, "\n")
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = "    " + l
		}
	}
	return strings.Join(lines, "\n")
}

func (a *app) newRoot() *cobra.Command {
	cobra.AddTemplateFunc("indent", indent)
	cobra.AddTemplateFunc("section", section)
	root := &cobra.Command{
		Annotations: map[string]string{manpage.Environment: environment, manpage.ExitStatus: exitStatus},
		Use:         "jailops",
		Short:       "Manage jails, images, networks and backups",
		Long: `jailops is the command line client of JailOps, a ZFS-native FreeBSD jail platform.
It talks to the jailopsd daemon of this host over its unix socket, or to a remote
daemon or hub over HTTPS with an API token or a client certificate.

Connection settings come, strongest first, from the flags --remote, --host and
--project, the environment (below), the user file ~/.config/jailops/config.yaml,
the host file /usr/local/etc/jailops/client.yaml, and last the default socket
/var/run/jailops/jailops.sock.

Output is a table for people: short, with borders, on a terminal (-o wide shows
every column, -o compact the plain form), plain and one line per row anywhere
else. Use -o json, -o yaml, -o name or -o csv in scripts; -q leaves out the
confirmations such as "jail/web started". Errors
print as "code: message" with a hint on the next line; 'jailops explain CODE' tells
more. -y answers yes/no questions only: deleting a jail or anything else that
destroys data needs the typed name or --confirm-data-loss ('jailops explain'
tells the confirmation flags apart). Colour is used on a terminal only and
NO_COLOR turns it off.`,
		Example: `jailops project create web --new-network
jailops project switch web
jailops jail create web --image freebsd-15-1 --network web --storage default
jailops --remote prod --host host-b jail start web --project web
jailops events --type lifecycle -o json`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			a.started = true
			a.cmdPath = cmd.CommandPath()
			if !cmd.Flag("output").Changed {
				if v := a.env.Getenv("JAILOPS_OUTPUT"); v != "" {
					a.output = v
				}
			}
			f, err := parseFormat(a.output)
			if err != nil {
				a.started = false
				return err
			}
			switch f {
			case fmtWide: // a table like any other, with every column
				f, a.wide = fmtTable, true
			case fmtCompact: // the plain table, on a terminal too
				f, a.compact = fmtTable, true
			}
			a.format = f
			if projectScoped(cmd) {
				if err := a.requireProject(); err != nil {
					a.started = false
					return err
				}
			}
			return nil
		},
	}
	root.SetHelpTemplate(helpTemplate)
	root.CompletionOptions.DisableDefaultCmd = true
	pf := root.PersistentFlags()
	pf.StringVar(&a.remote, "remote", "", "named remote, or an https URL, to talk to (default: the current remote, else the local socket)")
	pf.StringVar(&a.host, "host", "", "scope requests to this host (name or UUID) behind a hub")
	pf.StringVar(&a.project, "project", "", "project to act in (default: JAILOPS_PROJECT, else the current project of the remote chosen with 'project switch'; there is no default project)")
	pf.StringVarP(&a.output, "output", "o", "table", "output format: table, wide, compact, json, yaml, name or csv")
	pf.BoolVar(&a.dryRun, "dry-run", false, "show what would change and send nothing that changes state")
	pf.BoolVar(&a.wait, "wait", true, "wait for asynchronous operations to finish")
	pf.BoolVar(&a.noWait, "no-wait", false, "do not wait; print the operation id")
	pf.DurationVar(&a.timeout, "timeout", 0, "how long to wait for an operation (default 10m)")
	pf.BoolVarP(&a.yes, "yes", "y", false, "answer yes to confirmations (never to data-loss confirmations)")
	pf.StringVar(&a.configPath, "config", "", "user configuration file (default ~/.config/jailops/config.yaml)")
	pf.BoolVar(&a.noHeaders, "no-headers", false, "omit table headers")
	pf.BoolVarP(&a.quiet, "quiet", "q", false, "print no confirmations (errors and requested output still print)")
	enumFlag(root, "output", formatNames...)
	_ = root.RegisterFlagCompletionFunc("project", a.completeProjects())
	_ = root.RegisterFlagCompletionFunc("remote", a.remoteNames())
	_ = root.RegisterFlagCompletionFunc("host", a.completeHosts())
	root.AddCommand(
		a.jailCmd(), a.volumeCmd(), a.imageCmd(), a.appCmd(), a.networkCmd(), a.wireguardCmd(), a.firewallCmd(), a.backupCmd(),
		a.projectCmd(), a.storageCmd(), a.sessionsCmd(), a.whoamiCmd(), a.opCmd(), a.eventsCmd(), a.tokenCmd(), a.certCmd(), a.userCmd(), a.hostCmd(),
		a.remoteCmd(), a.auditCmd(), a.bootCmd(), a.stopAllCmd(), a.doctorCmd(), a.serverCmd(), a.explainCmd(), a.completionCmd(), a.versionCmd(), a.manCmd(),
	)
	a.addJailShortcuts(root)
	root.AddCommand(a.configCmd(), a.profileCmd(), a.updateCmd(), a.setAlias(a.jailDesc()), a.applyCmd())
	markProjectScoped(root)
	expandExamples(root)
	a.finishCompletion(root)
	return root
}

// expandExamples replaces @P@ in examples with the path of the command's
// parent, so shared builders can write examples for any group.
func expandExamples(c *cobra.Command) {
	if c.Example == "@SET@" && c.Parent() != nil {
		c.Example = setExample(strings.TrimPrefix(strings.TrimPrefix(c.Parent().CommandPath(), "jailops"), " "))
	}
	if strings.Contains(c.Example, "@P@") && c.Parent() != nil {
		p := strings.TrimPrefix(c.Parent().CommandPath(), "jailops")
		p = strings.TrimPrefix(p, " ")
		if p == "" {
			c.Example = strings.ReplaceAll(c.Example, "@P@ ", "")
		}
		c.Example = strings.ReplaceAll(c.Example, "@P@", p)
	}
	for _, s := range c.Commands() {
		expandExamples(s)
	}
}

func group(use, short, long, example string, aliases ...string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Long: long, Example: example, Aliases: aliases,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
}

// timeoutSeconds converts a duration to whole seconds, at least 1 when set.
func seconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return max(int(d/time.Second), 1)
}

// projectScopedCommands are the commands that act inside a project. They stop before anything is sent when no
// project was chosen: there is no default project. Host-level commands (images, networks, storage, projects,
// trust, backup targets and keys, the server) are not here.
// 'logs' checks for a project itself: with --all-projects it needs none.
var projectScopedCommands = []string{
	"jail", "create", "delete", "rename", "list", "info", "start", "stop", "restart", "exec", "shell", "label", "provision", "set",
	"firewall", "profile", "update", "config", "backup policy", "backup restore", "app export",
}

const projectAnnotation = "jailops/project"

// markProjectScoped tags the commands above (and everything below them).
func markProjectScoped(root *cobra.Command) {
	for _, path := range projectScopedCommands {
		if c, _, err := root.Find(strings.Fields(path)); err == nil && c != root {
			if c.Annotations == nil {
				c.Annotations = map[string]string{}
			}
			c.Annotations[projectAnnotation] = "required"
		}
	}
	// The list of configuration keys is the same for every project.
	if c, _, err := root.Find([]string{"config", "keys"}); err == nil && c.Name() == "keys" {
		c.Annotations = map[string]string{projectAnnotation: "none"}
	}
}

// projectScoped reports whether cmd (or the group it is in) acts inside a project.
func projectScoped(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Annotations[projectAnnotation] {
		case "none":
			return false
		case "required":
			return true
		}
	}
	return false
}

// requireProject refuses, before anything is sent, a command that needs a project when none was chosen.
func (a *app) requireProject() error {
	conn, err := a.resolveConnection()
	if err != nil {
		return err
	}
	if conn.Project != "" {
		return nil
	}
	return api.Errorf(api.CodeInvalid, "a project is required").
		WithHint("name one with --project NAME or JAILOPS_PROJECT=NAME, or choose one with 'jailops project switch NAME' (list them with 'jailops project list'; create one with 'jailops project create NAME --new-network')")
}
