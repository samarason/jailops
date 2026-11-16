package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// completeConfigKeys completes keys from the registry in sdk/api. Keys with a
// <device> or <name> placeholder complete up to the placeholder.
func completeConfigKeys(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, k := range api.ConfigKeys() {
		if strings.HasPrefix(k.Name, prefix) {
			out = append(out, k.Name+"\t"+k.Description)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

func (a *app) completeJailThenKeys(d *kindDesc[api.Jail]) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	names := completeKind(a, d)
	return func(cmd *cobra.Command, args []string, p string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return names(cmd, args, p)
		}
		return completeConfigKeys(cmd, args, p)
	}
}

// completeJailKeysValues completes the arguments of config set: the jail, then keys, then the value of the key just
// given (KEY VALUE or KEY=VALUE): true and false for a switch, the values of a choice, the names of what the key
// refers to (a network, a storage, policies, profiles, jails); a comma separated value completes its last element.
func (a *app) completeJailKeysValues(d *kindDesc[api.Jail]) completer {
	keys := a.completeJailThenKeys(d)
	return func(cmd *cobra.Command, args []string, p string) ([]string, cobra.ShellCompDirective) {
		key, prefix := "", ""
		switch {
		case len(args) >= 2 && !strings.Contains(args[len(args)-1], "=") && (len(args)-1)%2 == 1:
			key = args[len(args)-1] // KEY VALUE pairs: the value of the key before this word
		case strings.Contains(p, "="):
			k, _, _ := strings.Cut(p, "=")
			key, prefix, p = k, k+"=", strings.TrimPrefix(p, k+"=")
		}
		if key == "" {
			return keys(cmd, args, p)
		}
		values, ok := a.configValues(key)
		if !ok {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names, dir := values(cmd, nil, p)
		out := make([]string, 0, len(names))
		for _, n := range names {
			if name, _, _ := strings.Cut(n, "\t"); strings.HasPrefix(name, p) || strings.Contains(name, ",") {
				out = append(out, prefix+n)
			}
		}
		return out, dir
	}
}

type configRow struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

func (a *app) configCmd() *cobra.Command {
	d := a.jailDesc()
	cc := group("config", "Show and change the configuration keys of a jail",
		`Configuration keys are dotted names such as limits.memory, boot.autostart,
nic.eth0.mtu or shell. Each maps to one field of the jail specification; the
registry of keys, with types, validation and whether a change needs a restart,
is part of the SDK, so the CLI, the web interface and the daemon agree.
'config keys' lists them.

Changing a key updates the desired state and the daemon enforces it. When a
change needs a restart the command says which keys; it never restarts a jail
unless you pass --restart.`,
		`jailops config show nginx
jailops config set nginx limits.memory 2G limits.cpu 2
jailops config get nginx limits.memory
jailops config unset nginx limits.cpu
jailops config show nginx --expanded`)
	cc.AddCommand(a.configShow(d), a.configGet(d), a.configSet(d, false), a.configSet(d, true), a.configEdit(d), a.configKeys())
	return cc
}

func (a *app) configKeys() *cobra.Command {
	return &cobra.Command{
		Use:   "keys [PREFIX]",
		Short: "List the configuration keys that exist",
		Long: `List every key of the registry with its type, whether a change needs a restart
and what it means. A PREFIX such as nic or limits narrows the list. <device>
and <name> stand for the name of a device.`,
		Example:           "jailops config keys\njailops config keys limits",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeConfigKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			var keys []api.ConfigKey
			for _, k := range api.ConfigKeys() {
				if len(args) == 0 || strings.HasPrefix(k.Name, args[0]) {
					keys = append(keys, k)
				}
			}
			return a.emit(nonNil(keys), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, k := range keys {
					rr := "no"
					if k.RestartRequired {
						rr = "yes"
					}
					rows = append(rows, []string{k.Name, k.Type, rr, k.Description})
				}
				return []string{"KEY", "TYPE", "RESTART", "DESCRIPTION"}, rows
			}, func() []string {
				var n []string
				for _, k := range keys {
					n = append(n, k.Name)
				}
				return n
			})
		},
	}
}

func (a *app) configShow(d *kindDesc[api.Jail]) *cobra.Command {
	var expanded bool
	cmd := &cobra.Command{
		Use:   "show NAME",
		Short: "Show the configuration keys of a jail",
		Long: `Show every key that is set on a jail with its value. With --expanded the
profiles the jail lists are merged in and a SOURCE column says where each value
came from: the jail itself or a profile; the jail's own keys win.`,
		Example:           "jailops config show nginx\njailops config show nginx --expanded -o yaml",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			var vals, src map[string]string
			if expanded {
				ex, err := c.Jails().Expanded(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				vals, src = api.ConfigValues(ex.Jail.Spec), ex.Sources
			} else {
				j, err := c.Jails().Get(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				vals = api.ConfigValues(j.Spec)
			}
			rows := sortedRows(vals, src, expanded)
			return a.emit(rows, nil, func() ([]string, [][]string) {
				var out [][]string
				for _, r := range rows {
					row := []string{r.Key, r.Value}
					if expanded {
						row = append(row, r.Source)
					}
					out = append(out, row)
				}
				if expanded {
					return []string{"KEY", "VALUE", "SOURCE"}, out
				}
				return []string{"KEY", "VALUE"}, out
			}, func() []string {
				var n []string
				for _, r := range rows {
					n = append(n, r.Key)
				}
				return n
			})
		},
	}
	cmd.Flags().BoolVar(&expanded, "expanded", false, "merge the jail's profiles and show where each value comes from")
	return cmd
}

func sortedRows(vals, src map[string]string, expanded bool) []configRow {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([]configRow, 0, len(keys))
	for _, k := range keys {
		r := configRow{Key: k, Value: vals[k]}
		if expanded {
			r.Source = dash(src[k])
		}
		rows = append(rows, r)
	}
	return rows
}

func (a *app) configGet(d *kindDesc[api.Jail]) *cobra.Command {
	return &cobra.Command{
		Use:               "get NAME KEY",
		Short:             "Print the value of one configuration key",
		Long:              "Print the value of one key of a jail, alone on a line, so a script can capture it. A key that is valid but not set is an error (exit status 4).",
		Example:           "jailops config get nginx limits.memory",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: a.completeJailThenKeys(d),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkKey(args[1]); err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			j, err := c.Jails().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			v, ok := api.ConfigValues(j.Spec)[canonicalKey(args[1])]
			if !ok {
				return api.Errorf(api.CodeNotFound, "key %q is not set on jail %q", args[1], args[0]).WithHint("'jailops config show " + args[0] + "' lists the keys that are set")
			}
			if a.format != fmtTable {
				return a.emit(configRow{Key: args[1], Value: v}, nil, nil, func() []string { return []string{args[1]} })
			}
			fprintln(a.env.Stdout, v)
			return nil
		},
	}
}

func canonicalKey(k string) string {
	if rest, ok := strings.CutPrefix(k, "network."); ok {
		return "nic." + rest
	}
	return k
}

func checkKey(k string) error {
	if _, _, ok := api.ConfigKeyFor(k); !ok {
		return usagef("%q is not a configuration key (see 'jailops config keys')", k)
	}
	return nil
}

// previewConfig applies a change to a copy of the jail, to validate it and
// to learn which keys would need a restart, without sending anything.
func (a *app) previewConfig(ctx context.Context, c *sdk.Client, name string, set map[string]string, unset []string) ([]string, error) {
	j, err := c.Jails().Get(ctx, name)
	if err != nil {
		return nil, err
	}
	return api.ApplyConfig(&j.Spec, set, unset)
}

// changeConfig sends the change. The server stores it atomically and never
// restarts the jail unless restart is true.
func (a *app) changeConfig(ctx context.Context, c *sdk.Client, name string, set map[string]string, unset []string, restart bool) error {
	h, err := handle(c.Jails().Config(ctx, name, set, unset, restart))
	if err != nil {
		return err
	}
	if !a.waiting() {
		return a.finishOp(ctx, h, "jail", name, "configured", nil)
	}
	v, _, err := a.await(ctx, h)
	if err != nil {
		return err
	}
	res, _ := v.(sdk.ConfigResult)
	if a.format != fmtTable {
		out := map[string]any{"jail": name, "restart_required": nonNil(res.RestartRequired), "restarted": res.Restarted, "config": api.ConfigValues(res.Jail.Spec)}
		if w := res.Jail.Status.Warnings; len(w) > 0 {
			out["warnings"] = w
		}
		return a.emit(out, nil, nil, func() []string { return []string{name} })
	}
	fprintf(a.env.Stdout, "jail/%s configuration updated\n", name)
	for _, w := range res.Jail.Status.Warnings {
		fprintf(a.env.Stderr, "warning: %s\n", w)
	}
	switch {
	case len(res.RestartRequired) == 0:
	case res.Restarted:
		fprintf(a.env.Stdout, "jail/%s restarted to apply: %s\n", name, strings.Join(res.RestartRequired, ", "))
	default:
		fprintf(a.env.Stdout, "restart required for: %s\n", strings.Join(res.RestartRequired, ", "))
		fprintf(a.env.Stdout, "the jail was not restarted: run 'jailops restart %s' when it suits you, or repeat with --restart\n", name)
	}
	return nil
}

func (a *app) configSet(d *kindDesc[api.Jail], unset bool) *cobra.Command {
	var restart bool
	use, short := "set NAME KEY VALUE [KEY VALUE]...", "Set configuration keys of a jail"
	long := `Set one or more keys. Pairs may be written KEY VALUE or KEY=VALUE. The whole
change is validated first and applied atomically, with the ETag read at the
start, so nothing is half done. Device keys add devices: 'nic.eth1.network lan'
creates the nic eth1.

If a changed key needs a restart the command lists the keys and does NOT restart
the jail; --restart restarts it (if it is running) once the change is stored.`
	example := "jailops config set nginx limits.memory 2G limits.cpu 2\njailops config set nginx nic.eth0.ipv4=auto --restart\njailops config set nginx shell /usr/local/bin/bash"
	if unset {
		use, short = "unset NAME KEY...", "Remove configuration keys of a jail"
		long = `Reset keys to their defaults. Unsetting a device key such as nic.eth1 removes
the device. Restart handling is the same as for 'config set'.`
		example = "jailops config unset nginx limits.cpu\njailops config unset nginx nic.eth1 --restart"
	}
	valuesOrKeys := a.completeJailThenKeys(d)
	if !unset {
		valuesOrKeys = a.completeJailKeysValues(d)
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Long: long, Example: example,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: valuesOrKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runConfigChange(cmd, args[0], args[1:], unset, restart)
		},
	}
	cmd.Flags().BoolVar(&restart, "restart", false, "restart the jail afterwards if the change needs it (never done otherwise)")
	return cmd
}

func parsePairs(args []string) (map[string]string, error) {
	set := map[string]string{}
	for i := 0; i < len(args); i++ {
		k, v, ok := strings.Cut(args[i], "=")
		if !ok {
			if i+1 >= len(args) {
				return nil, usagef("key %q has no value: write KEY VALUE or KEY=VALUE", args[i])
			}
			i++
			v = args[i]
		}
		if err := checkKey(k); err != nil {
			return nil, err
		}
		set[k] = v
	}
	return set, nil
}

func (a *app) runConfigChange(cmd *cobra.Command, name string, rest []string, unset, doRestart bool) error {
	var set map[string]string
	var un []string
	if unset {
		for _, k := range rest {
			if err := checkKey(k); err != nil {
				return err
			}
			un = append(un, k)
		}
	} else {
		var err error
		if set, err = parsePairs(rest); err != nil {
			return err
		}
	}
	ctx := cmd.Context()
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	if a.dryRun {
		restart, err := a.previewConfig(ctx, c, name, set, un)
		if err != nil {
			return err
		}
		req := map[string]any{"restart_required": nonNil(restart)}
		if len(set) > 0 {
			req["set"] = set
		}
		if len(un) > 0 {
			req["unset"] = un
		}
		_, err = a.dry("update the configuration of jail "+name, req)
		return err
	}
	return a.changeConfig(ctx, c, name, set, un, doRestart)
}

func (a *app) configEdit(d *kindDesc[api.Jail]) *cobra.Command {
	var restart bool
	cmd := &cobra.Command{
		Use:   "edit NAME",
		Short: "Edit the configuration keys of a jail in your editor",
		Long: `Open the keys that are set on a jail as a flat YAML map (key: value) in
$JAILOPS_EDITOR, $VISUAL or $EDITOR. Changed values are set, deleted lines are
unset, new lines are added, all as one validated change. No change or an empty
file cancels. Restart handling is the same as for 'config set'.`,
		Example:           "EDITOR=nano jailops config edit nginx",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			j, err := c.Jails().Get(ctx, name)
			if err != nil {
				return err
			}
			before := api.ConfigValues(j.Spec)
			raw, err := toYAML(before)
			if err != nil {
				return err
			}
			f, err := os.CreateTemp("", "jailops-config-"+name+"-*.yaml")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			_, _ = f.WriteString("# Configuration keys of jail " + name + ". Delete a line to unset a key.\n" + string(raw))
			_ = f.Close()
			argv := a.editorArgv()
			ec := exec.CommandContext(ctx, argv[0], append(argv[1:], f.Name())...)
			ec.Stdin, ec.Stdout, ec.Stderr = a.env.Stdin, a.env.Stdout, a.env.Stderr
			if err := ec.Run(); err != nil {
				return fmt.Errorf("editor %q failed: %w", argv[0], err)
			}
			b, err := os.ReadFile(f.Name())
			if err != nil {
				return err
			}
			after := map[string]string{}
			if err := yaml.Unmarshal(b, &after); err != nil {
				return usagef("invalid YAML: %v", err)
			}
			if len(after) == 0 {
				fprintln(a.env.Stderr, "Edit cancelled: the file is empty.")
				return nil
			}
			set := map[string]string{}
			var un []string
			for k, v := range after {
				if err := checkKey(k); err != nil {
					return err
				}
				if before[k] != v {
					set[k] = v
				}
			}
			for k := range before {
				if _, ok := after[k]; !ok {
					un = append(un, k)
				}
			}
			sort.Strings(un)
			if len(set) == 0 && len(un) == 0 {
				fprintf(a.env.Stdout, "jail/%s unchanged\n", name)
				return nil
			}
			if ok, err := a.dry("update the configuration of jail "+name, map[string]any{"set": set, "unset": un}); ok || err != nil {
				return err
			}
			return a.changeConfig(ctx, c, name, set, un, restart)
		},
	}
	cmd.Flags().BoolVar(&restart, "restart", false, "restart the jail afterwards if the change needs it")
	return cmd
}

// setAlias is 'jailops set NAME KEY VALUE', the short form of 'config set'.
func (a *app) setAlias(d *kindDesc[api.Jail]) *cobra.Command {
	cmd := a.configSet(d, false)
	cmd.Short = "Set configuration keys of a jail (short for config set)"
	cmd.Example = "jailops set nginx shell /usr/local/bin/bash\njailops set nginx limits.memory 2G --restart"
	return cmd
}

func profileDesc() *kindDesc[api.Profile] {
	d := newDesc("profile", "profiles", api.KindProfile,
		func(p *api.Profile) *api.ObjectMeta { return &p.Metadata },
		func(p *api.Profile) *api.ProfileSpec { return &p.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Profile] { return c.Profiles() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Profile] { return c.Profiles() })
	d.renameLong = renameLong("profile", `the jails that apply it (for a host profile, --project host, the
jails of every project that has no profile of that name)`)
	d.head = []string{"NAME", "KEYS", "COMMENT"}
	d.row = func(_ time.Time, p api.Profile) []string {
		return []string{p.Metadata.Name, strconv.Itoa(len(p.Spec.Config)), dash(p.Spec.Comment)}
	}
	return &d
}

func (a *app) profileCmd() *cobra.Command {
	d := profileDesc()
	pc := group("profile", "Manage reusable sets of configuration keys",
		`A profile is a named set of configuration keys and devices (limits, devices,
boot policy). A jail lists profiles in order ('jailops create --profile base
--profile web'); later ones override earlier ones and the jail's own keys
override all of them, device by device. 'jailops config show NAME --expanded'
shows the merged result and where each value came from.

Profiles belong to the current project. With --project host they are
host-level profiles, visible to every project and written only by global
admins.`,
		"jailops profile list\njailops profile create web-limits --set limits.memory=2G --set limits.cpu=2\njailops profile show web-limits", "profiles")
	crudCommands(a, pc, d, "Create a profile from keys given with --set, or from a file. Only keys that the registry allows in profiles are accepted ('jailops config keys' shows them).",
		"jailops profile create web-limits --set limits.memory=2G --set limits.cpu=2\njailops profile create base -f base.yaml --project host",
		func(cmd *cobra.Command) func(string) (api.Profile, error) {
			var desc string
			var sets []string
			cmd.Flags().StringVar(&desc, "comment", "", "what the profile is for")
			cmd.Flags().StringArrayVar(&sets, "set", nil, "a key, KEY=VALUE (repeatable)")
			_ = cmd.RegisterFlagCompletionFunc("set", completeConfigKeys)
			return func(name string) (api.Profile, error) {
				cfg := map[string]string{}
				for _, s := range sets {
					k, v, ok := strings.Cut(s, "=")
					if !ok {
						return api.Profile{}, usagef("--set %q must be KEY=VALUE", s)
					}
					if err := checkKey(k); err != nil {
						return api.Profile{}, err
					}
					cfg[k] = v
				}
				return api.Profile{Metadata: api.ObjectMeta{Name: name}, Spec: api.ProfileSpec{Comment: desc, Config: cfg}}, nil
			}
		})
	return pc
}
