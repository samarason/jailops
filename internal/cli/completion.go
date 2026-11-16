package cli

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// finishCompletion is the last step of building the command tree. It gives what has no completion of its own the one
// it should have, so that Tab never falls back to the files of the current directory by accident:
//
//   - a command that takes no argument, or a name that does not exist yet, completes nothing;
//   - a flag that names something on the server, a file, a directory or one of a few values completes that, by the name
//     of the flag (flagCompleters) or, where one name means different things, by the path of the command and the flag
//     (flagCompletersFor).
//
// A flag that carries free text (a size, an address, a comment) completes nothing on purpose: completion_audit_test.go
// lists each of them with the reason, and a new flag that is neither completed nor listed there fails the test.
func (a *app) finishCompletion(root *cobra.Command) {
	byName, byPath := a.flagCompleters(), a.flagCompletersFor()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		path := strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
		if c.Runnable() && len(c.Commands()) == 0 && c.ValidArgsFunction == nil && len(c.ValidArgs) == 0 {
			if positionalWords(c.Use) > 0 {
				// an argument that is typed, not chosen: a name of something new, a token, an address
				c.ValidArgsFunction = typedArgument(c)
				if c.Annotations == nil {
					c.Annotations = map[string]string{}
				}
				c.Annotations[typedAnnotation] = "1"
			} else {
				c.ValidArgsFunction = completeNone
			}
		}
		c.NonInheritedFlags().VisitAll(func(f *pflag.Flag) {
			if _, ok := c.GetFlagCompletionFunc(f.Name); ok {
				return
			}
			fn := byPath[path+" --"+f.Name]
			if fn == nil {
				fn = byName[f.Name]
			}
			if fn == nil && (isFreeText(path, f.Name) || isNumberFlag(f)) {
				fn = completeNone // text or a number that is typed: never the files of the directory
			}
			if fn != nil {
				_ = c.RegisterFlagCompletionFunc(f.Name, fn)
			}
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}

// typedAnnotation marks a command whose positional argument is typed by the operator and completes nothing.
const typedAnnotation = "completion.typed"

// isFreeText says whether a flag is listed in freeTextFlags, by the command path and the flag or by the flag alone.
func isFreeText(path, flag string) bool {
	if _, ok := freeTextFlags[path+" --"+flag]; ok {
		return true
	}
	_, ok := freeTextFlags[flag]
	return ok
}

// isNumberFlag says whether a flag takes a number or a duration, which is typed.
func isNumberFlag(f *pflag.Flag) bool {
	switch f.Value.Type() {
	case "int", "int64", "uint", "uint16", "float64", "duration", "intSlice":
		return true
	}
	return false
}

// typedArgument completes nothing for an argument the operator types and says so in one line (cobra's ActiveHelp,
// shown by the shell on the second Tab and switched off with COBRA_ACTIVE_HELP=0): the name of a new object, or the
// word the usage line gives it.
func typedArgument(c *cobra.Command) completer {
	hint := ""
	for _, w := range strings.Fields(c.Use)[1:] {
		if positional.MatchString(w) {
			word := strings.Trim(w, "[]|.")
			if strings.HasPrefix(word, "NAME") {
				noun := "object"
				if p := c.Parent(); p != nil && p.Parent() != nil {
					noun = strings.ReplaceAll(p.Name(), "-", " ")
				} else {
					noun = "jail"
				}
				hint = "a name for the new " + noun
			} else {
				hint = word + " is typed, not chosen"
			}
			break
		}
	}
	return func(_ *cobra.Command, args []string, word string) ([]string, cobra.ShellCompDirective) {
		if hint == "" || len(args) > 0 || word != "" {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return cobra.AppendActiveHelp(nil, hint), cobra.ShellCompDirectiveNoFileComp
	}
}

// flagCompleters are the completions of the flags that mean the same wherever they are used.
func (a *app) flagCompleters() map[string]completer {
	yamlFiles := func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"yaml", "yml", "json"}, cobra.ShellCompDirectiveFilterFileExt
	}
	m := map[string]completer{
		"file":                yamlFiles,
		"passphrase-file":     completeFiles,
		"new-passphrase-file": completeFiles,
		"password-file":       completeFiles,
		"token-file":          completeFiles,
		"cert":                completeFiles,
		"key":                 completeFiles,
		"pem":                 completeFiles,
		"ca":                  completeFiles,
		"config":              completeFiles,
		"path":                completeDirs,
		"dir":                 completeDirs,
		"hosts":               commaList(a.completeHosts()),
		"projects":            commaList(a.completeProjects()),
		"image": a.completeNames(listNames(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Images().List(ctx), func(i api.Image) string { return i.Metadata.Name })
		})),
		"revoke-network": a.completeNames(listNames(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Networks().List(ctx), netName)
		})),
		"revoke-storage": a.completeNames(listNames(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Storage().List(ctx), storName)
		})),
		"jail": completeKind(a, a.jailDesc()),
		"volume": a.completeNames(listNames(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Volumes().List(ctx), func(v api.Volume) string { return v.Metadata.Name })
		})),
		"label":       a.completeLabels(),
		"selector":    a.completeLabels(),
		"tag":         a.completeTags(),
		"shell":       fixedValues(shells...),
		"prompt":      fixedValues("default", "short", "none"),
		"default-in":  fixedValues("allow", "deny"),
		"default-out": fixedValues("allow", "deny"),
		"icmp-type":   fixedValues(icmpTypes...),
	}
	return m
}

// flagCompletersFor are the completions of a flag whose name means different things in different commands, keyed by
// the command path (without the program name), a space and the flag.
func (a *app) flagCompletersFor() map[string]completer {
	return map[string]completer{
		"audit --user": a.completeNames(listNames(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Users().List(ctx), func(u api.User) string { return u.Metadata.Name })
		})),
		"app export --to":    completeFiles,
		"cert create --kind": fixedValues("client", "host", "backup"),
		"cert set --kind":    fixedValues("client", "host", "backup"),
	}
}

// completionTimeout is how long a completion waits for the server: a shell is waiting.
const completionTimeout = 3 * time.Second

// shells are the login shells that are usual in a jail; the setting names the path inside the jail.
var shells = []string{"/bin/sh", "/bin/csh", "/bin/tcsh", "/usr/local/bin/bash", "/usr/local/bin/zsh", "/usr/local/bin/fish"}

// icmpTypes are the ICMP and ICMPv6 types as pf names them.
var icmpTypes = []string{
	"echoreq", "echorep", "unreach", "timex", "paramprob", "squench", "redir", "routeradv", "routersol",
	"neighbradv", "neighbrsol", "toobig", "listqry", "listenrep", "listendone",
}

func fixedValues(values ...string) completer {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeDirs offers directories only.
func completeDirs(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

// commaList completes a flag whose value is a comma separated list: the last element is completed and what comes
// before it is kept, and no space follows so that the next element can be added.
func commaList(one completer) completer {
	return func(cmd *cobra.Command, args []string, p string) ([]string, cobra.ShellCompDirective) {
		head := ""
		if i := strings.LastIndex(p, ","); i >= 0 {
			head, p = p[:i+1], p[i+1:]
		}
		names, dir := one(cmd, args, p)
		var out []string
		for _, n := range names {
			name, _, _ := strings.Cut(n, "\t")
			if strings.HasPrefix(name, p) && !strings.Contains(","+head, ","+name+",") {
				out = append(out, head+n)
			}
		}
		return out, dir | cobra.ShellCompDirectiveNoSpace
	}
}

// completeLabels completes KEY=VALUE for the labels the jails of the project carry: the keys first, then the values
// that exist for the key.
func (a *app) completeLabels() completer {
	return func(cmd *cobra.Command, _ []string, p string) ([]string, cobra.ShellCompDirective) {
		jails, ok := a.completionJails(cmd)
		if !ok {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		key, val, hasValue := strings.Cut(p, "=")
		seen := map[string]bool{}
		var out []string
		for _, j := range jails {
			for k, v := range j.Metadata.Labels {
				switch {
				case !hasValue:
					if strings.HasPrefix(k, key) && !seen[k] {
						seen[k] = true
						out = append(out, k+"=")
					}
				case k == key && strings.HasPrefix(v, val) && !seen[v]:
					seen[v] = true
					out = append(out, key+"="+v)
				}
			}
		}
		sort.Strings(out)
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}

// completeTags completes the firewall tags that jails of the project already carry.
func (a *app) completeTags() completer {
	return func(cmd *cobra.Command, _ []string, p string) ([]string, cobra.ShellCompDirective) {
		jails, ok := a.completionJails(cmd)
		if !ok {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		seen := map[string]bool{}
		var out []string
		for _, j := range jails {
			for _, t := range j.Spec.Firewall.Tags {
				if strings.HasPrefix(t, p) && !seen[t] {
					seen[t] = true
					out = append(out, t)
				}
			}
		}
		sort.Strings(out)
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// completionJails lists the jails of the project for a completion; a shell is waiting, so a server that is slow or
// answers with an error yields nothing.
func (a *app) completionJails(cmd *cobra.Command) ([]api.Jail, bool) {
	ctx, cancel := context.WithTimeout(cmd.Context(), completionTimeout)
	defer cancel()
	c, err := a.connect(ctx)
	if err != nil {
		return nil, false
	}
	jails, err := collect(c.Jails().List(ctx))
	return jails, err == nil
}

// configValues completes the value of a configuration key of a jail from what the key is: true and false for a
// switch, the values of a choice, the names of the objects a key refers to. ok is false for a key whose value is free.
func (a *app) configValues(key string) (completer, bool) {
	k, found := configKeyOf(key)
	if !found {
		return nil, false
	}
	switch {
	case k.Type == "bool":
		return fixedValues("true", "false"), true
	case k.Type == "enum" && len(k.Values) > 0:
		return fixedValues(k.Values...), true
	}
	names := func(list func(ctx context.Context, c *sdk.Client) iterNames) completer {
		return a.completeNames(listNames(list))
	}
	switch strings.NewReplacer("<device>", "*", "<name>", "*", "<var>", "*").Replace(k.Name) {
	case "nic.*.network":
		return names(func(ctx context.Context, c *sdk.Client) iterNames { return namesOf(c.Networks().List(ctx), netName) }), true
	case "storage":
		return names(func(ctx context.Context, c *sdk.Client) iterNames { return namesOf(c.Storage().List(ctx), storName) }), true
	case "image":
		return names(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Images().List(ctx), func(i api.Image) string { return i.Metadata.Name })
		}), true
	case "profiles":
		return commaList(names(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Profiles().List(ctx), func(p api.Profile) string { return p.Metadata.Name })
		})), true
	case "boot.depends":
		return commaList(completeKind(a, a.jailDesc())), true
	case "firewall.policies":
		return commaList(names(func(ctx context.Context, c *sdk.Client) iterNames {
			return namesOf(c.Firewall().Policies().List(ctx), func(p api.FirewallPolicy) string { return p.Metadata.Name })
		})), true
	case "firewall.tags":
		return commaList(a.completeTags()), true
	case "prompt":
		return fixedValues("default", "short", "none"), true
	case "shell":
		return fixedValues(shells...), true
	case "nic.*.ipv4", "nic.*.ipv6":
		return fixedValues("auto"), true
	case "disk.*.mount":
		return nil, false
	}
	return nil, false
}

// configKeyOf finds the registry entry of a key; "<device>", "<name>" and "<var>" in the registry match any one
// name.
func configKeyOf(key string) (api.ConfigKey, bool) {
	parts := strings.Split(key, ".")
	for _, k := range api.ConfigKeys() {
		want := strings.Split(k.Name, ".")
		if len(want) != len(parts) {
			continue
		}
		match := true
		for i := range want {
			if !strings.HasPrefix(want[i], "<") && want[i] != parts[i] {
				match = false
				break
			}
		}
		if match {
			return k, true
		}
	}
	return api.ConfigKey{}, false
}

// freeTextFlags are the flags that carry text the operator makes up, with why nothing can be completed: they complete
// nothing and never the files of the directory. A key is a flag name (every command) or "command path --flag".
var freeTextFlags = map[string]string{
	"action":                           "an audit action is matched as typed",
	"address":                          "an address or an endpoint the operator types",
	"alias":                            "the name of a new alias",
	"member":                           "an address or a prefix the operator types",
	"allow-from":                       "a network in CIDR form",
	"allowed-ips":                      "networks in CIDR form",
	"as":                               "the name the restored jail is given: new",
	"at":                               "a time of day",
	"comment":                          "free text",
	"confirm-within":                   "a duration typed as text",
	"console-from":                     "addresses typed by the operator",
	"dataset":                          "the API lists no ZFS datasets of the host",
	"db":                               "a database of the app, made by the install",
	"default-host":                     "the host of a hub, as the remote knows it",
	"disk":                             "a size",
	"directory":                        "the URL of an ACME directory",
	"dns":                              "addresses of resolvers",
	"domain":                           "DNS names",
	"email":                            "an address",
	"endpoint":                         "host:port of a WireGuard peer",
	"env":                              "KEY=VALUE typed by the operator",
	"exclude":                          "addresses kept out of a range",
	"fingerprint":                      "a certificate fingerprint pasted from elsewhere",
	"gateway":                          "an address",
	"grace":                            "a duration typed as text",
	"grep":                             "a pattern",
	"host-uuid":                        "a UUID pasted from elsewhere",
	"upgrade-at":                       "a time of day, HH:MM",
	"url":                              "a URL typed or pasted",
	"package-set":                      "the name of a package set",
	"hostname":                         "a name",
	"interface":                        "the name of a new interface",
	"ipv4":                             "an address",
	"ipv6":                             "a prefix",
	"keys":                             "a path inside the image's source",
	"map":                              "OLD=NEW of two networks, typed",
	"max-memory":                       "a size",
	"memory":                           "a size",
	"message":                          "free text",
	"mode":                             "an octal mode",
	"name":                             "the name of something new",
	"nameserver":                       "addresses of resolvers",
	"ntp-server":                       "servers by name or address",
	"package":                          "package names of a source that is not on the server",
	"pool":                             "addresses of a range",
	"port":                             "port numbers",
	"project create --firewall-policy": "the project does not exist yet, so it has no policies to name",
	"range":                            "an address range",
	"recipient":                        "an age public key pasted from elsewhere",
	"release":                          "a release name of the image's source",
	"repo":                             "a repository URL",
	"schedule":                         "a schedule written as text",
	"search":                           "DNS search domains",
	"service":                          "service names of an app being written",
	"set":                              "KEY=VALUE typed by the operator",
	"since":                            "a duration or a time typed as text",
	"since-id":                         "an event or log id pasted from output",
	"size":                             "a size",
	"ssh-from":                         "addresses typed by the operator",
	"subnet":                           "a prefix",
	"token":                            "a secret pasted from elsewhere",
	"update-window":                    "a time window written as text",
	"uplink":                           "the API lists no network interfaces of the host",
	"user":                             "a user of the jail (exec, shell, console): the jail's /etc/passwd is not read from here",
	"verify-schedule":                  "a schedule written as text",
}

// positionalWords counts the positional arguments a usage line names: the words after the command name that are not
// flags and begin with a capital letter (NAME, [PATTERN...], BACKUP).
var positional = regexp.MustCompile(`^\[?[A-Z]`)

func positionalWords(use string) int {
	n := 0
	words := strings.Fields(use)
	for i := 1; i < len(words); i++ {
		w := words[i]
		if strings.HasPrefix(w, "-") || strings.HasPrefix(w, "[-") {
			// a flag, and the word after it that is its value
			if i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") && !strings.HasPrefix(words[i+1], "[") && !strings.Contains(w, "]") {
				i++
			}
			continue
		}
		if positional.MatchString(w) {
			n++
		}
	}
	return n
}
