package cli

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

type check struct {
	Name   string `json:"check"`
	Status string `json:"status"` // PASS, INFO, WARN, FAIL
	Detail string `json:"detail"`
}

func (a *app) doctorCmd() *cobra.Command {
	var fix bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check the connection and the server",
		Long: `Run a series of checks and print PASS, WARN or FAIL for each (INFO for a fact the
server reports that is not a fault, such as a setting it stores and does not enforce yet): which
configuration is used, whether the server answers, how it sees you, whether the
API versions and extensions match, and what the host reports about ZFS and PF.
The exit status is 1 when a check failed.

--fix performs the safe cleanups the checks report (the mounts a stop that did not finish left below the root of
a stopped jail) and lists what an earlier network layout left, with the commands that remove it. A jail that runs is
never touched, and the command can be run again. With --dry-run it only lists what it would do.`,
		Example: "jailops doctor\njailops doctor --fix\njailops doctor --fix --dry-run\njailops --remote prod doctor -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			var checks []check
			add := func(n, s, d string) { checks = append(checks, check{n, s, d}) }
			conn, err := a.resolveConnection()
			if err != nil {
				add("configuration", "FAIL", err.Error())
			} else {
				src := []string{}
				for _, k := range sortedKeys(conn.Sources) {
					src = append(src, k+": "+conn.Sources[k])
				}
				name := conn.Name
				if name == "" {
					name = "local"
				}
				add("configuration", "PASS", fmt.Sprintf("remote %s -> %s (%s)", name, conn.describe(), strings.Join(src, "; ")))
				if conn.Host != "" {
					add("host scope", "PASS", "requests go to host "+conn.Host+" through the hub")
				}
				var c *sdk.Client
				if c, err = a.connect(ctx); err != nil {
					if isTransport(err) {
						msg, h := a.unreachable(err)
						add("connection", "FAIL", msg)
						add("hint", "WARN", h)
					} else {
						add("connection", "FAIL", err.Error())
					}
				} else {
					info, ierr := c.Info(ctx)
					if ierr != nil {
						add("connection", "FAIL", ierr.Error())
					} else {
						add("connection", "PASS", fmt.Sprintf("%s, server %s, API %s", info.Hostname, info.Version, info.APIVersion))
						if info.Auth == "trusted" {
							add("authentication", "PASS", "the server trusts this client")
						} else {
							add("authentication", "WARN", "the server sees this client as "+info.Auth+": most calls will be refused")
						}
						if info.APIVersion != api.Version {
							add("api version", "WARN", fmt.Sprintf("server speaks %s, this client %s", info.APIVersion, api.Version))
						} else {
							add("api version", "PASS", info.APIVersion)
						}
						// a feature the server was not given (no backup node, no host module) is not a problem: only what every
						// server of this release has is reported as missing
						var missing []string
						off := 0
						for _, e := range api.Extensions {
							if slices.Contains(info.APIExtensions, e) {
								continue
							}
							if slices.Contains(api.OptionalExtensions, e) {
								off++
								continue
							}
							missing = append(missing, e)
						}
						switch {
						case len(missing) > 0:
							add("extensions", "WARN", "the server lacks: "+strings.Join(missing, ", "))
						case off > 0:
							add("extensions", "PASS", fmt.Sprintf("every extension this server offers is known (%d optional ones are off here: backup, sealed secrets, host modules)", off))
						default:
							add("extensions", "PASS", fmt.Sprintf("all %d known extensions present", len(api.Extensions)))
						}
						env := info.Environment
						if env.Pool == "" {
							add("zfs", "WARN", "the server reports no ZFS pool")
						} else {
							detail := "pool " + env.Pool
							if env.ZFSVersion != "" {
								detail += " (zfs " + env.ZFSVersion + ")"
							}
							add("zfs", "PASS", detail)
						}
						if env.PF {
							add("pf", "PASS", "packet filter available")
						} else {
							add("pf", "WARN", "the server reports no packet filter: firewall policies cannot be applied")
						}
						if _, lerr := collect(c.Operations().List(ctx)); lerr != nil {
							if conn.Project != "" && api.IsCode(lerr, api.CodeNotFound) {
								// the server is fine: the configuration of the client names a project it does not have
								add("project", "WARN", fmt.Sprintf("the project %q (%s) does not exist on this server: %s. List the projects with `jailops project list`, choose another with `jailops project switch NAME` (it is stored in %s)",
									conn.Project, conn.Sources["project"], lerr.Error(), a.userConfigPath()))
							} else {
								add("permissions", "WARN", "cannot list operations: "+lerr.Error())
							}
						} else {
							add("permissions", "PASS", "can read operations")
						}
						if c.Has("doctor") {
							rep, derr := c.Doctor(ctx)
							switch {
							case derr != nil:
								add("server diagnostics", "WARN", "not available: "+derr.Error())
							default:
								for _, sc := range rep.Checks {
									st := map[api.DoctorStatus]string{api.DoctorOK: "PASS", api.DoctorFail: "FAIL", api.DoctorInfo: "INFO"}[sc.Status]
									if st == "" {
										st = "WARN"
									}
									msg := sc.Message
									if sc.Hint != "" && sc.Status != api.DoctorOK {
										msg += " (" + sc.Hint + ")"
									}
									add("server: "+sc.Name, st, msg)
								}
							}
						}
					}
				}
			}
			bad := 0
			for _, c := range checks {
				if c.Status == "FAIL" {
					bad++
				}
			}
			if err := a.emit(checks, stateStyle(1), func() ([]string, [][]string) {
				var rows [][]string
				for _, c := range checks {
					rows = append(rows, []string{c.Name, c.Status, c.Detail})
				}
				return []string{"CHECK", "STATUS", "DETAIL"}, rows
			}, func() []string {
				var n []string
				for _, c := range checks {
					n = append(n, c.Name)
				}
				return n
			}); err != nil {
				return err
			}
			if fix {
				c, cerr := a.connect(ctx)
				if cerr != nil {
					return cerr
				}
				res, ferr := c.DoctorFix(ctx, a.dryRun)
				if ferr != nil {
					return ferr
				}
				if len(res.Actions) == 0 {
					a.say("nothing to clean up\n")
				}
				for _, act := range res.Actions {
					state := "done"
					switch {
					case res.DryRun:
						state = "would do"
					case act.Error != "":
						state = "not done"
					case !act.Done:
						state = "skipped"
					}
					line := fmt.Sprintf("%s: %s: %s", act.Check, state, act.What)
					if act.Error != "" && !res.DryRun {
						line += " (" + act.Error + ")"
					}
					a.say("%s\n", line)
				}
			}
			if bad > 0 {
				return fmt.Errorf("%d check(s) failed", bad)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "perform the safe cleanups the checks report (see the description)")
	return cmd
}

func (a *app) serverCmd() *cobra.Command {
	sc := group("server", "Information about the server", "Commands about the daemon this client is connected to.", "jailops server info", "srv")
	sc.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show the server's version, role, environment and extensions",
		Long: `Show what the server reports about itself: version, role (host or backup node),
whether it is a hub or clustered, how it sees this client, its environment
(operating system, ZFS, pool, PF) and the API extensions it implements.`,
		Example: "jailops server info\njailops --remote prod --host host-b server info -o yaml",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			info, err := c.Info(cmd.Context())
			if err != nil {
				return err
			}
			if a.format != fmtTable {
				return a.emit(info, nil, nil, func() []string { return []string{info.Hostname} })
			}
			w := a.env.Stdout
			kv := func(k string, v any) { fprintf(w, "%-14s %v\n", k+":", v) }
			kv("Hostname", info.Hostname)
			kv("Host UUID", dash(info.HostUUID))
			kv("Version", info.Version)
			kv("API version", info.APIVersion)
			kv("Role", info.Role)
			kv("Hub", yesno(info.Hub))
			kv("Clustered", yesno(info.Clustered))
			kv("Seen as", info.Auth)
			kv("OS", fmt.Sprintf("%s %s (%s)", info.Environment.OS, info.Environment.KernelVersion, info.Environment.Arch))
			kv("ZFS", fmt.Sprintf("%s, pool %s", dash(info.Environment.ZFSVersion), dash(info.Environment.Pool)))
			kv("PF", yesno(info.Environment.PF))
			kv("Linuxulator", yesno(info.Environment.Linuxulator))
			kv("Extensions", strings.Join(info.APIExtensions, ", "))
			return nil
		},
	})
	return sc
}

func (a *app) versionCmd() *cobra.Command {
	var clientOnly bool
	cmd := &cobra.Command{
		Use:     "version",
		Short:   "Print client and server versions",
		Long:    "Print the version of this client, of the SDK and API it speaks and, unless --client is given, of the server it is connected to. An unreachable server is not an error here.",
		Example: "jailops version\njailops version --client -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := map[string]string{"client": a.env.Version, "sdk": sdk.Version, "api": api.Version}
			if !clientOnly {
				if c, err := a.connect(cmd.Context()); err == nil {
					if info, err := c.Info(cmd.Context()); err == nil {
						out["server"] = info.Version
					}
				}
			}
			if a.format != fmtTable {
				return a.emit(out, nil, nil, nil)
			}
			fprintf(a.env.Stdout, "Client:  %s\nSDK:     %s\nAPI:     %s\n", out["client"], out["sdk"], out["api"])
			if !clientOnly {
				fprintf(a.env.Stdout, "Server:  %s\n", dash(out["server"]))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&clientOnly, "client", false, "print client information only; do not contact a server")
	return cmd
}

func (a *app) completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion bash|zsh|fish",
		Short: "Generate a shell completion script",
		Long: `Print a completion script for a shell. Commands and flags complete on their
own; names of jails, images, networks, projects, backups and operations are
completed from the server you are connected to, and when no server answers the
shell simply gets no names.

The packages install the scripts, so a packaged client needs nothing from this
command: /usr/local/share/bash-completion/completions/jailops,
/usr/local/share/zsh/site-functions/_jailops and
/usr/local/share/fish/vendor_completions.d/jailops.fish (bash finds it
by itself with the bash-completion package, and without the package source <(jailops completion bash) does the same;
zsh needs compinit). For a binary installed by hand:

bash:  source <(jailops completion bash)       (or save it under /usr/local/share/bash-completion/completions/jailops)
zsh:   jailops completion zsh > "${fpath[1]}/_jailops"
fish:  jailops completion fish > ~/.config/fish/completions/jailops.fish`,
		Example:   "source <(jailops completion bash)\njailops completion zsh > ~/.zfunc/_jailops",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				script, err := bashCompletionScript(cmd.Root())
				if err != nil {
					return err
				}
				_, err = a.env.Stdout.Write(script)
				return err
			case "zsh":
				return cmd.Root().GenZshCompletion(a.env.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(a.env.Stdout, true)
			}
			return usagef("unknown shell %q (use bash, zsh or fish)", args[0])
		},
	}
}

func (a *app) auditCmd() *cobra.Command {
	var limit int
	var since time.Duration
	var user, action string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show the newest audit log entries of the server",
		Long: `Show who changed what: the newest entries of the server's audit log, newest
first. Every state change is audited with the requestor (user, token name or
certificate fingerprint), the action and the result. Reading the log needs the
admin role.

--limit (default 200, at most 1000), --since and --user are applied by the
server. --action is a pattern matched by this client against the action
("POST /api/v1/jails/{name}/start"; * matches anything, case is ignored): the
server then sends its 1000 newest entries that pass the other filters, and the
client keeps the --limit newest that match.`,
		Example: "jailops audit\njailops audit --limit 50 -o json\njailops audit --since 24h --user alice\njailops audit --action 'DELETE *'",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 0 || limit > 1000 {
				return usagef("--limit must be between 1 and 1000")
			}
			if since < 0 {
				return usagef("--since must be a positive duration such as 24h")
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			if err := c.Require(cmd.Context(), "audit_log"); err != nil {
				return err
			}
			f := sdk.AuditFilter{Limit: limit, Actor: user}
			if since > 0 {
				f.Since = a.env.Now().Add(-since)
			}
			if action != "" {
				f.Limit = 1000
			}
			items, err := c.AuditFiltered(cmd.Context(), f)
			if err != nil {
				return err
			}
			if action != "" {
				kept := items[:0]
				for _, e := range items {
					if globMatch(action, e.Action) {
						kept = append(kept, e)
					}
				}
				items = kept
				keep := limit
				if keep == 0 {
					keep = 200 // the server's default
				}
				if len(items) > keep {
					items = items[:keep]
				}
			}
			a.empty = "No audit entries match."
			return a.emit(nonNil(items), nil, func() ([]string, [][]string) {
				var rows [][]string
				for _, e := range items {
					rows = append(rows, []string{e.Timestamp.UTC().Format("2006-01-02 15:04:05"), e.Requestor, e.Action, dash(e.Resource), dash(e.Result)})
				}
				return []string{"TIME", "REQUESTOR", "ACTION", "RESOURCE", "RESULT"}, rows
			}, func() []string {
				var n []string
				for _, e := range items {
					n = append(n, e.ID)
				}
				return n
			})
		},
	}
	f := cmd.Flags()
	f.IntVar(&limit, "limit", 0, "the number of entries, at most 1000 (default 200)")
	f.DurationVar(&since, "since", 0, "only the entries of this last period, for example 24h")
	f.StringVar(&user, "user", "", "only the entries of this requestor: a user, a token name or a certificate fingerprint")
	f.StringVar(&action, "action", "", "only the actions that match this pattern, for example 'DELETE *' (matched by the client)")
	return cmd
}

// globMatch matches s against a pattern where * is any text and ? one character, ignoring case.
func globMatch(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("(?is)^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(s)
}

// bashEval is the line of the generated bash script that asks the program for the completions.
const bashEval = `    out=$(eval "${requestComp}" 2>/dev/null)`

// bashUnfinishedQuote closes a quote that the word being completed has not closed yet, so that a value typed as
// --from "j<Tab> reaches the program: the script runs the request through eval, which refuses an
// unfinished quote and would complete nothing.
const bashUnfinishedQuote = `    case ${lastParam} in
        \"*) [[ ${#lastParam} -eq 1 || ${lastParam: -1} != \" ]] && requestComp="${requestComp}\"" ;;
        \'*) [[ ${#lastParam} -eq 1 || ${lastParam: -1} != \' ]] && requestComp="${requestComp}'" ;;
    esac
`

// bashFallback brings the two functions of the bash-completion package that the generated script uses, for a host
// that does not have the package: the words of the line with a colon or an equals sign kept inside a word (so that
// jail:web is one word) and the names of files. Where the package is loaded its functions are the ones in use.
const bashFallback = `# The bash-completion package is not needed: these stand in for the two functions of it that are used below.
if ! declare -F _get_comp_words_by_ref >/dev/null 2>&1; then
    _get_comp_words_by_ref()
    {
        local exclude="" __i __j=-1 __w __join=0 __words=() __cword=0 __name
        while [[ $# -gt 0 ]]; do
            case $1 in
                -n) exclude=$2; shift 2 ;;
                -c | -i) shift 2 ;;
                -*) shift ;;
                *) break ;;
            esac
        done
        for ((__i = 0; __i < ${#COMP_WORDS[@]}; __i++)); do
            __w=${COMP_WORDS[__i]}
            if ((__j >= 0)) && [[ -n $exclude ]] && { ((__join)) || [[ -n $__w && $__w != *[!"$exclude"]* ]]; }; then
                __words[__j]+=$__w
            else
                ((__j++))
                __words[__j]=$__w
            fi
            if [[ -n $exclude && -n $__w && $__w != *[!"$exclude"]* ]]; then __join=1; else __join=0; fi
            ((__i == COMP_CWORD)) && __cword=$__j
        done
        for __name in "$@"; do
            case $__name in
                cur) cur=${__words[__cword]} ;;
                prev) prev=""; ((__cword > 0)) && prev=${__words[__cword - 1]} ;;
                words) words=("${__words[@]}") ;;
                cword) cword=$__cword ;;
            esac
        done
    }
fi
if ! declare -F _filedir >/dev/null 2>&1; then
    _filedir()
    {
        local dirsonly=0 filter="" f
        if [[ ${1-} == -d ]]; then dirsonly=1; else filter=${1-}; fi
        COMPREPLY=()
        while IFS= read -r f; do
            if [[ -d $f ]]; then
                COMPREPLY+=("$f/")
            elif ((!dirsonly)) && { [[ -z $filter ]] || [[ $f =~ \.($filter)$ ]]; }; then
                COMPREPLY+=("$f")
            fi
        done < <(compgen -f -- "${cur-}")
    }
fi

`

// bashBeforeDebug is where the fallback goes: before the first function of the generated script.
const bashBeforeDebug = "__jailops_debug()\n{"

// bashCompletionScript is the bash completion script of the command tree, with the unfinished quote of the last word
// closed before the program is asked, and stand-ins for the bash-completion package where it is missing.
func bashCompletionScript(root *cobra.Command) ([]byte, error) {
	var b bytes.Buffer
	if err := root.GenBashCompletionV2(&b, true); err != nil {
		return nil, err
	}
	s := b.String()
	for _, line := range []string{bashEval, bashBeforeDebug} {
		if !strings.Contains(s, line) {
			return nil, fmt.Errorf("the generated bash completion script has no line %q to put the additions before", line)
		}
	}
	s = strings.Replace(s, bashEval, bashUnfinishedQuote+bashEval, 1)
	s = strings.Replace(s, bashBeforeDebug, bashFallback+bashBeforeDebug, 1)
	return []byte(s), nil
}
