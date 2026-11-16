package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
)

type remoteRow struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
	Target  string `json:"target"`
	Auth    string `json:"auth"`
	Host    string `json:"host,omitempty"`
	Source  string `json:"source"`
}

func authSummary(r RemoteConfig) string {
	var p []string
	if r.Token != "" || r.TokenFile != "" {
		p = append(p, "token")
	}
	if r.Cert != "" {
		p = append(p, "mtls")
	}
	if r.Fingerprint != "" {
		p = append(p, "pinned")
	}
	if r.CA != "" {
		p = append(p, "ca")
	}
	if len(p) == 0 {
		if r.URL == "" {
			return "root only"
		}
		return "none"
	}
	return strings.Join(p, "+")
}

func (a *app) remoteCmd() *cobra.Command {
	rc := group("remote", "Manage the daemons this client connects to",
		`A remote is a named daemon or hub: an HTTPS URL with a token or a client
certificate, pinned by certificate fingerprint when it is self-signed. They
are kept in ~/.config/jailops/config.yaml (mode 0600). The built-in remote
"local" is the unix socket of this host.

(To manage the hosts behind a hub, see 'jailops host'.)`,
		`jailops remote add prod https://hub.example.net:39110 --token-file -
jailops remote add myhost host.example.org --token-file -
jailops remote list
jailops remote switch prod
jailops remote remove old`, "remotes")
	rc.AddCommand(a.remoteAdd(), a.remoteList(), a.remoteRemove(), a.remoteSwitch())
	return rc
}

func (a *app) remoteAdd() *cobra.Command {
	var r RemoteConfig
	var sw bool
	cmd := &cobra.Command{
		Use:   "add NAME ADDRESS",
		Short: "Add a remote",
		Long: `Add a named remote. ADDRESS is host or host:port (the default port is 39110), https://host:port, or
unix:/path for a socket.

With a trust token (joc_..., made by 'jailops cert enroll') the command joins the server: it pins the server
fingerprint carried by the token (there is no trust-on-first-use prompt), generates a client key pair (the key is stored
with mode 0600 next to the configuration), presents the token and the certificate, and saves the remote with the
certificate in place of an API token.

With an API token, or none, the remote is saved as it is. If the server's certificate is not signed by a trusted
authority, the command connects once, shows the certificate's SHA-256 fingerprint and asks whether to pin it. Compare
it with the fingerprint reported by the server before you answer yes. -y does not answer this question. If you
already know the fingerprint, pass --fingerprint: the command checks it against what the server presents and refuses
on a mismatch.

The token is read from --token, from the first line of standard input with --token-file -, or
referenced by file with --token-file (an API token: the path is stored, not the token). Prefer standard input or a
file: a value on the command line is visible to other users.`,
		Example: `jailops remote add myhost host.example.org --token-file - <trust-token.txt
jailops remote add prod https://hub.example.net:39110 --token-file - <token.txt
jailops remote add lab https://10.0.0.5:39110 --fingerprint ab:cd:ef:... --token-file ~/.jailops-lab
jailops remote add edge https://edge:39110 --cert client.pem --key client.key --switch`,
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeNone,
		RunE: func(cmd *cobra.Command, args []string) error {
			if r.TokenFile == "-" { // standard input
				line, err := a.readLine()
				if err != nil || line == "" {
					return usagef("--token-file - needs the token on the first line of standard input")
				}
				r.TokenFile, r.Token = "", line
			}
			name, target := args[0], args[1]
			if name == "local" || strings.Contains(name, "://") || name == "" {
				return usagef("%q is not a valid remote name", name)
			}
			if r.TokenFile != "" && r.Token == "" {
				// a trust token in a file joins; for an API token the path is stored, not the token
				if tok, err := a.readSecretFile("token", r.TokenFile); err == nil && strings.HasPrefix(tok, sdk.TrustTokenPrefix) {
					r.Token, r.TokenFile = tok, ""
				}
			}
			if strings.HasPrefix(r.Token, sdk.TrustTokenPrefix) {
				return a.addByTrustToken(cmd, name, target, r.Token, sw)
			}
			if sock, ok := strings.CutPrefix(target, "unix:"); ok {
				r.Socket = sock
			} else {
				r.URL = target
			}
			if r.URL != "" && !strings.Contains(r.URL, "://") {
				u, err := normalizeAddress(r.URL)
				if err != nil {
					return err
				}
				r.URL = u
			}
			if r.URL != "" && strings.HasPrefix(r.URL, "https://") && r.CA == "" {
				if err := a.pinCertificate(cmd.Context(), name, &r); err != nil {
					return err
				}
			}
			if ok, err := a.dry("add remote "+name+" for "+target, nil); ok || err != nil {
				return err
			}
			path := a.userConfigPath()
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			if cfg.Remotes == nil {
				cfg.Remotes = map[string]RemoteConfig{}
			}
			cfg.Remotes[name] = r
			current := false
			if sw || cfg.Current == "" {
				cfg.Current, current = name, true
			}
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			msg := "remote/" + name + " added"
			if current {
				msg += " (now the current remote)"
			}
			a.say("%s\n", msg)
			a.probeRemote(cmd.Context(), r)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&r.Token, "token", "", "API token or trust token (visible in the process list; prefer --token-file -)")
	f.StringVar(&r.TokenFile, "token-file", "", "file holding the token; the path is stored, not the token (- reads the first line of standard input)")
	f.StringVar(&r.Fingerprint, "fingerprint", "", "SHA-256 fingerprint of the server certificate to pin")
	f.StringVar(&r.Cert, "cert", "", "client certificate file for mTLS")
	f.StringVar(&r.Key, "key", "", "client key file for mTLS")
	f.StringVar(&r.CA, "ca", "", "CA bundle that signed the server certificate")
	f.StringVar(&r.Host, "default-host", "", "scope every request to this host behind a hub")
	f.BoolVar(&sw, "switch", false, "make this the current remote (default when none is set)")
	return cmd
}

// pinCertificate decides how the server's certificate is trusted: by the
// system roots, by a fingerprint the user supplied and that matches, or by a
// fingerprint the user confirmed after seeing it.
func (a *app) pinCertificate(ctx context.Context, name string, r *RemoteConfig) error {
	hp, err := hostPort(r.URL)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	probe, err := a.env.ProbeCert(pctx, hp)
	if err != nil {
		return fmt.Errorf("cannot reach %s to read its certificate: %w", hp, err)
	}
	got := sdk.Fingerprint(probe.Cert)
	if r.Fingerprint != "" {
		want := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(r.Fingerprint), "sha256:"), ":", ""))
		if want != got {
			return &hintError{
				err:  fmt.Errorf("the certificate of %s does not match the fingerprint you gave\n  expected: %s\n  presented: %s", hp, colonFP(want), colonFP(got)),
				hint: "do not pin it unless you know why it changed; ask the server's administrator"}
		}
		r.Fingerprint = got
		return nil
	}
	if probe.Trusted {
		return nil // a trusted authority signed it; no pin needed
	}
	w := a.env.Stderr
	// The fingerprint comes first, on its own line; the subject and issuer are the server's text and are quoted, so
	// that no character of theirs can paint over the fingerprint or the question.
	fprintf(w, "The server at %s presented a certificate that no trusted authority signed.\n", hp)
	fprintf(w, "  SHA-256:  %s\n", colonFP(got))
	fprintf(w, "  Subject:  %q\n  Issuer:   %q\n  Expires:  %s\n",
		probe.Cert.Subject.String(), probe.Cert.Issuer.String(), probe.Cert.NotAfter.UTC().Format("2006-01-02"))
	fprintln(w, "Compare this fingerprint with the one the server reports ('jailops server info' there) before trusting it.")
	fprintf(w, "Pin this certificate for remote %q? [y/N]: ", name)
	ans, err := a.readLine()
	if err != nil {
		return &usageError{err: errNotConfirmed, hint: "answer on standard input, or pass --fingerprint after checking it with the server's administrator"}
	}
	if s := strings.ToLower(ans); s != "y" && s != "yes" {
		return &abortError{"the certificate was not trusted; the remote was not added"}
	}
	r.Fingerprint = got
	return nil
}

// probeRemote tries the new remote once and reports the result.
func (a *app) probeRemote(ctx context.Context, r RemoteConfig) {
	conn := &Connection{URL: r.URL, Socket: r.Socket, Token: r.Token, Fingerprint: r.Fingerprint, Cert: r.Cert, Key: r.Key, CA: r.CA}
	if r.TokenFile != "" && conn.Token == "" {
		return
	}
	opts, err := conn.sdkOptions()
	if err != nil {
		fprintf(a.env.Stderr, "warning: %v\n", err)
		return
	}
	opts = append(opts, a.env.SDKOptions...)
	target := sdk.Local(sdk.WithSocket(conn.Socket))
	if conn.URL != "" {
		target = sdk.Remote(conn.URL)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cl, err := sdk.Connect(cctx, target, opts...)
	if err != nil {
		fprintf(a.env.Stderr, "warning: saved, but the server could not be reached: %v\n", err)
		return
	}
	defer cl.Close()
	info, err := cl.Info(cctx)
	if err != nil {
		return
	}
	if info.Hostname == "" {
		// a server tells a client it does not trust neither its name nor its version
		a.say("connected, seen as %s\n", info.Auth)
		return
	}
	a.say("connected to %s (version %s), seen as %s\n", info.Hostname, info.Version, info.Auth)
}

func (a *app) remoteList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List configured remotes",
		Long:    "List the remotes of the user and host configuration files and the built-in local socket. The current one is marked. Tokens are never shown.",
		Example: "jailops remote list\njailops remote list -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			user, system, err := a.loadAll()
			if err != nil {
				return err
			}
			cur := user.Current
			if cur == "" {
				cur = system.Current
			}
			if v := a.env.Getenv("JAILOPS_REMOTE"); v != "" {
				cur = v
			}
			if a.remote != "" {
				cur = a.remote
			}
			if cur == "" {
				cur = "local"
			}
			rows := []remoteRow{{Name: "local", Current: cur == "local", Target: "unix:" + sdk.DefaultSocket, Auth: "root only", Source: "built-in"}}
			seen := map[string]bool{}
			add := func(m map[string]RemoteConfig, src string) {
				for _, n := range sortedKeys(m) {
					if seen[n] {
						continue
					}
					seen[n] = true
					r := m[n]
					t := r.URL
					if t == "" {
						t = "unix:" + r.Socket
					}
					rows = append(rows, remoteRow{n, cur == n, t, authSummary(r), r.Host, src})
				}
			}
			add(user.Remotes, "user")
			add(system.Remotes, "system")
			return a.emit(rows, nil, func() ([]string, [][]string) {
				var out [][]string
				for _, r := range rows {
					mark := ""
					if r.Current {
						mark = "*"
					}
					out = append(out, []string{mark, r.Name, r.Target, r.Auth, dash(r.Host), r.Source})
				}
				return []string{"", "NAME", "TARGET", "AUTH", "HOST", "SOURCE"}, out
			}, func() []string {
				var n []string
				for _, r := range rows {
					n = append(n, r.Name)
				}
				return n
			})
		},
	}
}

func (a *app) remoteNames() func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		user, system, _ := a.loadAll()
		names := []string{"local"}
		names = append(names, sortedKeys(user.Remotes)...)
		names = append(names, sortedKeys(system.Remotes)...)
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

func (a *app) remoteRemove() *cobra.Command {
	return &cobra.Command{
		Use:               "remove NAME",
		Aliases:           []string{"rm", "delete"},
		Short:             "Remove a remote from the user configuration",
		Long:              "Remove a remote from ~/.config/jailops/config.yaml. A remote defined only in the host-wide file cannot be removed here.",
		Example:           "jailops remote remove old",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.remoteNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := a.userConfigPath()
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			if _, ok := cfg.Remotes[args[0]]; !ok {
				return usagef("remote %q is not in %s", args[0], path)
			}
			if ok, err := a.dry("remove remote "+args[0], nil); ok || err != nil {
				return err
			}
			delete(cfg.Remotes, args[0])
			if cfg.Current == args[0] {
				cfg.Current = ""
			}
			if err := saveConfig(path, cfg); err != nil {
				return err
			}
			a.say("remote/%s removed\n", args[0])
			return nil
		},
	}
}

func (a *app) remoteSwitch() *cobra.Command {
	return &cobra.Command{
		Use:               "switch NAME",
		Short:             "Make a remote the current one",
		Long:              "Make a remote the current one: the one used when --remote and JAILOPS_REMOTE are not set. \"local\" selects this host's socket.",
		Example:           "jailops remote switch prod\njailops remote switch local",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.remoteNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			user, system, err := a.loadAll()
			if err != nil {
				return err
			}
			_, u := user.Remotes[args[0]]
			_, s := system.Remotes[args[0]]
			if args[0] != "local" && !u && !s {
				return usagef("unknown remote %q", args[0])
			}
			if ok, err := a.dry("switch to remote "+args[0], nil); ok || err != nil {
				return err
			}
			user.Current = args[0]
			if err := saveConfig(a.userConfigPath(), user); err != nil {
				return err
			}
			a.say("now using remote %s\n", args[0])
			return nil
		},
	}
}
