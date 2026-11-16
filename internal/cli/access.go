package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

const secretWarning = "warning: this secret is shown only once and cannot be retrieved again; store it now."

func tokenDesc() *kindDesc[api.Token] {
	d := newDesc("token", "tokens", api.KindToken,
		func(t *api.Token) *api.ObjectMeta { return &t.Metadata },
		func(t *api.Token) *api.TokenSpec { return &t.Spec })
	d.list = func(ctx context.Context, c *sdk.Client, o ...sdk.ListOption) iter.Seq2[api.Token, error] {
		return c.Tokens().List(ctx, o...)
	}
	d.get = func(ctx context.Context, c *sdk.Client, n string) (api.Token, string, error) {
		return c.Tokens().GetETag(ctx, n)
	}
	d.del = func(ctx context.Context, c *sdk.Client, n string) (opHandle, error) {
		return nil, c.Tokens().Delete(ctx, n)
	}
	d.head = []string{"NAME", "ROLE", "SCOPE", "EXPIRES", "ALLOW-FROM", "AGE"}
	d.row = func(now time.Time, t api.Token) []string {
		exp := "never"
		if !t.Spec.ExpiresAt.IsZero() {
			exp = t.Spec.ExpiresAt.UTC().Format("2006-01-02")
		}
		return []string{t.Metadata.Name, string(t.Spec.Permission), scopeText(t.Spec.Projects, t.Spec.Global), exp, joinOrDash(t.Spec.AllowFrom), age(now, t.Metadata.CreatedAt)}
	}
	return &d
}

func (a *app) tokenCmd() *cobra.Command {
	d := tokenDesc()
	d.revoke = true
	tc := group("token", "Manage API tokens",
		`API tokens (jot_...) authenticate scripts and remote clients with one role.
The server stores only a hash: the secret is shown once, when the token is
created. Give a token the lowest role that does the job.`,
		"jailops token list\njailops token create ci --role operator --projects web --expires 720h\njailops token revoke ci", "tokens")
	addList(a, tc, d, "")
	addShow(a, tc, d)
	addDelete(a, tc, d)
	var perm, allow string
	var expires time.Duration
	var comment string
	var scope func() ([]string, bool, error)
	create := &cobra.Command{
		Use:   "create NAME",
		Short: "Create an API token",
		Long: `Create an API token with one role. The secret is printed once on standard output
(so $(jailops token create ci) captures it) and a warning goes to standard error.
With -o json the whole object is printed, secret included.`,
		Example: "jailops token create ci --role operator --projects web --expires 720h\nTOKEN=$(jailops token create deploy --role operator --global 2>/dev/null)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			projects, global, err := scope()
			if err != nil {
				return err
			}
			t := api.Token{Metadata: api.ObjectMeta{Name: args[0]}, Spec: api.TokenSpec{Comment: comment, Permission: api.Permission(perm), Projects: projects, Global: global}}
			if expires > 0 {
				t.Spec.ExpiresAt = a.env.Now().Add(expires).UTC()
			}
			if allow != "" {
				t.Spec.AllowFrom = strings.Split(allow, ",")
			}
			if ok, err := a.dry("create token "+args[0], t); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			out, err := c.Tokens().Create(cmd.Context(), t)
			if err != nil {
				return err
			}
			fprintln(a.env.Stderr, secretWarning)
			if a.format == fmtTable {
				fprintln(a.env.Stdout, out.Secret)
				return nil
			}
			return a.emit(out, nil, nil, func() []string { return []string{out.Metadata.Name} })
		},
	}
	roleFlag(create, &perm, "readonly", "")
	scope = scopeFlags(create)
	create.Flags().DurationVar(&expires, "expires", 0, "token lifetime, for example 720h (default: never)")
	create.Flags().StringVar(&comment, "comment", "", "what the token is for")
	create.Flags().StringVar(&allow, "allow-from", "", "comma-separated source networks the token may be used from")
	tc.AddCommand(create)
	return tc
}

func certDesc() *kindDesc[api.Certificate] {
	d := newDesc("certificate", "certificates", api.KindCertificate,
		func(t *api.Certificate) *api.ObjectMeta { return &t.Metadata },
		func(t *api.Certificate) *api.CertificateSpec { return &t.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Certificate] { return c.Certificates() })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.Certificate] { return c.Certificates() })
	d.renameLong = renameLong("certificate", `nothing else names it: its fingerprint, permissions and projects stay. The audit log keeps the name it had when it acted`)
	d.head = []string{"NAME", "KIND", "ROLE", "SCOPE", "EXPIRES", "FINGERPRINT"}
	d.row = func(_ time.Time, t api.Certificate) []string {
		exp := "never"
		if !t.Spec.ExpiresAt.IsZero() {
			exp = t.Spec.ExpiresAt.UTC().Format("2006-01-02")
		}
		return []string{t.Metadata.Name, t.Spec.Kind, string(t.Spec.Permission), scopeText(t.Spec.Projects, t.Spec.Global), exp, colonFP(t.Spec.Fingerprint)}
	}
	return &d
}

func (a *app) certCmd() *cobra.Command {
	d := certDesc()
	d.revoke = true
	cc := group("cert", "Manage trusted certificates",
		`Certificates are trusted by their SHA-256 fingerprint: client certificates for
people and tools using mTLS, host certificates for hubs and hosts, and backup
certificates for backup transport.`,
		"jailops cert list\njailops cert create laptop --pem laptop.pem --role operator --projects web\njailops cert revoke laptop",
		"certs", "certificate", "certificates")
	crudCommands(a, cc, d, `Trust a certificate by fingerprint. Give --pem with a PEM certificate, or
--fingerprint with its SHA-256 (hex, colons allowed).`,
		"jailops cert create laptop --pem laptop.pem --role operator --projects web\njailops cert create host-b --kind host --fingerprint FINGERPRINT --role admin --global",
		func(cmd *cobra.Command) func(string) (api.Certificate, error) {
			var file, fp, kind, perm, comment string
			cmd.Flags().StringVar(&file, "pem", "", "PEM certificate file to trust")
			cmd.Flags().StringVar(&fp, "fingerprint", "", "SHA-256 fingerprint of the certificate")
			cmd.Flags().StringVar(&kind, "kind", "client", "client, host or backup")
			cmd.Flags().StringVar(&comment, "comment", "", "what the certificate is for")
			roleFlag(cmd, &perm, "readonly", "")
			scope := scopeFlags(cmd)
			return func(name string) (api.Certificate, error) {
				projects, global, err := scope()
				if err != nil {
					return api.Certificate{}, err
				}
				if file != "" {
					b, err := a.readInput(file)
					if err != nil {
						return api.Certificate{}, err
					}
					blk, _ := pem.Decode(b)
					if blk == nil {
						return api.Certificate{}, usagef("%s holds no PEM certificate", file)
					}
					cert, err := x509.ParseCertificate(blk.Bytes)
					if err != nil {
						return api.Certificate{}, usagef("%s: %v", file, err)
					}
					fp = sdk.Fingerprint(cert)
				}
				fp = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(fp), "sha256:"), ":", ""))
				if len(fp) != 64 {
					return api.Certificate{}, usagef("give --pem or a SHA-256 --fingerprint (64 hex digits)")
				}
				return api.Certificate{Metadata: api.ObjectMeta{Name: name}, Spec: api.CertificateSpec{Comment: comment, Fingerprint: fp, Permission: api.Permission(perm), Kind: kind, Projects: projects, Global: global}}, nil
			}
		})
	cc.AddCommand(a.certEnroll())
	return cc
}

func userDesc() *kindDesc[api.User] {
	d := newDesc("user", "users", api.KindUser,
		func(t *api.User) *api.ObjectMeta { return &t.Metadata },
		func(t *api.User) *api.UserSpec { return &t.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.User] { return c.Users().Resource })
	renameFrom(&d, func(c *sdk.Client) *sdk.Resource[api.User] { return c.Users().Resource })
	d.renameLong = renameLong("user", `nothing else names it: the password, the second factor and the sessions stay with the user. The audit log keeps the name it had when the user acted`)
	d.head = []string{"NAME", "ROLE", "SCOPE", "TOTP", "DISABLED"}
	d.row = func(_ time.Time, t api.User) []string {
		return []string{t.Metadata.Name, string(t.Spec.Permission), scopeText(t.Spec.Projects, t.Spec.Global), yesno(t.Spec.TOTP), yesno(t.Spec.Disabled)}
	}
	return &d
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *app) userCmd() *cobra.Command {
	d := userDesc()
	uc := group("user", "Manage local user accounts",
		`Users are people who sign in to the web interface with a password and optional
second factor. Passwords are never returned; a generated one is shown once
when the user is created.`,
		"jailops user list\njailops user create alice --role operator --projects web\njailops user disable alice", "users")
	addList(a, uc, d, "")
	addShow(a, uc, d)
	addEdit(a, uc, d)
	addDelete(a, uc, d)
	addRename(a, uc, d, d.renameLong)
	var perm, passFile, comment string
	var passPrompt, asAdmin bool
	var scope func() ([]string, bool, error)
	create := &cobra.Command{
		Use:   "create NAME",
		Short: "Create a user",
		Long: `Create a user. Without a password option the server generates one, which is
printed once on standard output with a warning on standard error. With
--password-file - the first line of standard input is the
password; with --password-file FILE the first line of FILE; with
--password-prompt the password is asked on the terminal. A password is never an
argument of the command line.

--admin creates a global administrator (role admin, global scope). On the host,
as root, it is the first-administrator bootstrap and the recovery path:
sudo jailops user create admin --admin`,
		Example: "sudo jailops user create admin --admin --password-prompt\njailops user create alice --role operator --projects web\necho 's3cret-pass' | jailops user create bob --password-file - --global\njailops user create carol --role operator --projects web --password-file /root/carol.pass",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var projects []string
			var global bool
			if asAdmin {
				if cmd.Flags().Changed("role") || cmd.Flags().Changed("projects") || cmd.Flags().Changed("global") {
					return usagef("--admin already means role admin with global scope: do not combine it with --role, --projects or --global")
				}
				perm, global = string(api.PermAdmin), true
			} else {
				var err error
				if projects, global, err = scope(); err != nil {
					return err
				}
			}
			req := api.UserCreate{Metadata: api.ObjectMeta{Name: args[0]}, Spec: api.UserSpec{Comment: comment, Permission: api.Permission(perm), Projects: projects, Global: global}}
			if n := btoi(passPrompt) + btoi(passFile != ""); n > 1 {
				return usagef("--password-file and --password-prompt exclude each other")
			}
			if passPrompt || passFile != "" {
				pw, err := a.newPassword(passFile)
				if err != nil {
					return err
				}
				req.Password = pw
			}
			shown := req
			shown.Password = ""
			if ok, err := a.dry("create user "+args[0], shown); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			out, err := c.Users().Create(cmd.Context(), req)
			if err != nil {
				return err
			}
			if out.Password != "" {
				fprintln(a.env.Stderr, secretWarning)
				if a.format == fmtTable {
					fprintln(a.env.Stdout, out.Password)
					return nil
				}
			} else if a.format == fmtTable {
				fprintf(a.env.Stdout, "user/%s created\n", args[0])
				return nil
			}
			return a.emit(out, nil, nil, func() []string { return []string{args[0]} })
		},
	}
	roleFlag(create, &perm, "readonly", "")
	scope = scopeFlags(create)
	create.Flags().StringVar(&comment, "comment", "", "who or what the user is")
	create.Flags().BoolVar(&passPrompt, "password-prompt", false, "ask for the password on the terminal")
	create.Flags().StringVar(&passFile, "password-file", "", "read the password from the first line of this file (- for standard input)")
	create.Flags().BoolVar(&asAdmin, "admin", false, "create a global administrator (role admin, global scope)")
	setDisabled := func(verb string, disabled bool) *cobra.Command {
		return &cobra.Command{
			Use:               verb + " NAME",
			Short:             strings.ToUpper(verb[:1]) + verb[1:] + " a user account",
			Long:              strings.ToUpper(verb[:1]) + verb[1:] + " a user account. A disabled user cannot sign in; the account and its settings are kept.",
			Example:           "jailops user " + verb + " alice",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeKind(a, d),
			RunE: func(cmd *cobra.Command, args []string) error {
				patch := map[string]any{"spec": map[string]any{"disabled": disabled}}
				if ok, err := a.dry(verb+" user "+args[0], patch); ok || err != nil {
					return err
				}
				c, err := a.connect(cmd.Context())
				if err != nil {
					return err
				}
				u, err := c.Users().Patch(cmd.Context(), args[0], patch, "")
				if err != nil {
					return err
				}
				return a.finishOp(cmd.Context(), nil, "user", args[0], verb+"d", u)
			},
		}
	}
	uc.AddCommand(create, setDisabled("disable", true), setDisabled("enable", false), a.userSetPasswordCmd(d), a.userSetRoleCmd(d))
	return uc
}

func (a *app) userSetPasswordCmd(d *kindDesc[api.User]) *cobra.Command {
	var generate bool
	var passFile string
	cmd := &cobra.Command{
		Use:   "set-password NAME",
		Short: "Set a user's password",
		Long: `Replace a user's password without knowing the old one. It needs a global
administrator; as root on the host it is the recovery path for a lost password.
The user's sessions end. The password is asked on the terminal (twice), or read
from the first line of standard input with --password-file -,
from the first line of a file with --password-file FILE, or generated by the
server with --generate (printed once). It is never an argument of the command
line.`,
		Example:           "sudo jailops user set-password alice\necho 'a long new passphrase' | sudo jailops user set-password alice --password-file -\nsudo jailops user set-password alice --password-file /root/alice.pass\nsudo jailops user set-password alice --generate",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			pw := ""
			switch {
			case btoi(generate)+btoi(passFile != "") > 1:
				return usagef("--password-file and --generate exclude each other")
			case !generate:
				var err error
				if pw, err = a.newPassword(passFile); err != nil {
					return err
				}
			}
			if ok, err := a.dry("set the password of user "+args[0], map[string]any{"generate": generate}); ok || err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			out, err := c.Users().SetPassword(cmd.Context(), args[0], pw)
			if err != nil {
				return err
			}
			if out.Password != "" {
				fprintln(a.env.Stderr, secretWarning)
				if a.format == fmtTable {
					fprintln(a.env.Stdout, out.Password)
					return nil
				}
				return a.emit(out, nil, nil, func() []string { return []string{args[0]} })
			}
			fprintf(a.env.Stdout, "user/%s password set; its sessions ended\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&passFile, "password-file", "", "read the password from the first line of this file (- for standard input)")
	cmd.Flags().BoolVar(&generate, "generate", false, "let the server generate the password and print it once")
	return cmd
}

func (a *app) userSetRoleCmd(d *kindDesc[api.User]) *cobra.Command {
	var role string
	var scope func() ([]string, bool, error)
	cmd := &cobra.Command{
		Use:   "set-role NAME [--role ROLE] [--projects a,b | --global]",
		Short: "Change a user's role and scope",
		Long: `Change the role of a user, the projects it acts in (or --global), or both.
What you leave out stays as it is: --projects alone keeps the role, --role alone
keeps the scope. A scope you give replaces the old one whole. The command prints
the role and scope before and after.`,
		Example:           "jailops user set-role alice --role operator --projects web,db\njailops user set-role alice --projects web\nsudo jailops user set-role alice --role admin --global",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ch := cmd.Flags().Changed
			newScope := ch("projects") || ch("global")
			if !ch("role") && !newScope {
				return usagef("give --role, --projects or --global (what you leave out stays as it is)")
			}
			var projects []string
			var global bool
			if newScope {
				var err error
				if projects, global, err = scope(); err != nil {
					return err
				}
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			cur, _, err := d.get(cmd.Context(), c, args[0])
			if err != nil {
				return err
			}
			if !ch("role") {
				role = string(cur.Spec.Permission)
			}
			if !newScope {
				projects, global = cur.Spec.Projects, cur.Spec.Global
			}
			// the API field is still called permission
			spec := map[string]any{"permission": role, "global": global, "projects": nil}
			if len(projects) > 0 {
				spec["projects"] = projects
			}
			patch := map[string]any{"spec": spec}
			change := fmt.Sprintf("%s, %s -> %s, %s", cur.Spec.Permission, scopeText(cur.Spec.Projects, cur.Spec.Global), role, scopeText(projects, global))
			if ok, err := a.dry("set the role of user "+args[0]+" ("+change+")", patch); ok || err != nil {
				return err
			}
			u, err := c.Users().Patch(cmd.Context(), args[0], patch, "")
			if err != nil {
				return err
			}
			if a.format == fmtTable {
				a.say("user/%s updated (%s)\n", args[0], change)
				return nil
			}
			return a.finishOp(cmd.Context(), nil, "user", args[0], "updated", u)
		},
	}
	roleFlag(cmd, &role, "", "new role: readonly, operator, admin, backup-push, backup-pull, restore or backup-admin (default: keep the current one)")
	scope = scopeFlags(cmd)
	return cmd
}

// btoi counts a set flag as 1.
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func hostDesc() *kindDesc[api.Remote] {
	d := newDesc("host", "hosts", api.KindRemote,
		func(t *api.Remote) *api.ObjectMeta { return &t.Metadata },
		func(t *api.Remote) *api.RemoteSpec { return &t.Spec })
	fromResource(&d, func(c *sdk.Client) *sdk.Resource[api.Remote] { return c.Remotes() })
	d.head = []string{"NAME", "ADDRESS", "ONLINE", "VERSION", "LAST SEEN"}
	d.style = func(col int, v string) string {
		if col == 2 {
			switch v {
			case "yes":
				return "32"
			case "no":
				return "31"
			}
		}
		return ""
	}
	d.row = func(now time.Time, t api.Remote) []string {
		return []string{t.Metadata.Name, t.Spec.Address, yesno(t.Status.Online), dash(t.Status.Version), age(now, t.Status.LastSeen)}
	}
	return &d
}

// completeHosts completes the name of a host behind a hub.
func (a *app) completeHosts() completer {
	return a.completeNames(func(ctx context.Context, c *sdk.Client) ([]string, error) {
		items, err := collect(c.Remotes().List(ctx))
		var n []string
		for _, h := range items {
			n = append(n, h.Metadata.Name)
		}
		return n, err
	})
}

// hostUUID resolves a host of a hub given by name or UUID to its UUID.
func (a *app) hostUUID(ctx context.Context, c *sdk.Client, nameOrUUID string) (string, error) {
	if len(nameOrUUID) == 36 && strings.Count(nameOrUUID, "-") == 4 {
		return nameOrUUID, nil
	}
	hosts, err := collect(c.Remotes().List(ctx))
	if err != nil {
		return "", err
	}
	for _, h := range hosts {
		if h.Metadata.Name == nameOrUUID && h.Spec.HostUUID != "" {
			return h.Spec.HostUUID, nil
		}
	}
	return "", api.Errorf(api.CodeNotFound, "host %q not found", nameOrUUID).WithHint("'jailops host list' names the hosts of the hub; a UUID is accepted as well")
}

func (a *app) hostCmd() *cobra.Command {
	d := hostDesc()
	hc := group("host", "Manage the hosts a hub controls",
		`On a hub, a host is a daemon the hub manages over mTLS. Once added, address it
with the global --host flag on any command. (The 'remote' commands, in contrast,
configure where this client connects.)`,
		"jailops host list\njailops host create host-b --url https://10.0.0.2:39110 --fingerprint ab12...\njailops --host host-b jail list", "hosts")
	crudCommands(a, hc, d, "Add a host to the hub. The fingerprint pins the host's certificate.",
		"jailops host create host-b --url https://10.0.0.2:39110 --fingerprint ab12...",
		func(cmd *cobra.Command) func(string) (api.Remote, error) {
			var addr, fp, uuid, comment string
			cmd.Flags().StringVar(&addr, "url", "", "https://host:port of the host (required without -f)")
			cmd.Flags().StringVar(&fp, "fingerprint", "", "SHA-256 fingerprint of the host certificate")
			cmd.Flags().StringVar(&uuid, "host-uuid", "", "UUID of the host, when known")
			cmd.Flags().StringVar(&comment, "comment", "", "what the host is for")
			return func(name string) (api.Remote, error) {
				if addr == "" && !a.partial {
					return api.Remote{}, usagef("--address is required (or use -f FILE)")
				}
				return api.Remote{Metadata: api.ObjectMeta{Name: name}, Spec: api.RemoteSpec{Comment: comment, Address: addr, Fingerprint: fp, HostUUID: uuid}}, nil
			}
		})
	a.addHostManagement(hc)
	return hc
}
