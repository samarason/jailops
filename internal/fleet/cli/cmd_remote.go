package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"jailops.net/jailops/internal/fleet/vault"
)

func (a *app) cmdRemote() *cobra.Command {
	root := &cobra.Command{
		Use:   "remote",
		Short: "Manage the client-certificate identity of hosts (hosts/<host>/remote.sops.yaml)",
		Long: `A host can be reached with a token (token_secret in host.yaml) or with a client
certificate. The certificate lives in hosts/<host>/remote.sops.yaml: the url and
the pinned server fingerprint stay readable in git, the client certificate and
key are encrypted by SOPS. The connection is pinned mTLS: it refuses a server
whose certificate does not match the fingerprint.`,
	}
	root.AddCommand(a.remoteList(), a.remoteBootstrap())
	return root
}

func (a *app) remoteList() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List the hosts that have a remote file (decrypts nothing)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := a.path()
			if err != nil {
				return err
			}
			hs, err := vault.ListRemotes(p)
			if err != nil {
				return err
			}
			if len(hs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no remote files)")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "HOST\tURL\tSERVER FINGERPRINT")
			for _, h := range hs {
				r, err := vault.RemoteStructure(p, h)
				if err != nil {
					fmt.Fprintf(tw, "%s\t(unreadable)\t%v\n", h, err)
					continue
				}
				fp := vault.NormalizeFingerprint(r.ServerFingerprint)
				if len(fp) > 16 {
					fp = fp[:8] + "..." + fp[len(fp)-8:]
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", h, r.URL, fp)
			}
			return tw.Flush()
		},
	}
}

func (a *app) remoteBootstrap() *cobra.Command {
	var url, fp, name, perm, projects string
	var global, force bool
	var life time.Duration
	c := &cobra.Command{
		Use:   "bootstrap HOST --url https://HOST:39110 --fingerprint SHA256",
		Short: "Make a client certificate for a host, store it encrypted, print the command that trusts it",
		Example: `jailops-sync remote bootstrap web1 --url https://web1:39110 --fingerprint 3f9a... > sync.pem
jailops-sync remote bootstrap web1 --url https://web1:39110 --fingerprint 3f9a... --projects web,mail
jailops-sync remote bootstrap web1 --url https://web1:39110 --fingerprint 3f9a... --force`,
		Long: `Generates an ECDSA P-256 client certificate and key, writes them with the url and
the pinned server fingerprint to hosts/HOST/remote.sops.yaml encrypted under the
repository's .sops.yaml (the plaintext key never touches the disk), and prints the
command an administrator runs on the host to trust the certificate.

The server fingerprint is the hex SHA-256 of the host's certificate. Take it from
the host itself ('jailops cert enroll' prints a token that carries it) rather than
from the network: there is no trust on first use.

The certificate PEM goes to standard output, everything else to standard error,
so the certificate can be piped to the host:

  jailops-sync remote bootstrap web1 --url https://web1:39110 --fingerprint 3f9a... \
      | ssh admin@web1 'cat > /tmp/sync.pem && jailops cert create sync-prod --pem /tmp/sync.pem --role admin --global'

Needs a key that is a recipient of the matching creation_rule.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			if url == "" || fp == "" {
				return &ExitError{ExitFatal, "--url and --fingerprint are required"}
			}
			p, err := a.path()
			if err != nil {
				return err
			}
			// The host directory is a real host of the repository.
			hostFile := filepath.Join(p, "hosts", host, "host.yaml")
			if _, err := os.Stat(hostFile); err != nil {
				return fmt.Errorf("hosts/%s/host.yaml does not exist: declare the host first (kind Host)", host)
			}
			dest := vault.RemotePath(p, host)
			if _, err := os.Lstat(dest); err == nil && !force {
				return fmt.Errorf("%s already exists; --force replaces it (the old certificate stays trusted on the host until it is deleted there)", vault.RemoteRel(host))
			}
			r := vault.Remote{URL: url, ServerFingerprint: vault.NormalizeFingerprint(fp)}
			if name == "" {
				name = "jailops-sync-" + host
			}
			certPEM, keyPEM, cfp, err := vault.NewClientIdentity(name, time.Now(), life)
			if err != nil {
				return err
			}
			r.ClientCert, r.ClientKey = string(certPEM), string(keyPEM)
			if err := r.Check(); err != nil {
				return err
			}
			plain := remoteYAML(r)
			enc, err := vault.EncryptYAML(p, vault.RemoteRel(host), []byte(plain))
			if err != nil {
				return fmt.Errorf("encrypt %s: %w", vault.RemoteRel(host), err)
			}
			if err := vault.WriteFileAtomic(dest, enc, 0o644); err != nil {
				return err
			}
			e := cmd.ErrOrStderr()
			fmt.Fprintf(e, "wrote %s (encrypted; the key is only in that file)\n", vault.RemoteRel(host))
			fmt.Fprintf(e, "client certificate fingerprint %s\n\n", cfp)
			fmt.Fprintln(e, "The certificate PEM is on standard output. Trust it on the host as an administrator:")
			trust := fmt.Sprintf("  jailops cert create %s --pem CERT.pem --role %s", name, perm)
			switch {
			case projects != "":
				trust += " --projects " + projects
			case global:
				trust += " --global"
			}
			fmt.Fprintln(e, trust)
			fmt.Fprintf(e, "\nThen commit it: git add %s && git commit -m 'add %s remote'\n", vault.RemoteRel(host), host)
			fmt.Fprintf(e, "Check the connection: jailops-sync doctor --host %s\n", host)
			_, err = cmd.OutOrStdout().Write(certPEM)
			return err
		},
	}
	f := c.Flags()
	f.StringVar(&url, "url", "", "the host's API address (https://...)")
	f.StringVar(&fp, "fingerprint", "", "hex SHA-256 of the host's certificate (sha256: and colons are accepted)")
	f.StringVar(&name, "name", "", "certificate name on the host (default jailops-sync-HOST)")
	f.StringVar(&perm, "permission", "admin", "role to print in the trust command (jailops-sync creates projects and storage: admin)")
	f.StringVar(&projects, "projects", "", "projects to print in the trust command, comma separated")
	f.BoolVar(&global, "global", true, "print --global in the trust command (ignored when --projects is given)")
	f.DurationVar(&life, "valid-for", 5*365*24*time.Hour, "validity of the certificate")
	f.BoolVar(&force, "force", false, "replace an existing remote file")
	return c
}

// remoteYAML renders the plaintext document that is encrypted. Block scalars
// keep the PEM readable and survive SOPS. The fingerprint is quoted: a hex string of
// digits (or one like 12e45...) would otherwise be read as a number.
func remoteYAML(r vault.Remote) string {
	block := func(s string) string {
		var b strings.Builder
		for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			b.WriteString("  " + l + "\n")
		}
		return b.String()
	}
	return "url: " + r.URL + "\nserver_fingerprint: \"" + r.ServerFingerprint + "\"\nclient_cert: |\n" + block(r.ClientCert) + "client_key: |\n" + block(r.ClientKey)
}
