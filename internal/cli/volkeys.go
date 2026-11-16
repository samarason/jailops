package cli

import (
	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

// Encrypted volumes: the passphrase is typed on the terminal without echo, or read from a file for scripts. It is
// never a command line argument (it would be in the shell history and in ps).

// readPassphraseFile reads a passphrase from the first line of a file, or of standard input for "-".
func (a *app) readPassphraseFile(path string) (string, error) {
	return a.readSecretFile("passphrase", path)
}

// promptPassphrase asks on the terminal without echo; a pipe is refused.
func (a *app) promptPassphrase(prompt string) (string, error) {
	if !a.env.IsTTY(a.env.Stdin) {
		return "", usagef("standard input is not a terminal: give the passphrase with --passphrase-file FILE")
	}
	return a.env.ReadSecret(prompt)
}

// newPassphrase reads a new passphrase: from file, else asked twice. It must be 12 to 512 bytes long.
func (a *app) newPassphrase(file, prompt string) (string, error) {
	var p string
	if file != "" {
		var err error
		if p, err = a.readPassphraseFile(file); err != nil {
			return "", err
		}
	} else {
		first, err := a.promptPassphrase(prompt)
		if err != nil {
			return "", err
		}
		second, err := a.promptPassphrase("Repeat the passphrase: ")
		if err != nil {
			return "", err
		}
		if first != second {
			return "", usagef("the passphrases do not match")
		}
		p = first
	}
	if err := api.CheckPassphrase(p); err != nil {
		return "", usagef("%s", err.(*api.Error).Message)
	}
	return p, nil
}

// newVolumePassphrase is the passphrase of an encrypted volume being created.
func (a *app) newVolumePassphrase() (string, error) {
	if a.passFile == "" && a.env.IsTTY(a.env.Stdin) {
		fprintln(a.env.Stderr, "The encrypted volume needs a passphrase. It is asked for after every host boot and cannot be recovered when lost.")
	}
	return a.newPassphrase(a.passFile, "Passphrase for the encrypted volume: ")
}

// givenPassphrase reads an existing passphrase: from file, else asked once.
func (a *app) givenPassphrase(file, prompt string) (string, error) {
	if file != "" {
		return a.readPassphraseFile(file)
	}
	p, err := a.promptPassphrase(prompt)
	if err == nil && p == "" {
		err = usagef("the passphrase is empty")
	}
	return p, err
}

func (a *app) volumeUnlock(d *kindDesc[api.Volume]) *cobra.Command {
	var start bool
	var file string
	cmd := &cobra.Command{
		Use:   "unlock NAME",
		Short: "Type the passphrase of an encrypted volume",
		Long: `Load the key of an encrypted volume after a host boot or a lock. The passphrase is
asked on the terminal without echo (--passphrase-file reads it from a file for
scripts). With --start the jail that attaches the volume starts once it is unlocked;
a jail that was due to start at boot (autostart) starts after the unlock anyway.

A wrong passphrase answers bad_passphrase. After five wrong passphrases in a row
the volume refuses unlocks for 30 seconds.`,
		Example:           "jailops volume unlock vault\njailops volume unlock vault --start\njailops volume unlock vault --passphrase-file /root/vault.pass",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if ok, err := a.dry("unlock volume "+name, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			p, err := a.givenPassphrase(file, "Passphrase of "+name+": ")
			if err != nil {
				return err
			}
			h, err := handle(c.Volumes().Unlock(ctx, name, p, start))
			if err != nil {
				return err
			}
			verb := "unlocked"
			if start {
				verb = "unlocked and its jail started"
			}
			return a.finishOp(ctx, h, "volume", name, verb, nil)
		},
	}
	cmd.Flags().BoolVar(&start, "start", false, "start the jail that attaches the volume once it is unlocked")
	cmd.Flags().StringVar(&file, "passphrase-file", "", "read the passphrase from this file (its first line) instead of asking")
	return cmd
}

func (a *app) volumeLock(d *kindDesc[api.Volume]) *cobra.Command {
	return &cobra.Command{
		Use:   "lock NAME",
		Short: "Lock an encrypted volume and stop its jail",
		Long: `Stop the jail that attaches an encrypted volume, unmount the volume and unload its
key. The data is then unreadable on this host until 'jailops volume unlock' is
given the passphrase again.`,
		Example:           "jailops volume lock vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if ok, err := a.dry("lock volume "+name, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			h, err := handle(c.Volumes().Lock(ctx, name))
			if err != nil {
				return err
			}
			return a.finishOp(ctx, h, "volume", name, "locked", nil)
		},
	}
}

func (a *app) volumePassphrase(d *kindDesc[api.Volume]) *cobra.Command {
	var oldFile, newFile string
	cmd := &cobra.Command{
		Use:   "passphrase NAME",
		Short: "Change the passphrase of an encrypted volume",
		Long: `Change the passphrase of an unlocked encrypted volume (zfs change-key). The current
passphrase is asked first, then the new one twice. The data is not encrypted again:
the passphrase protects the key, and the key stays. Scripts give --passphrase-file
(the current one) and --new-passphrase-file.`,
		Example:           "jailops volume passphrase vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, name := cmd.Context(), args[0]
			if ok, err := a.dry("change the passphrase of volume "+name, nil); ok || err != nil {
				return err
			}
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			old, err := a.givenPassphrase(oldFile, "Current passphrase of "+name+": ")
			if err != nil {
				return err
			}
			nw, err := a.newPassphrase(newFile, "New passphrase: ")
			if err != nil {
				return err
			}
			h, err := handle(c.Volumes().ChangePassphrase(ctx, name, old, nw))
			if err != nil {
				return err
			}
			return a.finishOp(ctx, h, "volume", name, "passphrase changed", nil)
		},
	}
	cmd.Flags().StringVar(&oldFile, "passphrase-file", "", "read the current passphrase from this file instead of asking")
	cmd.Flags().StringVar(&newFile, "new-passphrase-file", "", "read the new passphrase from this file instead of asking")
	return cmd
}
