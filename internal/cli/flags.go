package cli

import (
	"github.com/spf13/cobra"
)

// roles are the values of --role.
var roles = []string{"readonly", "operator", "admin", "backup-push", "backup-pull", "restore", "backup-admin"}

// roleFlag registers --role.
func roleFlag(cmd *cobra.Command, p *string, def, usage string) {
	if usage == "" {
		usage = "role: readonly, operator, admin, backup-push, backup-pull, restore or backup-admin"
	}
	cmd.Flags().StringVar(p, "role", def, usage)
	enumFlag(cmd, "role", roles...)
}
