package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// renameFn is the client call of a kind's rename.
type renameFn func(ctx context.Context, c *sdk.Client, name string, req api.Rename, etag string) (*sdk.Operation[api.RenameResult], error)

// renameFrom wires the rename of a plain Resource.
func renameFrom[T any](d *kindDesc[T], r func(*sdk.Client) *sdk.Resource[T]) {
	d.rename = func(ctx context.Context, c *sdk.Client, n string, req api.Rename, etag string) (*sdk.Operation[api.RenameResult], error) {
		return r(c).Rename(ctx, n, req, etag)
	}
}

// renameLong is the help of a rename command; what names the references of the kind.
func renameLong(noun, what string) string {
	first := "Give " + article(noun) + " " + noun + " a new name. Everything that refers to it changes with it in one operation: " +
		strings.Join(strings.Fields(what), " ") + ". A failure in the middle undoes what was done; a daemon that stops in the middle undoes it at its next start."
	return fillText(first, 80) + `

The command first asks the server what would change and shows it, then asks for
confirmation (-y answers yes). --dry-run shows the list and changes nothing. The
new name follows the rule of create. An object a repository or a hub manages is
renamed there, not here.`
}

// fillText breaks a paragraph into lines of at most width columns.
func fillText(p string, width int) string {
	var b strings.Builder
	n := 0
	for _, w := range strings.Fields(p) {
		if n > 0 && n+1+len(w) > width {
			b.WriteByte('\n')
			n = 0
		} else if n > 0 {
			b.WriteByte(' ')
			n++
		}
		b.WriteString(w)
		n += len(w)
	}
	return b.String()
}

// addRename adds "rename OLD NEW" to a kind's group.
func addRename[T any](a *app, parent *cobra.Command, d *kindDesc[T], long string) {
	parent.AddCommand(a.renameCmd(d.noun, long, completeKind(a, d), etagGetter(d.get), d.rename))
}

func (a *app) renameCmd(noun, long string, complete completer, etagOf func(ctx context.Context, c *sdk.Client, name string) (string, error), rename renameFn) *cobra.Command {
	return &cobra.Command{
		Use:               "rename OLD NEW",
		Short:             "Rename " + article(noun) + " " + noun + " and everything that refers to it",
		Long:              long,
		Example:           "jailops @P@ rename OLD NEW\njailops @P@ rename OLD NEW --dry-run\njailops @P@ rename -y OLD NEW",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeArgs(complete, completeNone),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			// the plan shown and the rename done are of the version read here: a change in between is a conflict
			etag, err := etagOf(ctx, c, args[0])
			if err != nil {
				return err
			}
			return a.runRename(ctx, noun, args[0], args[1], etag, rename)
		},
	}
}

// etagGetter adapts a kind's get to the ETag a rename sends.
func etagGetter[T any](get func(ctx context.Context, c *sdk.Client, name string) (T, string, error)) func(ctx context.Context, c *sdk.Client, name string) (string, error) {
	return func(ctx context.Context, c *sdk.Client, name string) (string, error) {
		_, etag, err := get(ctx, c, name)
		return etag, err
	}
}

// runRename shows what a rename changes, asks, renames and says what changed. etag is the version the caller read
// ("" sends no If-Match).
func (a *app) runRename(ctx context.Context, noun, from, to, etag string, rename renameFn) error {
	c, err := a.connect(ctx)
	if err != nil {
		return err
	}
	if err := c.Require(ctx, "rename"); err != nil {
		return err
	}
	op, err := rename(ctx, c, from, api.Rename{NewName: to, DryRun: true}, etag)
	if err != nil {
		return err
	}
	plan, err := op.Wait(ctx)
	if err != nil {
		return err
	}
	if a.dryRun {
		if a.format == fmtJSON || a.format == fmtYAML {
			return a.emit(plan, nil, nil, nil)
		}
		fprintf(a.env.Stdout, "dry-run: would rename %s %s to %s\n", noun, from, to)
		a.printRenamePlan(plan)
		return nil
	}
	if !a.yes {
		fprintf(a.env.Stderr, "Renaming %s %s to %s changes:\n", noun, from, to)
		a.printRenameChanges(plan, a.env.Stderr)
	}
	if err := a.confirm(fmt.Sprintf("Rename %s %q to %q?", noun, from, to)); err != nil {
		return err
	}
	op, err = rename(ctx, c, from, api.Rename{NewName: to}, etag)
	if err != nil {
		return err
	}
	if !a.waiting() {
		info := op.Info()
		return a.emit(info, nil, func() ([]string, [][]string) {
			return []string{"OPERATION", "STATUS", "DESCRIPTION"}, [][]string{{info.ID, string(info.Status), info.Description}}
		}, func() []string { return []string{info.ID} })
	}
	v, _, err := a.await(ctx, typedOp[api.RenameResult]{op})
	if err != nil {
		return err
	}
	res, _ := v.(api.RenameResult)
	for _, w := range res.Warnings {
		fprintf(a.env.Stderr, "warning: %s\n", w)
	}
	if a.format == fmtJSON || a.format == fmtYAML {
		return a.emit(res, nil, nil, nil)
	}
	a.say("%s/%s renamed to %s%s\n", noun, from, to, renameCounts(res))
	if noun == "project" {
		return a.followProjectRename(from, to)
	}
	return nil
}

// renameCounts is " (2 references, 1 dataset)", or "" for a rename that touched nothing else.
func renameCounts(res api.RenameResult) string {
	words := map[string][2]string{
		api.RenameReference: {"reference", "references"}, api.RenameDataset: {"dataset", "datasets"},
		api.RenameAnchor: {"firewall anchor", "firewall anchors"}, api.RenameInterface: {"interface description", "interface descriptions"},
		api.RenameFile: {"file", "files"}, api.RenameState: {"state file", "state files"},
	}
	var parts []string
	for _, k := range []string{api.RenameReference, api.RenameDataset, api.RenameAnchor, api.RenameInterface, api.RenameFile, api.RenameState} {
		switch n := res.Counts[k]; n {
		case 0:
		case 1:
			parts = append(parts, "1 "+words[k][0])
		default:
			parts = append(parts, fmt.Sprintf("%d %s", n, words[k][1]))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + " changed)"
}

func (a *app) printRenamePlan(res api.RenameResult) {
	a.printRenameChanges(res, a.env.Stdout)
	if len(res.Steps) > 0 {
		fprintln(a.env.Stdout, "steps:")
		for _, s := range res.Steps {
			fprintf(a.env.Stdout, "  %s\n", s)
		}
	}
}

func (a *app) printRenameChanges(res api.RenameResult, w interface{ Write([]byte) (int, error) }) {
	for _, c := range res.Changes {
		if c.Detail != "" {
			fprintf(w, "  %-10s %s: %s\n", c.Kind, c.Object, c.Detail)
		} else {
			fprintf(w, "  %-10s %s\n", c.Kind, c.Object)
		}
	}
	for _, x := range res.Warnings {
		fprintf(w, "  warning: %s\n", x)
	}
}
