package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

func updateSummary(r api.UpdateReport) string {
	var p []string
	if n := len(r.Packages); n > 0 {
		p = append(p, fmt.Sprintf("%d packages", n))
	}
	if r.OS != nil {
		p = append(p, "os "+r.OS.From+" -> "+r.OS.To)
	}
	if r.Error != "" {
		return "error: " + r.Error
	}
	return dash(strings.Join(p, ", "))
}

func (a *app) emitReports(reports []api.UpdateReport) error {
	return a.emit(nonNil(reports), func(col int, v string) string {
		if col == 3 && v == "yes" {
			return "33"
		}
		return ""
	}, func() ([]string, [][]string) {
		var rows [][]string
		for _, r := range reports {
			rows = append(rows, []string{r.Jail, r.Project, dash(string(r.Mode)), yesno(r.Available), updateSummary(r), age(a.env.Now(), r.CheckedAt)})
		}
		return []string{"JAIL", "PROJECT", "MODE", "AVAILABLE", "UPDATES", "CHECKED"}, rows
	}, func() []string {
		var n []string
		for _, r := range reports {
			n = append(n, r.Jail)
		}
		return n
	})
}

func (a *app) emitRecords(recs []api.UpdateRecord) error {
	return a.emit(nonNil(recs), updateStyle, func() ([]string, [][]string) {
		var rows [][]string
		for _, r := range recs {
			change := dash(r.From)
			if r.To != "" {
				change = r.From + " -> " + r.To
			}
			if r.Kind == api.UpdateKindPackages {
				change = fmt.Sprintf("%d packages", len(r.Packages))
			}
			res := r.Result
			if r.RootRolledBack {
				res += " (root rolled back)"
			}
			rows = append(rows, []string{r.ID, r.Jail, r.Kind, res, change, dash(r.Snapshot), age(a.env.Now(), r.Started)})
		}
		return []string{"ID", "JAIL", "KIND", "RESULT", "CHANGE", "SNAPSHOT", "AGE"}, rows
	}, func() []string {
		var n []string
		for _, r := range recs {
			n = append(n, r.ID)
		}
		return n
	})
}

func (a *app) updateCmd() *cobra.Command {
	d := a.jailDesc()
	uc := group("update", "Check for and apply updates of jails",
		`Managed updates: a check lists what could change (packages inside the jail,
a newer image generation for the root) and changes nothing; an apply takes a
snapshot first, updates, runs the jail's health check and, when an OS update
fails, swaps the root back to the previous generation. Application data is
never rolled back for you. The history keeps the snapshot of every update.

Everything acts in the current project (--project, JAILOPS_PROJECT or
'project switch'). Which jails update on their own is a matter of each jail's
update policy; these commands are the manual side.`,
		`jailops update list
jailops update check
jailops update apply web --dry-run
jailops update apply web
jailops update history web`, "updates")

	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the result of the latest update check of each jail",
		Long:    "List the latest update check of every jail that has one, with what is available. It does not contact the jails; run 'update check' to refresh.",
		Example: "jailops update list\njailops update list --project web -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			rs, err := c.Updates().List(cmd.Context())
			if err != nil {
				return err
			}
			return a.emitReports(rs)
		},
	}

	var checkAll bool
	check := &cobra.Command{
		Use:   "check [JAIL...]",
		Short: "Check what could be updated, without changing anything",
		Long: `Ask jails what could be updated: packages and a newer image generation. Name
the jails; without names every jail of the project is checked (--project selects
it, --all says the same). A stopped jail cannot be asked about its packages and
shows an error in the result.`,
		Example:           "jailops update check web\njailops update check\njailops update check --project shop",
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			names, err := updateTargets(args, checkAll || len(args) == 0)
			if err != nil {
				return err
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Updates().Check(cmd.Context(), names...))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "update check", "", "started", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			rs, _ := v.([]api.UpdateReport)
			return a.emitReports(rs)
		},
	}
	check.Flags().BoolVar(&checkAll, "all", false, "check every jail of the project (the default without names)")

	var applyAll, pkgs, osOnly bool
	apply := &cobra.Command{
		Use:   "apply JAIL... | --all",
		Short: "Apply updates to jails",
		Long: `Apply updates. By default each jail gets what its update policy allows;
--packages or --os restrict it. Every update takes an atomic snapshot first,
which stays in the history.

With --dry-run nothing is applied: the command checks the jails and shows
what an apply would change. Applying to every jail of a project (--all) is a
batch: you must type the project name to confirm, unless -y is given. Naming
jails asks a yes/no question, also skipped by -y.

The exit status is 1 when an update failed; the history shows whether the root
was rolled back.`,
		Example: `jailops update apply web --dry-run
jailops update apply web db
jailops update apply --all --project shop
jailops update apply --all -y --packages`,
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			names, err := updateTargets(args, applyAll)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			c, err := a.connect(ctx)
			if err != nil {
				return err
			}
			req := api.UpdateApplyRequest{Jails: names, All: len(names) == 0, Packages: pkgs, OS: osOnly}
			if a.dryRun {
				h, err := handle(c.Updates().Check(ctx, names...))
				if err != nil {
					return err
				}
				v, _, err := a.await(ctx, h)
				if err != nil {
					return err
				}
				rs, _ := v.([]api.UpdateReport)
				var todo []api.UpdateReport
				for _, r := range rs {
					if r.Available {
						todo = append(todo, r)
					}
				}
				if a.format == fmtTable {
					fprintf(a.env.Stdout, "dry-run: would apply updates to %d of %d jails in project %s\n", len(todo), len(rs), a.conn.CurrentProject())
				}
				return a.emitReports(todo)
			}
			project := a.conn.CurrentProject()
			if req.All {
				warn := fmt.Sprintf("This applies updates to every jail of project %q that has any, one after the other.", project)
				if a.yes {
					// -y answers the batch question
				} else if err := a.confirmTyped(warn, project, false, "-y"); err != nil {
					return err
				}
			} else if err := a.confirm(fmt.Sprintf("Apply updates to %s in project %s?", strings.Join(names, ", "), project)); err != nil {
				return err
			}
			h, err := handle(c.Updates().Apply(ctx, req))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(ctx, h, "update", "", "started", nil)
			}
			v, _, err := a.await(ctx, h)
			if err != nil {
				return err
			}
			recs, _ := v.([]api.UpdateRecord)
			if err := a.emitRecords(recs); err != nil {
				return err
			}
			bad := 0
			for _, r := range recs {
				if r.Result != api.UpdateOK {
					bad++
				}
			}
			if bad > 0 {
				return &hintError{err: fmt.Errorf("%d of %d updates failed", bad, len(recs)), hint: "'jailops update history JAIL' shows what happened and the snapshot that was taken"}
			}
			return nil
		},
	}
	apply.Flags().BoolVar(&applyAll, "all", false, "apply to every jail of the project that has updates")
	apply.Flags().BoolVar(&pkgs, "packages", false, "only package updates")
	apply.Flags().BoolVar(&osOnly, "images", false, "only image generation updates")

	history := &cobra.Command{
		Use:               "history JAIL",
		Short:             "Show the update history of a jail",
		Long:              "Show the updates applied to a jail, newest first: result, what changed and the snapshot taken before. Rolling a package update back is a data rollback to that snapshot ('jail rollback --data --snapshot').",
		Example:           "jailops update history web",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			recs, err := c.Jails().UpdateHistory(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return a.emitRecords(recs)
		},
	}
	uc.AddCommand(list, check, apply, history)
	return uc
}

func updateTargets(args []string, all bool) ([]string, error) {
	switch {
	case all && len(args) > 0:
		return nil, usagef("name jails or use --all, not both")
	case !all && len(args) == 0:
		return nil, usagef("name the jails to update, or use --all for every jail of the project")
	}
	return args, nil
}

func (a *app) provisionCmd() *cobra.Command {
	var again bool
	d := a.jailDesc()
	cmd := &cobra.Command{
		Use:   "provision JAIL [--again]",
		Short: "Run the provisioning declared in a jail's specification",
		Long: `Run a jail's provisioning: the packages, files, services and one-off commands
declared in spec.provision, in that order, once. JailOps knows how to do each
step on FreeBSD and on Alpine, and nothing runs inside the jail as an agent.
Provisioning runs once; after it completed the command refuses unless --again
is given. 'jailops jail show' shows whether it ran.`,
		Example:           "jailops provision web\njailops provision web --again",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeKind(a, d),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ok, err := a.dry("provision jail "+args[0], map[string]bool{"again": again}); ok || err != nil {
				return err
			}
			if again {
				if err := a.confirm(fmt.Sprintf("Run the provisioning of %q again?", args[0])); err != nil {
					return err
				}
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			h, err := handle(c.Jails().Provision(cmd.Context(), args[0], again))
			if err != nil {
				return err
			}
			if !a.waiting() {
				return a.finishOp(cmd.Context(), h, "jail", args[0], "provisioning", nil)
			}
			v, _, err := a.await(cmd.Context(), h)
			if err != nil {
				return err
			}
			res, _ := v.(api.ProvisionResult)
			if a.format != fmtTable {
				return a.emit(res, nil, nil, func() []string { return []string{args[0]} })
			}
			fprintf(a.env.Stdout, "jail/%s provisioned (%d steps)\n", args[0], len(res.Steps))
			for _, s := range res.Steps {
				fprintf(a.env.Stdout, "  %s\n", s)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&again, "again", false, "run it although provisioning completed before")
	return cmd
}
