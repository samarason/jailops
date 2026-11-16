package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk/api"
)

func (a *app) bootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "boot",
		Short: "Show which jails start when the host boots, and in which order",
		Long: `Show what the daemon starts after a boot of the host: the jails with autostart in the
order they start, and the jails it does not start with the reason. The plan is
computed the way the boot does it, from the jails as they are now, whether they
run or not.

The order is that of the whole host. A jail starts after the jails in its
boot.depends, which start even when they have no autostart of their own; among
the jails that are ready, the lower boot.priority starts first, then the name. A
jail whose dependencies form a cycle or do not exist is not started, and neither
is a jail with an encrypted volume: it waits for its passphrase after a boot
('jailops volume unlock'), and starts then.

You see the jails of every project you may use, whatever project you chose; --project
shows one project. The order among the jails is the host's. No project needs to be chosen.

A jail starts at boot only with autostart: 'jailops create ... --autostart', or
'jailops config set JAIL boot.autostart true'. 'jailops list -c name,state,autostart'
shows which jails have it.`,
		Example: "jailops boot\njailops boot --project web\njailops boot -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			// the whole host unless --project names one
			plan, err := c.BootPlan(cmd.Context(), !cmd.Flag("project").Changed)
			if err != nil {
				return err
			}
			return a.emitBootPlan(plan)
		},
	}
}

func (a *app) emitBootPlan(p api.BootPlan) error {
	p.Order, p.NotStarted = nonNil(p.Order), nonNil(p.NotStarted)
	switch a.format {
	case fmtJSON, fmtYAML:
		return a.emit(p, nil, nil, nil)
	case fmtCSV:
		return usagef("-o csv is not available for this command")
	case fmtName:
		return a.emit(p, nil, nil, func() []string {
			var n []string
			for _, e := range p.Order {
				n = append(n, e.Jail)
			}
			return n
		})
	}
	projects := map[string]bool{}
	for _, e := range p.Order {
		projects[e.Project] = true
	}
	for _, s := range p.NotStarted {
		projects[s.Project] = true
	}
	name := func(project, jail string) string {
		if len(projects) > 1 {
			return project + "/" + jail
		}
		return jail
	}
	var order, skipped [][]string
	for _, e := range p.Order {
		why := e.Reason
		if len(e.Depends) > 0 {
			why += ", after " + strings.Join(e.Depends, ", ")
		}
		order = append(order, []string{strconv.Itoa(e.Position), name(e.Project, e.Jail), strconv.Itoa(e.Priority), why})
	}
	for _, s := range p.NotStarted {
		skipped = append(skipped, []string{name(s.Project, s.Jail), s.Reason})
	}
	w := a.env.Stdout
	if len(order) == 0 && len(skipped) == 0 {
		fprintln(a.env.Stderr, "No jail starts at boot. Give one autostart: jailops config set JAIL boot.autostart true")
		return nil
	}
	print := func(head []string, rows [][]string) {
		if a.pretty() {
			a.printBoxed(w, head, rows, nil, nil)
			return
		}
		a.printTable(w, head, rows, nil)
	}
	if len(order) > 0 {
		print([]string{"#", "JAIL", "PRIORITY", "WHY"}, order)
	}
	if len(skipped) > 0 {
		if len(order) > 0 {
			fmt.Fprintln(w)
		}
		print([]string{"NOT STARTED", "WHY"}, skipped)
	}
	return nil
}
