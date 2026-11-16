package cli

import (
	"fmt"
	"sync"

	"github.com/spf13/cobra"

	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// stopAllParallel is how many jails stop at the same time.
const stopAllParallel = 8

// stopAllCmd is what a host shutdown runs (the rc script jailops_shutdown): every running jail of every project, the
// jails that others depend on last.
func (a *app) stopAllCmd() *cobra.Command {
	var force bool
	var grace string
	cmd := &cobra.Command{
		Use:   "stop-all",
		Short: "Stop every running jail of every project you may use, dependents first",
		Long: `Stop every running jail of every project you may use, up to eight at a time, each
with its own graceful shutdown (--grace sets how long a jail gets, --force skips it).
No project needs to be chosen.

The order is the reverse of the boot order ('jailops boot'): a jail stops before the
jails in its boot.depends, and among the jails that may stop the one with the higher
boot.priority goes first. A jail that cannot be stopped is reported and the rest
are stopped anyway; the exit status says whether all stopped.

The host does this itself when it shuts down (the rc script jailops_shutdown, enabled
with jailopsd_enable), so that databases and other services get their shutdown and the
poststop hooks run, instead of every process of the jails being killed at once.`,
		Example: "jailops stop-all\njailops stop-all --grace 60s\njailops stop-all --dry-run",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var opts []sdk.ActionOption
			if force {
				opts = append(opts, sdk.Force())
			}
			if grace != "" {
				secs, err := parseGrace(grace)
				if err != nil {
					return err
				}
				opts = append(opts, sdk.ActionTimeout(secs))
			}
			c, err := a.connect(cmd.Context())
			if err != nil {
				return err
			}
			type target struct{ project, name string }
			targets := map[string]target{}
			var nodes []api.BootNode
			for p, err := range c.Projects().List(cmd.Context()) {
				if err != nil {
					return err
				}
				proj := p.Metadata.Name
				for j, err := range c.Project(proj).Jails().List(cmd.Context()) {
					if err != nil {
						return err
					}
					if j.Status.Power != api.PowerRunning {
						continue
					}
					key := proj + "/" + j.Metadata.Name
					node := api.BootNode{Key: key, Boot: api.BootPolicy{Priority: j.Spec.Boot.Priority}}
					for _, d := range j.Spec.Boot.Depends {
						node.Boot.Depends = append(node.Boot.Depends, proj+"/"+d)
					}
					nodes = append(nodes, node)
					targets[key] = target{proj, j.Metadata.Name}
				}
			}
			order := api.StopOrder(nodes)
			if len(order) == 0 {
				fprintln(a.env.Stderr, "No jail is running.")
				return nil
			}
			// the jails stop side by side, a few at a time: one that is slow to stop (a database flushing) does not hold up
			// the others, and the budget of a host shutdown is not spent one jail after the other. A jail still stops
			// after every jail that depends on it, and among the jails that may stop the order above decides who goes first.
			dependents := map[string][]string{}
			for _, n := range nodes {
				for _, d := range n.Boot.Depends {
					if _, ok := targets[d]; ok {
						dependents[d] = append(dependents[d], n.Key)
					}
				}
			}
			var mu sync.Mutex
			done := map[string]bool{}
			started := map[string]bool{}
			running, failed := 0, 0
			type outcome struct {
				h     opHandle
				err   error
				ready bool
			}
			results := make([]outcome, len(order))
			index := map[string]int{}
			for i, key := range order {
				index[key] = i
			}
			wake := make(chan struct{}, len(order)+1)
			ready := func(key string) bool {
				for _, d := range dependents[key] {
					if !done[d] {
						return false
					}
				}
				return true
			}
			stopOne := func(key string) {
				t := targets[key]
				h, err := handle(c.Project(t.project).Jails().Stop(cmd.Context(), t.name, opts...))
				if err == nil {
					_, err = h.WaitAny(cmd.Context()) // silent: the lines are printed in the order of the stops, below
				}
				mu.Lock()
				results[index[key]] = outcome{h: h, err: err, ready: true}
				done[key] = true
				running--
				mu.Unlock()
				wake <- struct{}{}
			}
			skipped := map[string]bool{}
			for _, key := range order {
				if ok, err := a.dry("stop jail "+key, nil); ok || err != nil {
					if err != nil {
						return err
					}
					done[key], started[key], skipped[key] = true, true, true
					results[index[key]].ready = true
				}
			}
			printed := 0
			printReady := func() {
				for printed < len(order) && results[printed].ready {
					key := order[printed]
					if r := results[printed]; !skipped[key] {
						err := r.err
						if err == nil {
							err = a.finishOp(cmd.Context(), r.h, "jail", key, "stopped", nil)
						}
						if err != nil {
							failed++
							fprintln(a.env.Stderr, fmt.Sprintf("jail %s: %v", key, err))
						}
					}
					printed++
				}
			}
			for {
				mu.Lock()
				for _, key := range order {
					if started[key] || running >= stopAllParallel || !ready(key) {
						continue
					}
					started[key] = true
					running++
					go stopOne(key)
				}
				finished := len(started) == len(order) && running == 0
				if !finished && running == 0 {
					// nothing may start (a cycle in boot.depends): the first jail left goes, the rest follow it
					for _, key := range order {
						if !started[key] {
							started[key] = true
							running++
							go stopOne(key)
							break
						}
					}
				}
				mu.Unlock()
				mu.Lock()
				printReady()
				mu.Unlock()
				if finished {
					break
				}
				<-wake
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d jails could not be stopped", failed, len(order))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "do not wait for a graceful shutdown")
	cmd.Flags().StringVar(&grace, "grace", "", "time each jail gets to shut down: seconds, or a duration such as 30s")
	return cmd
}
