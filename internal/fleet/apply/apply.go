// Package apply executes a plan through the SDK.
//
// Safety rules:
//
//   - Nothing runs if the plan has an error, an ownership refusal, or a
//     refuse-worthy change without Force.
//   - Update and delete re-read the live object and re-check that this
//     fleet owns it immediately before writing, and write with its ETag, so a
//     concurrent change is a conflict, never an overwrite.
//   - Deletes run only with Prune, and only for owned objects.
//   - On a host, the first failure stops that host (later objects may depend
//     on it); other hosts continue.
package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"jailops.net/jailops/internal/fleet/applylog"
	"jailops.net/jailops/internal/fleet/model"
	"jailops.net/jailops/internal/fleet/plan"
	"jailops.net/jailops/sdk"
	"jailops.net/jailops/sdk/api"
)

// Options tune an apply.
type Options struct {
	// Prune also deletes owned objects the repository no longer declares.
	Prune bool
	// Force allows refuse-worthy changes.
	Force bool
	Log   *applylog.Log
	Out   io.Writer
}

// Outcome of one item.
type Outcome struct {
	Item   plan.Item
	Status string // ok, failed, skipped
	Err    error
}

// Result of an apply.
type Result struct {
	Outcomes []Outcome
}

// Failed returns the failed outcomes.
func (r Result) Failed() []Outcome {
	var out []Outcome
	for _, o := range r.Outcomes {
		if o.Status == "failed" {
			out = append(out, o)
		}
	}
	return out
}

// Check returns why the plan must not be applied, or nil.
func Check(p *plan.Plan, opt Options) error {
	if err := p.Err(); err != nil {
		return fmt.Errorf("the plan has errors, nothing applied:\n%w", err)
	}
	if refs := p.Refusals(); len(refs) > 0 {
		var b strings.Builder
		for _, i := range refs {
			fmt.Fprintf(&b, "\n  %s %s on %s: %s", i.Kind, i.Name, i.Host, strings.Join(i.Details, "; "))
		}
		return fmt.Errorf("refusing to touch objects this fleet does not own (use `adopt --claim` to take one over deliberately):%s", b.String())
	}
	if d := p.Dangerous(opt.Prune); len(d) > 0 && !opt.Force {
		var b strings.Builder
		for _, i := range d {
			for _, g := range i.Dangers {
				fmt.Fprintf(&b, "\n  %s %s on %s: %s", i.Kind, i.Name, i.Host, g)
			}
		}
		return fmt.Errorf("refusing: dangerous changes need --force:%s", b.String())
	}
	return nil
}

// Run applies the plan. It returns an error when Check fails or any item failed.
func Run(ctx context.Context, s *plan.Session, p *plan.Plan, opt Options) (Result, error) {
	if opt.Out == nil {
		opt.Out = io.Discard
	}
	var res Result
	if err := Check(p, opt); err != nil {
		opt.Log.Write(applylog.KindApplyError, map[string]any{"error": err.Error(), "phase": "check"})
		return res, err
	}
	opt.Log.Write(applylog.KindApplyStart, map[string]any{
		"fleet": p.FleetID, "hosts": p.Hosts, "summary": p.Summary(), "prune": opt.Prune, "force": opt.Force,
	})
	me := s.Fleet.ManagedBy()
	byHost := map[string][]plan.Item{}
	for _, it := range p.Items {
		byHost[it.Host] = append(byHost[it.Host], it)
	}
	for _, host := range p.Hosts {
		stopped := false
		for _, it := range byHost[host] {
			switch it.Action {
			case plan.ActionMatch, plan.ActionUnmanaged:
				continue
			case plan.ActionBlocked:
				res.add(opt, it, "skipped", errors.New(strings.Join(it.Details, "; ")))
				continue
			case plan.ActionDelete:
				if !opt.Prune {
					res.add(opt, it, "skipped", errors.New("owned but undeclared; pass --prune to delete"))
					continue
				}
			}
			if stopped {
				res.add(opt, it, "skipped", errors.New("an earlier change on this host failed"))
				continue
			}
			if err := ctx.Err(); err != nil {
				return res, err
			}
			if ch, ok := it.Spec.(plan.AppChange); ok {
				once, err := applyApp(ctx, s, it, ch)
				if err != nil {
					res.add(opt, it, "failed", err)
					stopped = true
					continue
				}
				res.add(opt, it, "ok", nil)
				for _, l := range once {
					// to the person running sync only: never to the apply log
					fmt.Fprintln(opt.Out, l)
				}
				continue
			}
			if err := applyItem(ctx, s, it, me); err != nil {
				res.add(opt, it, "failed", err)
				stopped = true
				continue
			}
			res.add(opt, it, "ok", nil)
		}
	}
	// Second writes (a project's mandatory firewall policy, which exists
	// only once the project's policies have been created).
	for _, host := range p.Hosts {
		for _, it := range byHost[host] {
			if it.Post == nil || (it.Action != plan.ActionCreate && it.Action != plan.ActionUpdate) {
				continue
			}
			if failedOn(res, host) {
				break
			}
			post := it
			post.Action, post.Spec = plan.ActionUpdate, *it.Post
			post.Details = []string{"set the mandatory firewall policy"}
			if err := applyItem(ctx, s, post, me); err != nil {
				res.add(opt, post, "failed", err)
				break
			}
			res.add(opt, post, "ok", nil)
		}
	}
	failed := res.Failed()
	opt.Log.Write(applylog.KindApplyEnd, map[string]any{"fleet": p.FleetID, "summary": p.Summary(), "failed": len(failed)})
	if len(failed) > 0 {
		var errs []error
		for _, f := range failed {
			errs = append(errs, fmt.Errorf("%s %s on %s (%s): %w", f.Item.Kind, f.Item.Name, f.Item.Host, f.Item.Action, f.Err))
		}
		return res, errors.Join(errs...)
	}
	return res, nil
}

func failedOn(r Result, host string) bool {
	for _, o := range r.Outcomes {
		if o.Status == "failed" && o.Item.Host == host {
			return true
		}
	}
	return false
}

func (r *Result) add(opt Options, it plan.Item, status string, err error) {
	r.Outcomes = append(r.Outcomes, Outcome{it, status, err})
	data := map[string]any{"host": it.Host, "kind": string(it.Kind), "project": it.Project, "name": it.Name, "action": string(it.Action), "status": status}
	line := fmt.Sprintf("  %-8s %s %s", status, it.Host, it.Ref())
	if err != nil {
		data["error"] = err.Error()
		line += ": " + err.Error()
	}
	opt.Log.Write(applylog.KindChange, data)
	fmt.Fprintf(opt.Out, "%s (%s)\n", line, it.Action)
}

func applyItem(ctx context.Context, s *plan.Session, it plan.Item, me string) error {
	c, err := s.Client(ctx, it.Host)
	if err != nil {
		return err
	}
	c = plan.ScopeClient(c, it.Kind, it.Project)
	ad, err := plan.AdapterFor(it.Kind)
	if err != nil {
		return err
	}
	if it.Action == plan.ActionCreate || it.Action == plan.ActionUpdate {
		if it.Spec, err = plan.SealSops(s, it.Spec); err != nil {
			return err
		}
	}
	switch it.Action {
	case plan.ActionCreate:
		if err := ad.Create(ctx, c, it.Meta, it.Spec); err != nil {
			return err
		}
		if it.Kind == api.KindJail {
			return afterCreate(ctx, c, it)
		}
		if it.Build {
			return buildImage(ctx, c, it.Name)
		}
		return nil
	case plan.ActionUpdate:
		live, etag, err := ad.Get(ctx, c, it.Name)
		if err != nil {
			return err
		}
		if live.Meta.ManagedBy != me {
			return fmt.Errorf("ownership changed since planning: managed_by is now %q", live.Meta.ManagedBy)
		}
		meta := it.Meta
		meta.UUID = "" // the server keeps the identity it assigned
		if err := ad.Update(ctx, c, meta, it.Spec, etag); err != nil {
			return err
		}
		if it.Build {
			return buildImage(ctx, c, it.Name)
		}
		return nil
	case plan.ActionDelete:
		live, _, err := ad.Get(ctx, c, it.Name)
		if err != nil {
			return err
		}
		if live.Meta.ManagedBy != me {
			return fmt.Errorf("ownership changed since planning: managed_by is now %q", live.Meta.ManagedBy)
		}
		return ad.Delete(ctx, c, it.Name)
	}
	return fmt.Errorf("action %q is not executable", it.Action)
}

// buildImage builds the next generation of an image and waits for it. Only a declared `build: true` image on a host
// that holds no generation gets here.
func buildImage(ctx context.Context, c *sdk.Client, name string) error {
	op, err := c.Images().Build(ctx, name, api.ImageBuild{})
	if err == nil {
		_, err = op.Wait(ctx)
	}
	if err != nil {
		return fmt.Errorf("image %s: building the first generation failed: %w", name, err)
	}
	return nil
}

// afterCreate runs a new jail's start flag and typed hooks, in order.
func afterCreate(ctx context.Context, c *sdk.Client, it plan.Item) error {
	o := it.Desired
	run := func(what string, op *sdk.Operation[api.Jail], err error) error {
		if err == nil {
			_, err = op.Wait(ctx)
		}
		if err != nil {
			return fmt.Errorf("jail created, but %s failed: %w", what, err)
		}
		return nil
	}
	if o.Start {
		op, err := c.Jails().Start(ctx, it.Name)
		if err := run("start", op, err); err != nil {
			return err
		}
	}
	for i, h := range o.After {
		what := fmt.Sprintf("hook %d (%s)", i, h.Action)
		switch h.Action {
		case model.HookStart:
			op, err := c.Jails().Start(ctx, it.Name)
			if err := run(what, op, err); err != nil {
				return err
			}
		case model.HookRestart:
			op, err := c.Jails().Restart(ctx, it.Name)
			if err := run(what, op, err); err != nil {
				return err
			}
		case model.HookSnapshot:
			op, err := c.Jails().Snapshots(it.Name).Create(ctx, h.Name, "created by jailops-sync")
			if err == nil {
				_, err = op.Wait(ctx)
			}
			if err != nil {
				return fmt.Errorf("jail created, but %s failed: %w", what, err)
			}
		case model.HookExec:
			// Typed argv, never a shell.
			sess, err := c.Jails().Exec(ctx, it.Name, h.Argv, sdk.ExecOptions{})
			if err != nil {
				return fmt.Errorf("jail created, but %s failed: %w", what, err)
			}
			code, err := sess.Run(nil, nil, nil)
			if err == nil && code != 0 {
				err = fmt.Errorf("exit status %d", code)
			}
			if err != nil {
				return fmt.Errorf("jail created, but %s failed: %w", what, err)
			}
		}
	}
	return nil
}

// applyApp installs an app or changes who may reach it. The lines it returns
// are for the person running sync and nothing else: a connection string with
// the password of a new database role, which the host keeps nowhere and sync
// writes nowhere.
func applyApp(ctx context.Context, s *plan.Session, it plan.Item, ch plan.AppChange) ([]string, error) {
	c, err := s.Client(ctx, it.Host)
	if err != nil {
		return nil, err
	}
	c = c.Project(it.Project)
	switch {
	case ch.Install != nil:
		op, err := c.Apps().Install(ctx, ch.App, *ch.Install)
		if err == nil {
			_, err = op.Wait(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("install app %s as jail %s: %w", ch.App, ch.Jail, err)
		}
		return nil, nil
	case ch.Allow != nil:
		allow := *ch.Allow
		allow.Rotate, allow.DryRun = false, false // re-applying never makes a new password
		r, err := c.Apps().Allow(ctx, ch.Jail, allow)
		if err != nil {
			return nil, err
		}
		if r.ConnectionString == "" {
			return nil, nil
		}
		return []string{
			fmt.Sprintf("    connection string for %s on %s/%s (shown once, stored nowhere; `jailops app allow %s --from %s --rotate` makes a new one):",
				allow.Source, it.Project, ch.Jail, ch.Jail, allow.Source),
			"      " + r.ConnectionString,
		}, nil
	case ch.Deny != nil:
		_, err := c.Apps().Deny(ctx, ch.Jail, *ch.Deny)
		return nil, err
	}
	return nil, fmt.Errorf("nothing to do for %s", it.Ref())
}
