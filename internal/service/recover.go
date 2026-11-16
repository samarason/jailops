package service

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"jailops.net/jailops/internal/lifecycle"
	"jailops.net/jailops/internal/plan"
	"jailops.net/jailops/sdk/api"
)

// RecoveryOutcome says what startup recovery did with one interrupted run.
type RecoveryOutcome struct {
	Run    string
	Action string // rolled-back, completed, dropped, needs-attention
	Detail string
}

// recoverInterrupted resolves what the previous process left behind: the
// operations that were running become failed ("interrupted"), and every
// journalled plan run is rolled back through the plan journal, so the pool is
// consistent and the jail startable on its old generation.
func (s *Service) recoverInterrupted(ctx context.Context) error {
	ops, err := s.d.DB.Operations.MarkInterrupted(ctx)
	if err != nil {
		return err
	}
	byID := map[string]*api.Operation{}
	for _, o := range ops {
		byID[o.ID] = o
	}
	recs, err := s.journal.List(ctx)
	if err != nil {
		return err
	}
	// An installation is resolved after the runs of its steps (the start of
	// its jail rolls back first), so it sees what they left.
	slices.SortStableFunc(recs, func(a, b plan.Record) int {
		return cmp.Compare(boolInt(strings.HasPrefix(a.ID, "app-install/")), boolInt(strings.HasPrefix(b.ID, "app-install/")))
	})
	var outcomes []RecoveryOutcome
	for _, rec := range recs {
		out := s.recoverRun(ctx, rec)
		outcomes = append(outcomes, out)
		s.log.Warn("recovered an interrupted run", "run", out.Run, "action", out.Action, "detail", out.Detail)
		if req, ok := s.journal.getRequest(rec.ID); ok {
			op := byID[req.OpID]
			if op == nil {
				op, _ = s.d.DB.Operations.Get(ctx, req.OpID)
			}
			if op != nil && op.Error != nil {
				op.Error = op.Error.WithDetail("recovery", out.Action+": "+out.Detail)
				_ = s.d.DB.Operations.Put(ctx, *op)
			}
		}
		if out.Action != "needs-attention" {
			_ = s.journal.Delete(ctx, rec.ID)
			s.journal.deleteRequest(rec.ID)
		}
	}
	for _, id := range s.journal.requestIDs() {
		if _, ok, _ := s.journal.Get(ctx, id); !ok {
			s.journal.deleteRequest(id) // the run finished; only its request was left
		}
	}
	if len(outcomes) > 0 {
		_ = s.RefreshJails(ctx)
		s.mu.Lock()
		s.recovered = outcomes
		s.mu.Unlock()
	}
	return nil
}

// Recovered returns what the last startup recovery did.
func (s *Service) Recovered() []RecoveryOutcome {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]RecoveryOutcome(nil), s.recovered...)
}

func (s *Service) recoverRun(ctx context.Context, rec plan.Record) RecoveryOutcome {
	out := RecoveryOutcome{Run: rec.ID}
	kind, rest, _ := strings.Cut(rec.ID, "/")
	req, haveReq := s.journal.getRequest(rec.ID)
	fail := func(err error) RecoveryOutcome {
		out.Action, out.Detail = "needs-attention", err.Error()
		return out
	}
	recover := func(p *plan.Plan, err error) RecoveryOutcome {
		if err != nil {
			return fail(err)
		}
		found, err := s.life.RecoverRun(ctx, kind, rest, p)
		if err != nil {
			return fail(err)
		}
		out.Action = "rolled-back"
		if !found {
			out.Action, out.Detail = "dropped", "the run had already ended"
		}
		return out
	}
	if s.life == nil {
		return fail(fmt.Errorf("no host role"))
	}
	switch kind {
	case "create":
		if !haveReq || req.Create == nil {
			return fail(fmt.Errorf("the create request was not recorded"))
		}
		if key, err := lifecycle.KeyOf(*req.Create); err == nil {
			s.place(key, req.Create.Spec.Storage)
			defer s.unplace(key)
		}
		p, _, err := s.life.PlanCreate(ctx, *req.Create, true)
		return recover(p, err)
	case "upgrade":
		if !haveReq || req.Upgrade == nil || req.State == nil {
			return fail(fmt.Errorf("the upgrade request was not recorded"))
		}
		ur := *req.Upgrade
		ur.Stamp, ur.Resume = req.Stamp, req.State
		p, _, err := s.life.PlanUpgrade(ctx, rest, ur)
		if p == nil && err == nil {
			return fail(fmt.Errorf("the upgrade plan cannot be rebuilt"))
		}
		return recover(p, err)
	case "rollback":
		if !haveReq || req.Rollback == nil {
			return fail(fmt.Errorf("the rollback request was not recorded"))
		}
		if req.Rollback.Scope != api.RollbackRoot && req.Rollback.Scope != "" {
			out.Action, out.Detail = "dropped", "data rollbacks are forward-only; repeat the rollback if it did not finish"
			return out
		}
		if req.State == nil {
			return fail(fmt.Errorf("the rollback state was not recorded"))
		}
		ro := *req.Rollback
		ro.Stamp, ro.Resume = req.Stamp, req.State
		p, _, err := s.life.PlanRollbackRoot(ctx, rest, ro, req.TargetGen)
		if p == nil && err == nil {
			return fail(fmt.Errorf("the rollback plan cannot be rebuilt"))
		}
		return recover(p, err)
	case "copy":
		if !haveReq || req.Copy == nil {
			return fail(fmt.Errorf("the copy request was not recorded"))
		}
		if si, ok := s.storageOfJail(req.Copy.Src); ok {
			s.place(req.Copy.Dst, si.Name)
			defer s.unplace(req.Copy.Dst)
		}
		p, _, err := s.life.PlanCopy(ctx, req.Copy.Src, req.Copy.Dst, req.Copy.UUID, req.Stamp, true)
		return recover(p, err)
	case "start":
		p, err := s.life.PlanStart(ctx, rest)
		return recover(p, err)
	case "stop":
		if err := s.life.StopJail(ctx, rest); err != nil {
			return fail(err)
		}
		out.Action, out.Detail = "completed", "the jail was stopped"
		return out
	case "destroy":
		out.Action, out.Detail = "dropped", "the destroy was interrupted; delete the jail again to finish"
		return out
	case "app-install":
		// app-install/<key>: the jail is deleted while its start never
		// completed (the create's own run rolls a half-made jail back, the
		// start's own run a half-made start), stopped and kept afterwards, as
		// a failed installation leaves it.
		if _, ok, _ := s.journal.Get(ctx, "create/"+rest); ok {
			out.Action, out.Detail = "dropped", "the create of the jail is rolled back by its own run"
			return out
		}
		if ok, err := s.d.ZFS.Exists(ctx, s.lcfg.ContainerDS(rest)); err != nil {
			return fail(err)
		} else if !ok {
			out.Action, out.Detail = "dropped", "nothing was created"
			return out
		}
		if rec.Done < 2 { // create-jail and start-jail are the first two steps
			if _, err := s.life.DestroyJail(ctx, rest, true, false); err != nil {
				return fail(err)
			}
			out.Action, out.Detail = "rolled-back", "the jail of the interrupted installation never completed a start and was deleted"
			return out
		}
		if err := s.life.StopJail(ctx, rest); err != nil {
			return fail(err)
		}
		// kept for inspection means it does not come back with the host either
		if err := s.setJailAutostart(ctx, rest, false); err != nil {
			return fail(err)
		}
		out.Action, out.Detail = "completed", "the jail of the interrupted installation was stopped and kept for inspection; delete it to install again"
		return out
	case "image-build", "image-receive":
		// image-build/<image>/g<N>: remove the staging dataset of the run on
		// every pool (a receive stages on the pool that receives).
		img, g, _ := strings.Cut(rest, "/")
		n, _ := strconv.Atoi(strings.TrimPrefix(g, "g"))
		mgrs := s.imageManagers()
		if len(mgrs) == 0 || img == "" || n == 0 {
			return fail(fmt.Errorf("bad run id"))
		}
		for _, m := range mgrs {
			ds := m.Layout.StagingDS(img, n)
			if ok, _ := s.d.ImageZFS.Exists(ctx, ds); ok {
				if err := s.d.ImageZFS.DestroyRecursive(ctx, ds); err != nil {
					return fail(err)
				}
			}
		}
		out.Action, out.Detail = "rolled-back", "the staging dataset was removed"
		return out
	case "rename":
		// rename/<kind>/<project>/<name>: the steps were recorded before the first ran
		if !haveReq || req.Rename == nil {
			return fail(fmt.Errorf("the rename request was not recorded"))
		}
		found, err := s.planExec.Recover(ctx, rec.ID, s.renameExecPlan(req.Rename.Steps))
		if err != nil {
			return fail(err)
		}
		out.Action, out.Detail = "rolled-back", "the interrupted rename was undone; the old name is in force"
		if !found {
			out.Action, out.Detail = "dropped", "the run had already ended"
		}
		return out
	case "image-delete":
		out.Action, out.Detail = "dropped", "the generation delete was interrupted; delete it again to finish"
		return out
	case "create-volume":
		// create-volume/<project>_<name>: the dataset the run made is taken away again (the volume has no object yet:
		// the object is stored after the dataset is complete), so the name can be used again
		if !haveReq || req.Volume == nil {
			return fail(fmt.Errorf("the volume request was not recorded"))
		}
		found, err := s.life.RecoverCreateVolume(ctx, *req.Volume)
		if err != nil {
			return fail(err)
		}
		out.Action, out.Detail = "rolled-back", "the interrupted creation of the volume was undone; create it again"
		if !found {
			out.Action, out.Detail = "dropped", "the run had already ended"
		}
		return out
	}
	return fail(fmt.Errorf("unknown run kind %q", kind))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var _ = lifecycle.PropGen
