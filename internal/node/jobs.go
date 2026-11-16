package node

import (
	"context"
	"errors"
	"fmt"
	"jailops.net/jailops/internal/supervise"
	"time"

	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/sdk/api"
)

// runJob records a job, runs fn and records its outcome. Repository-wide kinds
// are exclusive: a second one while another runs is CodeBusy.
func (n *Node) runJob(ctx context.Context, kind, actor string, params any, fn func(ctx context.Context) (any, error)) (ctl.Job, error) {
	if n.closed.Load() {
		return ctl.Job{}, errf(api.CodeBusy, "the node is shutting down")
	}
	job, err := n.db.StartJob(ctx, kind, actor, params)
	if err != nil {
		if errors.Is(err, ctl.ErrConflict) {
			return job, errf(api.CodeBusy, "another repository-wide job is running").WithHint("see the job list")
		}
		return job, err
	}
	jctx, cancel := context.WithCancel(ctx)
	n.bgMu.Lock()
	n.cancels[job.ID] = cancel
	n.bgMu.Unlock()
	defer func() {
		cancel()
		n.bgMu.Lock()
		delete(n.cancels, job.ID)
		n.bgMu.Unlock()
	}()
	n.audit(ctx, actor, kind+".start", fmt.Sprint(job.ID), map[string]any{"params": params}, "")
	res, err := fn(jctx)
	state := ctl.JobSucceeded
	switch {
	case err != nil && errors.Is(err, context.Canceled):
		state = ctl.JobCancelled
	case err != nil:
		state = ctl.JobFailed
	}
	if ferr := n.db.FinishJob(context.WithoutCancel(ctx), job.ID, state, res, err); ferr != nil && err == nil {
		err = ferr
	}
	n.audit(ctx, actor, kind+".finish", fmt.Sprint(job.ID), map[string]any{"state": state}, "")
	job.State = state
	return job, err
}

// startAsync is runJob in the background; it returns once the job row exists.
func (n *Node) startAsync(kind, actor string, params any, fn func(ctx context.Context) (any, error)) (ctl.Job, error) {
	started := make(chan ctl.Job, 1)
	failed := make(chan error, 1)
	n.jobsDone.Add(1)
	go func() {
		defer n.jobsDone.Done()
		ctx := context.Background()
		job, err := n.db.StartJob(ctx, kind, actor, params)
		if err != nil {
			if errors.Is(err, ctl.ErrConflict) {
				err = errf(api.CodeBusy, "another repository-wide job is running")
			}
			failed <- err
			return
		}
		started <- job
		jctx, cancel := context.WithCancel(ctx)
		n.bgMu.Lock()
		n.cancels[job.ID] = cancel
		n.bgMu.Unlock()
		n.audit(ctx, actor, kind+".start", fmt.Sprint(job.ID), map[string]any{"params": params}, "")
		var res any
		if perr := supervise.Guard(nil, "node-job-"+kind, func() { res, err = fn(jctx) }); perr != nil {
			res, err = nil, perr
		}
		cancel()
		n.bgMu.Lock()
		delete(n.cancels, job.ID)
		n.bgMu.Unlock()
		state := ctl.JobSucceeded
		switch {
		case err != nil && errors.Is(err, context.Canceled):
			state = ctl.JobCancelled
		case err != nil:
			state = ctl.JobFailed
		}
		_ = n.db.FinishJob(context.WithoutCancel(ctx), job.ID, state, res, err)
		n.audit(ctx, actor, kind+".finish", fmt.Sprint(job.ID), map[string]any{"state": state}, "")
	}()
	select {
	case j := <-started:
		return j, nil
	case err := <-failed:
		return ctl.Job{}, err
	}
}

// CancelJob stops a running job between batches.
func (n *Node) CancelJob(ctx context.Context, id int64, actor string) error {
	n.bgMu.Lock()
	c, ok := n.cancels[id]
	n.bgMu.Unlock()
	if !ok {
		return errf(api.CodeNotFound, "no running job %d", id)
	}
	c()
	n.audit(ctx, actor, "job.cancel", fmt.Sprint(id), nil, "")
	return nil
}

// WaitJob waits until a job is final.
func (n *Node) WaitJob(ctx context.Context, id int64) (ctl.Job, error) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		j, err := n.db.Job(ctx, id)
		if err != nil {
			return j, err
		}
		if j.State != ctl.JobRunning && j.State != ctl.JobQueued {
			return j, nil
		}
		select {
		case <-ctx.Done():
			return j, ctx.Err()
		case <-t.C:
		}
	}
}
