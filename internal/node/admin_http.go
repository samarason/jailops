package node

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"jailops.net/jailops/internal/node/ctl"
	"jailops.net/jailops/internal/node/wire"
	"jailops.net/jailops/internal/repo/datastore"
	"jailops.net/jailops/internal/repo/format"
	"jailops.net/jailops/sdk/api"
)

// AdminHandler serves AdminRoutes. It MUST be served on a local unix socket
// only. The caller authenticates the peer (credentials of the unix socket) and
// attaches the administrator with WithActor; a request without one is refused.
// Long jobs (GC, verify, retention, reconcile) run in the background: the
// answer is the job, which GET .../jobs/{id} follows; with "?wait=1" the call
// answers when the job is final.
func (n *Node) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	h := map[string]func(http.ResponseWriter, *http.Request, Actor){
		"GET " + Base + "/admin/status":                                            n.aStatus,
		"GET " + Base + "/admin/sessions":                                          n.aSessions,
		"GET " + Base + "/admin/jobs":                                              n.aJobs,
		"GET " + Base + "/admin/jobs/{id}":                                         n.aJob,
		"POST " + Base + "/admin/jobs/{id}/cancel":                                 n.aCancel,
		"POST " + Base + "/admin/gc":                                               n.aGC,
		"POST " + Base + "/admin/verify":                                           n.aVerify,
		"POST " + Base + "/admin/retention":                                        n.aRetention,
		"POST " + Base + "/admin/reconcile":                                        n.aReconcile,
		"GET " + Base + "/admin/maintenance":                                       n.aGetMode,
		"PUT " + Base + "/admin/maintenance":                                       n.aSetMode,
		"PUT " + Base + "/admin/groups/{group}/snapshots/{snap}/protected":         n.aProtect,
		"POST " + Base + "/admin/groups/{group}/snapshots/{snap}/deletion":         n.aRequestDeletion,
		"DELETE " + Base + "/admin/groups/{group}/snapshots/{snap}/deletion":       n.aCancelDeletion,
		"POST " + Base + "/admin/groups/{group}/snapshots/{snap}/deletion/execute": n.aExecuteDeletion,
		"GET " + Base + "/admin/quarantine":                                        n.aQuarantine,
		"POST " + Base + "/admin/quarantine/purge":                                 n.aPurgeQuarantine,
		"POST " + Base + "/admin/quarantine/{id}":                                  n.aQuarantineChunk,
		"GET " + Base + "/admin/escrow":                                            n.aEscrowList,
		"DELETE " + Base + "/admin/escrow/{domain}":                                n.aDeleteEscrow,
		"GET " + Base + "/admin/retention-policies":                                n.aPolicies,
		"PUT " + Base + "/admin/retention-policies/{scope}":                        n.aSetPolicy,
		"DELETE " + Base + "/admin/retention-policies/{scope}":                     n.aDeletePolicy,
	}
	for _, rt := range AdminRoutes {
		fn, ok := h[rt.Key()]
		if !ok {
			panic("node: no handler for " + rt.Key())
		}
		delete(h, rt.Key())
		perm := rt.Perm
		mux.HandleFunc(rt.Key(), func(w http.ResponseWriter, r *http.Request) {
			a, ok := ActorFrom(r.Context())
			if !ok {
				writeErr(w, errf(api.CodeUnauthorized, "no authenticated administrator"))
				return
			}
			if !Satisfies(a.Perm, perm) {
				writeErr(w, errf(api.CodeForbidden, "%s cannot do this (needs %s)", a.Perm, perm))
				return
			}
			fn(w, r, a)
		})
	}
	if len(h) != 0 {
		panic(fmt.Sprintf("node: %d admin handlers have no route", len(h)))
	}
	return mux
}

func (n *Node) aStatus(w http.ResponseWriter, r *http.Request, a Actor) {
	st, err := n.Status(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (n *Node) aSessions(w http.ResponseWriter, r *http.Request, a Actor) {
	s, err := n.db.OpenSessions(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if s == nil {
		s = []ctl.Session{}
	}
	writeJSON(w, 200, s)
}

func (n *Node) aJobs(w http.ResponseWriter, r *http.Request, a Actor) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	j, err := n.db.Jobs(r.Context(), r.URL.Query().Get("kind"), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	if j == nil {
		j = []ctl.Job{}
	}
	writeJSON(w, 200, j)
}

func jobID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, errf(api.CodeInvalid, "malformed job id")
	}
	return id, nil
}

func (n *Node) aJob(w http.ResponseWriter, r *http.Request, a Actor) {
	id, err := jobID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	j, err := n.db.Job(r.Context(), id)
	if errors.Is(err, ctl.ErrNotFound) {
		err = errf(api.CodeNotFound, "no such job")
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, j)
}

func (n *Node) aCancel(w http.ResponseWriter, r *http.Request, a Actor) {
	id, err := jobID(r)
	if err == nil {
		err = n.CancelJob(r.Context(), id, a.Name)
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, nil)
}

// answerJob answers a started job, waiting for it when asked.
func (n *Node) answerJob(w http.ResponseWriter, r *http.Request, j ctl.Job, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	if r.URL.Query().Get("wait") != "" {
		fin, werr := n.WaitJob(r.Context(), j.ID)
		if werr != nil {
			writeErr(w, werr)
			return
		}
		j = fin
		writeJSON(w, 200, j)
		return
	}
	writeJSON(w, http.StatusAccepted, j)
}

// GCRequest is the body of POST /admin/gc.
type GCRequest struct {
	Grace  string `json:"grace,omitempty"` // a duration such as "36h"
	DryRun bool   `json:"dry_run,omitempty"`
}

func (n *Node) aGC(w http.ResponseWriter, r *http.Request, a Actor) {
	var req GCRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	var d time.Duration
	if req.Grace != "" {
		var err error
		if d, err = time.ParseDuration(req.Grace); err != nil {
			writeErr(w, errf(api.CodeInvalid, "malformed grace duration"))
			return
		}
	}
	j, err := n.StartGC(GCOptions{Grace: d, DryRun: req.DryRun}, a.Name)
	n.answerJob(w, r, j, err)
}

func (n *Node) aVerify(w http.ResponseWriter, r *http.Request, a Actor) {
	var req VerifyOptions
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	j, err := n.StartVerify(req, a.Name)
	n.answerJob(w, r, j, err)
}

func (n *Node) aRetention(w http.ResponseWriter, r *http.Request, a Actor) {
	var req RetentionOptions
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	j, err := n.StartRetention(req, a.Name)
	n.answerJob(w, r, j, err)
}

func (n *Node) aReconcile(w http.ResponseWriter, r *http.Request, a Actor) {
	j, err := n.StartReconcile(a.Name)
	n.answerJob(w, r, j, err)
}

// ModeBody is the body of PUT /admin/maintenance and its answer.
type ModeBody struct {
	Mode string `json:"mode"`
}

func (n *Node) aGetMode(w http.ResponseWriter, r *http.Request, a Actor) {
	writeJSON(w, 200, ModeBody{Mode: n.Mode().String()})
}

func (n *Node) aSetMode(w http.ResponseWriter, r *http.Request, a Actor) {
	var b ModeBody
	if err := decode(r, &b); err != nil {
		writeErr(w, err)
		return
	}
	m, ok := datastore.ParseMode(b.Mode)
	if !ok || b.Mode == "" {
		writeErr(w, errf(api.CodeInvalid, "mode must be online, read-only or offline"))
		return
	}
	if err := n.SetMode(r.Context(), m, a.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, ModeBody{Mode: m.String()})
}

// ProtectBody is the body of PUT .../protected.
type ProtectBody struct {
	Protected bool `json:"protected"`
}

func (n *Node) aProtect(w http.ResponseWriter, r *http.Request, a Actor) {
	var b ProtectBody
	if err := decode(r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if err := n.SetProtected(r.Context(), r.PathValue("group"), r.PathValue("snap"), b.Protected, a.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, b)
}

// DeletionBody is the body of POST .../deletion.
type DeletionBody struct {
	Delay string `json:"delay,omitempty"` // a duration; empty means the node's default
}

func (n *Node) aRequestDeletion(w http.ResponseWriter, r *http.Request, a Actor) {
	var b DeletionBody
	if err := decode(r, &b); err != nil {
		writeErr(w, err)
		return
	}
	var d time.Duration
	if b.Delay != "" {
		var err error
		if d, err = time.ParseDuration(b.Delay); err != nil {
			writeErr(w, errf(api.CodeInvalid, "malformed delay"))
			return
		}
	}
	del, err := n.RequestDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), a.Name, d)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, del)
}

func (n *Node) aCancelDeletion(w http.ResponseWriter, r *http.Request, a Actor) {
	if err := n.CancelDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), a.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, nil)
}

func (n *Node) aExecuteDeletion(w http.ResponseWriter, r *http.Request, a Actor) {
	if err := n.ExecuteDeletion(r.Context(), r.PathValue("group"), r.PathValue("snap"), a.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, nil)
}

func (n *Node) aQuarantine(w http.ResponseWriter, r *http.Request, a Actor) {
	q, err := n.ListQuarantine(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if q == nil {
		q = []QuarantinedChunk{}
	}
	writeJSON(w, 200, q)
}

func (n *Node) aPurgeQuarantine(w http.ResponseWriter, r *http.Request, a Actor) {
	c, err := n.PurgeQuarantine(r.Context(), 24*time.Hour)
	if err != nil {
		writeErr(w, err)
		return
	}
	n.audit(r.Context(), a.Name, "quarantine.purge", "", map[string]any{"removed": c}, a.Remote)
	writeJSON(w, 200, map[string]int{"removed": c})
}

func (n *Node) aQuarantineChunk(w http.ResponseWriter, r *http.Request, a Actor) {
	id, err := format.ParseID(r.PathValue("id"))
	if err != nil {
		writeErr(w, errf(api.CodeInvalid, "malformed chunk id"))
		return
	}
	moved, err := n.QuarantineChunk(r.Context(), id, a.Name, a.Remote)
	if err != nil {
		writeErr(w, asAPIError(err))
		return
	}
	writeJSON(w, 200, map[string]bool{"moved": moved})
}

func (n *Node) aEscrowList(w http.ResponseWriter, r *http.Request, a Actor) {
	d, err := n.ListEscrow(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, wire.EscrowList{Domains: d})
}

func (n *Node) aDeleteEscrow(w http.ResponseWriter, r *http.Request, a Actor) {
	if err := n.DeleteEscrow(r.Context(), r.PathValue("domain"), a.Name, a.Remote); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, nil)
}

func (n *Node) aPolicies(w http.ResponseWriter, r *http.Request, a Actor) {
	p, err := n.db.RetentionPolicies(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if p == nil {
		p = []ctl.RetentionPolicyRow{}
	}
	writeJSON(w, 200, p)
}

// PolicyBody is the body of PUT .../retention-policies/{scope}.
type PolicyBody struct {
	Policy   api.RetentionPolicy `json:"policy"`
	Timezone string              `json:"timezone,omitempty"`
}

func (n *Node) aSetPolicy(w http.ResponseWriter, r *http.Request, a Actor) {
	var b PolicyBody
	if err := decode(r, &b); err != nil {
		writeErr(w, err)
		return
	}
	if err := n.SetRetentionPolicy(r.Context(), r.PathValue("scope"), b.Policy, b.Timezone, a.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, 200, b)
}

func (n *Node) aDeletePolicy(w http.ResponseWriter, r *http.Request, a Actor) {
	err := n.db.DeleteRetentionPolicy(r.Context(), r.PathValue("scope"))
	if errors.Is(err, ctl.ErrNotFound) {
		err = errf(api.CodeNotFound, "no such policy")
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	n.audit(r.Context(), a.Name, "retention.policy.delete", r.PathValue("scope"), nil, a.Remote)
	writeJSON(w, 200, nil)
}
