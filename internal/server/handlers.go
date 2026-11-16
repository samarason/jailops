package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"jailops.net/jailops/internal/auth"
	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// ---- jails ----

func (s *Server) jailRoutes() []route {
	svc := s.svc
	jr := resource[api.Jail]{base: "/api/v1/jails", param: "name",
		list: svc.ListJails,
		get:  func(ctx context.Context, k string) (api.Jail, error) { return svc.GetJail(ctx, k) },
		put:  svc.UpdateJail, patch: svc.PatchJail,
		expanded: func(ctx context.Context, k string) (any, int64, error) {
			v, err := svc.ExpandedJail(ctx, k)
			return v, v.Jail.Metadata.Generation, err
		},
		gen: func(v api.Jail) int64 { return v.Metadata.Generation }, name: func(v api.Jail) string { return v.Metadata.Name },
	}.routes()
	jr = append(jr,
		route{method: "POST", pattern: "/api/v1/jails", h: func(c *rc) error {
			var j api.Jail
			if err := c.decode(&j); err != nil {
				return err
			}
			c.object = "/api/v1/jails/" + j.Metadata.Name
			op, err := svc.CreateJail(c.r.Context(), j)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/jails/{name}", h: func(c *rc) error {
			op, err := svc.DeleteJail(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}", h: func(c *rc) error {
			var j api.Jail
			if err := c.decode(&j); err != nil {
				return err
			}
			op, err := svc.CopyJail(c.r.Context(), c.pathArg("name"), j)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/exec", long: true, h: s.handleExec},
		// the browser console: a session instead of an HTTP upgrade (console.go)
		route{method: "POST", pattern: "/api/v1/jails/{name}/console", h: s.handleConsoleOpen},
		route{method: "GET", pattern: "/api/v1/jails/{name}/console/{id}/output", long: true, h: s.handleConsoleOutput},
		route{method: "POST", pattern: "/api/v1/jails/{name}/console/{id}/input", h: s.handleConsoleInput},
		route{method: "POST", pattern: "/api/v1/jails/{name}/console/{id}/resize", h: s.handleConsoleResize},
		route{method: "DELETE", pattern: "/api/v1/jails/{name}/console/{id}", h: s.handleConsoleClose},
		route{method: "GET", pattern: "/api/v1/jails/{name}/state", h: func(c *rc) error {
			v, err := svc.JailState(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/usage", h: func(c *rc) error {
			v, err := svc.JailUsage(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/logs", h: func(c *rc) error {
			v, truncated, err := svc.JailLogs(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			if truncated {
				c.w.Header().Set(api.HeaderTruncated, "true")
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/logs/{file...}", h: func(c *rc) error {
			q, err := api.ParseLogQuery(c.r.URL.Query())
			if err != nil {
				return err
			}
			v, err := svc.JailLog(c.r.Context(), c.pathArg("name"), c.pathArg("file"), q)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/app-draft", h: func(c *rc) error {
			v, err := svc.AppDraft(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "PUT", pattern: "/api/v1/jails/{name}/state", h: func(c *rc) error {
			var a api.JailAction
			if err := c.decode(&a); err != nil {
				return err
			}
			op, err := svc.JailAction(c.r.Context(), c.pathArg("name"), a)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		// the volumes a jail attaches (volumes.go has the volumes themselves)
		route{method: "GET", pattern: "/api/v1/jails/{name}/volumes", h: func(c *rc) error {
			v, err := svc.ListJailVolumes(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/volumes", h: func(c *rc) error {
			var req api.VolumeAttachRequest
			if err := c.decode(&req); err != nil {
				return err
			}
			c.object = "/api/v1/jails/" + c.pathArg("name")
			op, err := svc.AttachVolume(c.r.Context(), c.pathArg("name"), req)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/jails/{name}/volumes/{volume}", h: func(c *rc) error {
			c.object = "/api/v1/jails/" + c.pathArg("name")
			op, err := svc.DetachVolume(c.r.Context(), c.pathArg("name"), c.pathArg("volume"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/snapshots", h: func(c *rc) error {
			v, err := svc.ListSnapshots(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/snapshots", h: func(c *rc) error {
			// PROTOCOL.md: a JailSnapshot with an optional metadata.name. The web
			// UI sends {"comment": "..."}, which is accepted as well.
			var in struct {
				api.JailSnapshot
				Name    string `json:"name"`
				Comment string `json:"comment"`
			}
			if err := c.decodeOptional(&in); err != nil {
				return err
			}
			sn := in.JailSnapshot
			if sn.Metadata.Name == "" {
				sn.Metadata.Name = in.Name
			}
			if sn.Spec.Comment == "" {
				sn.Spec.Comment = in.Comment
			}
			op, err := svc.CreateSnapshot(c.r.Context(), c.pathArg("name"), sn)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "GET", pattern: "/api/v1/jails/{name}/snapshots/{snapshot}", h: func(c *rc) error {
			v, err := svc.GetSnapshot(c.r.Context(), c.pathArg("name"), c.pathArg("snapshot"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		route{method: "DELETE", pattern: "/api/v1/jails/{name}/snapshots/{snapshot}", h: func(c *rc) error {
			op, err := svc.DeleteSnapshot(c.r.Context(), c.pathArg("name"), c.pathArg("snapshot"))
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/rollback", h: func(c *rc) error {
			var rb api.JailRollback
			if err := c.decodeOptional(&rb); err != nil {
				return err
			}
			op, err := svc.RollbackJail(c.r.Context(), c.pathArg("name"), rb)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
		route{method: "POST", pattern: "/api/v1/jails/{name}/upgrade", h: func(c *rc) error {
			var up api.JailUpgrade
			if err := c.decodeOptional(&up); err != nil {
				return err
			}
			op, err := svc.UpgradeJail(c.r.Context(), c.pathArg("name"), up)
			if err != nil {
				return err
			}
			c.async(op)
			return nil
		}},
	)
	return jr
}

// ---- operations ----

func (s *Server) operationRoutes() []route {
	svc := s.svc
	return []route{
		{method: "GET", pattern: "/api/v1/operations", h: func(c *rc) error {
			v, err := svc.ListOperations(c.r.Context())
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "GET", pattern: "/api/v1/operations/{id}", h: func(c *rc) error {
			v, err := svc.GetOperation(c.r.Context(), c.pathArg("id"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "GET", pattern: "/api/v1/operations/{id}/wait", long: true, h: func(c *rc) error {
			secs := 60
			if t := c.r.URL.Query().Get("timeout"); t != "" {
				n, err := strconv.Atoi(t)
				if err != nil || n < 0 {
					return api.Errorf(api.CodeInvalid, "timeout must be a number of seconds")
				}
				secs = min(n, 300)
			}
			v, err := svc.WaitOperation(c.r.Context(), c.pathArg("id"), time.Duration(secs)*time.Second)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "DELETE", pattern: "/api/v1/operations/{id}", h: func(c *rc) error {
			if err := svc.CancelOperation(c.r.Context(), c.pathArg("id")); err != nil {
				return err
			}
			c.sync(200, struct{}{}, 0)
			return nil
		}},
	}
}

// ---- audit ----

func (s *Server) handleAudit(c *rc) error {
	q := c.r.URL.Query()
	aq := service.AuditQuery{Actor: q.Get("actor")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return api.Errorf(api.CodeInvalid, "limit must be a number")
		}
		aq.Limit = n
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return api.Errorf(api.CodeInvalid, "before must be an entry id")
		}
		aq.BeforeID = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return api.Errorf(api.CodeInvalid, "since must be an RFC 3339 time")
		}
		aq.Since = t
	}
	v, err := s.svc.ListAudit(c.r.Context(), aq)
	if err != nil {
		return err
	}
	c.sync(200, v, 0)
	return nil
}

// ---- events (Server-Sent Events) ----

func (s *Server) handleEvents(c *rc) error {
	fl, ok := c.w.(http.Flusher)
	if !ok {
		return api.Errorf(api.CodeInternal, "streaming is not supported on this connection")
	}
	var types map[string]bool
	if t := c.r.URL.Query().Get("type"); t != "" {
		types = map[string]bool{}
		for _, p := range strings.Split(t, ",") {
			p = strings.TrimSpace(p)
			switch api.EventType(p) {
			case api.EventLifecycle, api.EventOperation, api.EventLogging:
				types[p] = true
			default:
				return api.Errorf(api.CodeInvalid, "unknown event type %q", p)
			}
		}
	}
	after := int64(-1)
	if h := c.r.Header.Get("Last-Event-ID"); h != "" {
		n, err := strconv.ParseInt(h, 10, 64)
		if err != nil || n < 0 {
			return api.Errorf(api.CodeInvalid, "invalid Last-Event-ID %q", h)
		}
		after = n
	}
	release, err := s.streams.acquire(identityKey(c.actor))
	if err != nil {
		return err
	}
	defer release()
	rcn := http.NewResponseController(c.w)
	_ = rcn.SetWriteDeadline(time.Time{})
	ctx := c.r.Context()
	visible, err := s.svc.EventFilter(ctx)
	if err != nil {
		return err
	}
	gen := s.svc.CredentialGeneration()
	ch := s.svc.Events().Subscribe(ctx, after)
	h := c.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	c.w.WriteHeader(http.StatusOK)
	c.status = 200
	fmt.Fprint(c.w, "retry: 3000\n\n")
	fl.Flush()
	ka := time.NewTicker(s.cfg.KeepAlive)
	defer ka.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ka.C:
			// a credential revoked or changed since the stream began ends it
			if !s.stillAuthorized(c) {
				return nil
			}
			if _, err := fmt.Fprint(c.w, ": ping\n\n"); err != nil {
				return nil
			}
			fl.Flush()
		case se, ok := <-ch:
			if !ok {
				return nil
			}
			if g := s.svc.CredentialGeneration(); g != gen {
				if !s.stillAuthorized(c) {
					return nil
				}
				gen = g
			}
			if types != nil && !types[string(se.Event.Type)] {
				continue
			}
			if !visible(se.Event) {
				continue
			}
			data, _ := json.Marshal(se.Event)
			if _, err := fmt.Fprintf(c.w, "id: %d\nevent: %s\ndata: %s\n\n", se.ID, se.Event.Type, data); err != nil {
				return nil
			}
			fl.Flush()
		}
	}
}

// ---- authentication endpoints ----

func (s *Server) authRoutes() []route {
	svc := s.svc
	secure := func(c *rc) bool { return c.r.TLS != nil }
	return []route{
		{method: "POST", pattern: "/api/v1/auth/login", h: func(c *rc) error {
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
				TOTP     string `json:"totp"`
			}
			if err := c.decode(&req); err != nil {
				return err
			}
			// the user name is the caller's text: an anonymous request writes none of its body into the audit log
			host, _ := remoteAddr(c.r)
			sess, err := svc.Login(c.r.Context(), req.Username, req.Password, req.TOTP, host)
			if err != nil {
				return err
			}
			c.actor = service.Actor{Name: sess.User, Kind: "user", Perm: sess.Perm, Remote: host, Projects: sess.Projects, Global: sess.Global}
			maxAge := time.Until(sess.ExpiresAt)
			http.SetCookie(c.w, auth.SessionCookie(sess.ID, secure(c), maxAge))
			// The CSRF cookie is readable by the page, which echoes it in X-CSRF-Token.
			http.SetCookie(c.w, &http.Cookie{Name: "jailops_csrf", Value: sess.CSRF, Path: "/", Secure: secure(c),
				SameSite: http.SameSiteStrictMode, MaxAge: int(maxAge / time.Second)})
			c.sync(200, map[string]any{"user": sess.User, "permission": sess.Perm, "projects": sess.Projects, "global": sess.Global,
				"expires_at": sess.ExpiresAt, "csrf": sess.CSRF}, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/auth/logout", h: func(c *rc) error {
			if c.session != "" {
				if err := svc.Logout(c.r.Context(), c.session); err != nil {
					return err
				}
			}
			http.SetCookie(c.w, auth.ClearSessionCookie(secure(c)))
			http.SetCookie(c.w, &http.Cookie{Name: "jailops_csrf", Path: "/", MaxAge: -1, Secure: secure(c)})
			c.sync(200, struct{}{}, 0)
			return nil
		}},
		{method: "GET", pattern: "/api/v1/auth/session", h: func(c *rc) error {
			out := api.Identity{User: c.actor.Name, Kind: c.actor.Kind, Permission: c.actor.Perm, Projects: c.actor.Projects, Global: c.actor.Global}
			if c.actor.Kind == "user" {
				if info, err := svc.WhoAmI(c.r.Context(), c.actor.Name); err == nil {
					out.TOTP = info.TOTP
				}
			}
			c.sync(200, out, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/auth/password", h: func(c *rc) error {
			var req struct {
				Current string `json:"current"`
				New     string `json:"new"`
			}
			if err := c.decode(&req); err != nil {
				return err
			}
			if c.actor.Kind != "user" {
				return api.Errorf(api.CodeInvalid, "only user accounts have a password")
			}
			if err := svc.ChangePassword(c.r.Context(), c.actor.Name, req.Current, req.New); err != nil {
				return err
			}
			c.sync(200, struct{}{}, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/auth/totp", h: func(c *rc) error {
			if c.actor.Kind != "user" {
				return api.Errorf(api.CodeInvalid, "only user accounts have a second factor")
			}
			// enrolment starts with the password; the code of the new secret confirms it
			var req struct {
				Code     string `json:"code"`
				Password string `json:"password"`
			}
			if err := c.decodeOptional(&req); err != nil {
				return err
			}
			if req.Code == "" {
				v, err := svc.StartTOTP(c.r.Context(), c.actor.Name, req.Password)
				if err != nil {
					return err
				}
				c.sync(200, v, 0)
				return nil
			}
			codes, err := svc.ConfirmTOTP(c.r.Context(), c.actor.Name, req.Code)
			if err != nil {
				return err
			}
			c.sync(200, map[string]any{"recovery_codes": codes}, 0)
			return nil
		}},
		{method: "DELETE", pattern: "/api/v1/auth/totp", h: func(c *rc) error {
			if c.actor.Kind != "user" {
				return api.Errorf(api.CodeInvalid, "only user accounts have a second factor")
			}
			var req struct {
				Password string `json:"password"`
			}
			if err := c.decodeOptional(&req); err != nil {
				return err
			}
			if err := svc.DisableTOTP(c.r.Context(), c.actor.Name, req.Password); err != nil {
				return err
			}
			c.sync(200, struct{}{}, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/auth/recovery-codes", h: func(c *rc) error {
			if c.actor.Kind != "user" {
				return api.Errorf(api.CodeInvalid, "only user accounts have recovery codes")
			}
			var req struct {
				Password string `json:"password"`
			}
			if err := c.decodeOptional(&req); err != nil {
				return err
			}
			codes, err := svc.RecoveryCodes(c.r.Context(), c.actor.Name, req.Password)
			if err != nil {
				return err
			}
			c.sync(200, map[string]any{"recovery_codes": codes}, 0)
			return nil
		}},
	}
}
