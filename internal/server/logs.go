package server

import (
	"strings"

	"jailops.net/jailops/internal/service"
	"jailops.net/jailops/sdk/api"
)

// logRoutes serves the unified log view (/api/v1/logs) and the forwarding
// settings (/api/v1/logs/forward).
func (s *Server) logRoutes() []route {
	svc := s.svc
	view := func(c *rc, v api.LogForward, err error) error {
		if err != nil {
			return err
		}
		c.sync(200, v, v.Status.Generation)
		return nil
	}
	return []route{
		{method: "GET", pattern: "/api/v1/logs", h: func(c *rc) error {
			q, err := api.ParseLogsQuery(c.r.URL.Query())
			if err != nil {
				return err
			}
			ctx := c.r.Context()
			if v := c.r.URL.Query().Get("all_projects"); v == "true" || v == "1" {
				ctx = service.WithProject(ctx, "") // every project the caller may use
			}
			v, err := svc.ReadLogs(ctx, q)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "GET", pattern: "/api/v1/logs/forward", h: func(c *rc) error {
			v, err := svc.LogForward(c.r.Context())
			return view(c, v, err)
		}},
		{method: "PUT", pattern: "/api/v1/logs/forward", h: func(c *rc) error {
			var spec api.LogForwardSpec
			if err := c.decode(&spec); err != nil {
				return err
			}
			expect, err := c.expect()
			if err != nil {
				return err
			}
			names := make([]string, 0, len(spec.Sinks))
			for _, k := range spec.Sinks {
				// the receiver without a path or query, which may hold a secret
				tr, hp, _ := k.SinkTarget()
				names = append(names, k.Name+"="+tr+"://"+hp)
			}
			c.detail = "sinks=" + auditValue(strings.Join(names, ","))
			v, err := svc.SetLogForward(c.r.Context(), spec, expect)
			return view(c, v, err)
		}},
		{method: "DELETE", pattern: "/api/v1/logs/forward", h: func(c *rc) error {
			v, err := svc.ResetLogForward(c.r.Context())
			return view(c, v, err)
		}},
		{method: "POST", pattern: "/api/v1/logs/forward/test", h: func(c *rc) error {
			var t api.LogForwardTest
			if err := c.decode(&t); err != nil {
				return err
			}
			c.detail = "sink=" + auditValue(t.Sink)
			v, err := svc.TestLogForward(c.r.Context(), t.Sink)
			if err != nil {
				return err
			}
			if !v.OK {
				c.detail += " failed"
			}
			c.sync(200, v, 0)
			return nil
		}},
	}
}
