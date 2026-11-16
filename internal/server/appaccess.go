package server

import (
	"strings"

	"jailops.net/jailops/sdk/api"
)

// appAccessRoutes are who may connect to an installed app (docs/apps.md, "Who
// may connect"). Allow and deny answer at once, not as an operation: the
// connection string of a new role is in this answer only, and an operation's
// result would keep it.
func (s *Server) appAccessRoutes() []route {
	svc := s.svc
	return []route{
		{method: "GET", pattern: "/api/v1/jails/{name}/access", h: func(c *rc) error {
			v, err := svc.GetAppAccess(c.r.Context(), c.pathArg("name"))
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/jails/{name}/access", long: true, h: func(c *rc) error {
			var in api.AppAllow
			if err := c.decode(&in); err != nil {
				return err
			}
			c.object = "/api/v1/jails/" + c.pathArg("name") + "/access"
			c.detail = "allow source=" + auditValue(in.Source) + " ports=" + auditValue(strings.Join(in.Ports, ",")) + " db=" + auditValue(in.Database)
			v, err := svc.AllowApp(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
		{method: "POST", pattern: "/api/v1/jails/{name}/access/deny", long: true, h: func(c *rc) error {
			var in api.AppDeny
			if err := c.decode(&in); err != nil {
				return err
			}
			c.object = "/api/v1/jails/" + c.pathArg("name") + "/access"
			c.detail = "deny source=" + auditValue(in.Source)
			v, err := svc.DenyApp(c.r.Context(), c.pathArg("name"), in)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
	}
}
