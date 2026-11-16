package server

import (
	"jailops.net/jailops/internal/service"
)

// bootRoutes serves the boot plan (/api/v1/boot): what the daemon starts after a boot of the host, in which order.
func (s *Server) bootRoutes() []route {
	svc := s.svc
	return []route{
		{method: "GET", pattern: "/api/v1/boot", h: func(c *rc) error {
			// the order is that of the whole host; the caller sees the jails of the project it names, or with
			// all_projects of every project it may use
			ctx := c.r.Context()
			if v := c.r.URL.Query().Get("all_projects"); v == "true" || v == "1" {
				ctx = service.WithProject(ctx, "")
			}
			v, err := svc.BootPlan(ctx)
			if err != nil {
				return err
			}
			c.sync(200, v, 0)
			return nil
		}},
	}
}
