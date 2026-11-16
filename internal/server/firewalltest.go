package server

import "jailops.net/jailops/sdk/api"

// firewallTestRoutes serves the firewall test (extension "firewall_test"): whether a new connection would pass, and
// which rule decides at each anchor. It reads: nothing is changed or sent.
func (s *Server) firewallTestRoutes() []route {
	svc := s.svc
	return []route{
		{method: "POST", pattern: "/api/v1/firewall/test", h: func(c *rc) error {
			var req api.FirewallTestRequest
			if err := c.decode(&req); err != nil {
				return err
			}
			res, err := svc.FirewallTest(c.r.Context(), req)
			if err != nil {
				return err
			}
			c.sync(200, res, 0)
			return nil
		}},
	}
}
