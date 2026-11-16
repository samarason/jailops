package service

import (
	"context"
	"fmt"
	"strings"

	"jailops.net/jailops/sdk/api"
)

// doctorAppsAccess reports grants of app access whose firewall rule or
// pg_hba.conf line is missing on the host (drift), or whose pg_hba.conf lines name addresses a source no longer has.
func (s *Service) doctorAppsAccess(ctx context.Context, c *checkSet) {
	problems, n, err := s.accessDrift(ctx)
	switch {
	case err != nil:
		c.add("apps.access", api.DoctorUnknown, "the grants of app access cannot be read: "+err.Error(), "")
	case n == 0:
		return
	case len(problems) > 0:
		msg := fmt.Sprintf("%d problem(s) in %d grant(s): %s", len(problems), n, strings.Join(problems, "; "))
		c.add("apps.access", api.DoctorWarn, msg,
			"jailops app access APP shows each grant with what is missing; jailops app allow APP --from SOURCE writes it again, jailops app deny takes a grant back")
	default:
		c.add("apps.access", api.DoctorOK, fmt.Sprintf("%d grant(s); every firewall rule and pg_hba.conf line is in place", n), "")
	}
}
