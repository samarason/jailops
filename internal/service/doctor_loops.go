package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"jailops.net/jailops/internal/supervise"
	"jailops.net/jailops/sdk/api"
)

// doctorLoops warns when the supervisor started a background loop of the daemon again after a panic in the last day.
// The loop runs again (that is what the supervisor is for), but a panic is a bug that the operator wants to report.
func (s *Service) doctorLoops(c *checkSet) {
	var parts []string
	for _, l := range supervise.Loops() {
		if l.Recent == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s restarted %d times in the last day (last panic: %s)", l.Name, l.Recent, l.LastPanic))
	}
	if len(parts) == 0 {
		c.add("daemon.loops", api.DoctorOK, "no background loop of the daemon had to be restarted", "")
		return
	}
	c.add("daemon.loops", api.DoctorWarn, strings.Join(parts, "; "),
		"the loop runs again; the stack of each panic is in the log of jailopsd: report it as an issue")
}

// longOperation is how long an operation may run before doctor mentions it: the lock of its jail is held all that time,
// so one helper call that never returns keeps the jail busy until its deadline.
const longOperation = 15 * time.Minute

// doctorLongOperations warns of operations that have been running for a long time. Image builds and backups of a big
// jail can take that long; the line only makes a wedge visible.
func (s *Service) doctorLongOperations(ctx context.Context, c *checkSet) {
	ops, err := s.ListOperations(ctx)
	if err != nil {
		return
	}
	var parts []string
	for _, o := range ops {
		if o.Status != api.OpRunning || s.now().Sub(o.CreatedAt) < longOperation {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %q has run for %s", o.ID, o.Description, s.now().Sub(o.CreatedAt).Round(time.Minute)))
	}
	if len(parts) == 0 {
		c.add("operations.long", api.DoctorOK, "no operation has been running for more than 15 minutes", "")
		return
	}
	c.add("operations.long", api.DoctorWarn, strings.Join(parts, "; "),
		"`jailops op show ID` has the steps and their times; `jailops op cancel ID` stops one that may be cancelled")
}
