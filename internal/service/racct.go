package service

import (
	"context"
	"time"

	"jailops.net/jailops/sdk/api"
)

// limitsNotEnforcedWarning is the warning of a running jail that has memory, process or CPU limits on a host where
// kern.racct.enable is 0: the kernel accepts no rctl rule, so nothing enforces them.
const limitsNotEnforcedWarning = "limits.cpu, limits.memory and limits.pids are not enforced: kern.racct.enable is 0 (set it in /boot/loader.conf and reboot)"

// racctOn says whether the kernel's resource accounting is on. The answer is kept for a few seconds: a list of jails
// asks once, not once per jail.
func (s *Service) racctOn(ctx context.Context) bool {
	s.mu.RLock()
	at, on := s.racctAt, s.racctVal
	s.mu.RUnlock()
	if !at.IsZero() && s.now().Sub(at) < 10*time.Second {
		return on
	}
	v, err := s.sysctl(ctx, "kern.racct.enable")
	on = err != nil || v == "1" // an unreadable sysctl is not a reason to warn
	s.mu.Lock()
	s.racctAt, s.racctVal = s.now(), on
	s.mu.Unlock()
	return on
}

// limitsCondition is the condition of a running jail whose resource limits are stored but cannot be enforced.
func (s *Service) limitsCondition(ctx context.Context, j api.Jail) (api.Condition, string, bool) {
	r := s.effective(j).Resources
	if (r.Memory == "" && r.PIDs == 0 && r.CPU == 0) || s.racctOn(ctx) {
		return api.Condition{}, "", false
	}
	return api.Condition{Type: "Limits", Status: api.ConditionFalse, Reason: "NotEnforced", Message: limitsNotEnforcedWarning, Since: s.now().UTC()},
		limitsNotEnforcedWarning, true
}
