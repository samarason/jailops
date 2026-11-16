package service

import (
	"context"
	"sync"
	"time"

	"jailops.net/jailops/internal/validate"
	"jailops.net/jailops/sdk/api"
)

// hostReleaseCache keeps the host's release once it was read; a failed read is tried again after a minute.
type hostReleaseCache struct {
	mu    sync.Mutex
	value string
	tried time.Time
}

// hostOSRelease is the host's kern.osrelease ("15.1-RELEASE-p3"), or "" when it cannot be read here.
func (s *Service) hostOSRelease(ctx context.Context) string {
	c := &s.rel
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != "" || (!c.tried.IsZero() && s.now().Sub(c.tried) < time.Minute) {
		return c.value
	}
	c.tried = s.now()
	if s.d.Sysctl == nil && s.d.Run == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	r, err := s.sysctl(ctx, "kern.osrelease")
	if err != nil || validate.OSRelease("release", r) != nil {
		return ""
	}
	c.value = r
	return r
}

// hostBaseRelease is the release a new image of this host is made with ("15.1-RELEASE"), or "".
func (s *Service) hostBaseRelease() string {
	return api.BaseRelease(s.hostOSRelease(s.baseCtx))
}

// environment is the environment GET /api/v1 reports: the configured one, with the running release as the
// kernel version when the configuration does not say it. The console proposes it for the first image.
func (s *Service) environment() api.Environment {
	env := s.d.Env
	if env.KernelVersion == "" {
		env.KernelVersion = s.hostOSRelease(s.baseCtx)
	}
	return env
}
