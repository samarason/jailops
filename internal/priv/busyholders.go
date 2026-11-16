package priv

import (
	"context"
	"regexp"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
	"jailops.net/jailops/internal/sys/zfs"
	"jailops.net/jailops/sdk/api"
)

var reCannotUnmount = regexp.MustCompile(`cannot unmount '([^']+)'`)

// withHolders says, in a busy refusal of a destroy, what keeps the dataset open: the processes that have files, a
// working directory or a root in the mount point (fstat -f) and the mounts below it. A dataset that stays busy after
// the retries of the caller has a holder, and the holder is what the operator has to find; the error alone only names
// the mount point. Any other error is returned as it is.
func withHolders(ctx context.Context, r run.Runner, err error) error {
	if err == nil || r == nil || !(api.IsCode(err, api.CodeBusy) || zfs.IsBusy(err)) {
		return err
	}
	m := reCannotUnmount.FindStringSubmatch(err.Error())
	if m == nil || !strings.HasPrefix(m[1], "/") {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var held []string
	if res, rerr := r.Run(ctx, run.Cmd{Name: "/usr/bin/fstat", Args: []string{"-f", m[1]}, Timeout: 5 * time.Second}); rerr == nil {
		held = append(held, firstLines(string(res.Stdout), 8)...)
	}
	if res, rerr := r.Run(ctx, run.Cmd{Name: "/sbin/mount", Timeout: 5 * time.Second}); rerr == nil {
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			if strings.Contains(l, " on "+m[1]+"/") {
				held = append(held, "mount: "+strings.TrimSpace(l))
			}
		}
	}
	if len(held) == 0 {
		return err
	}
	return api.Errorf(api.CodeBusy, "%s\nheld by:\n  %s", strings.TrimSpace(err.Error()), strings.Join(held, "\n  "))
}

func firstLines(s string, n int) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
			if len(out) == n {
				break
			}
		}
	}
	return out
}
