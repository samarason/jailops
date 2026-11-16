package priv

import (
	"context"
	"strings"
	"time"

	"jailops.net/jailops/internal/sys/run"
)

// mountPoints lists the mount points of the host (mount -p, fstab format), one per mount. A list that cannot be read is
// nil: the check that needs it then has nothing to compare and says nothing.
func (l *Local) mountPoints(ctx context.Context) map[string]string {
	res, err := l.d.Runner.Run(ctx, run.Cmd{Name: "mount", Args: []string{"-p"}, Timeout: 10 * time.Second})
	if err != nil {
		return nil
	}
	return parseMountPoints(string(res.Stdout))
}

func parseMountPoints(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 3 {
			m[f[1]+"\x00"+f[0]] = f[1]
		}
	}
	return m
}

// landedElsewhere returns the mount points that appeared between before and after, other than dest.
func landedElsewhere(before, after map[string]string, dest string) []string {
	var out []string
	for k, mp := range after {
		if _, had := before[k]; !had && mp != dest {
			out = append(out, mp)
		}
	}
	return out
}

// checkMountLanded is the second half of a check that cannot be made once: the path of a mount lies in a tree a running
// jail controls, and between the helper's look at it and mount(8) the jail can swap a directory of the path for a
// symbolic link, which carries the mount to wherever it points. So the helper compares the host's mounts before and
// after, and a mount that appeared anywhere but at the path it was asked for is unmounted at once (the window is that
// of one mount(8) call, and what is left behind is nothing). before is nil when the list could not be read.
func (l *Local) checkMountLanded(ctx context.Context, before map[string]string, dest string) error {
	if before == nil {
		return nil
	}
	after := l.mountPoints(ctx)
	if after == nil {
		return nil
	}
	stray := landedElsewhere(before, after, dest)
	for _, mp := range stray {
		_, _ = l.d.Runner.Run(ctx, run.Cmd{Name: "umount", Args: []string{"-f", mp}, Timeout: 20 * time.Second})
	}
	if len(stray) > 0 {
		return forbidden("the mount landed on %s and not on %s (a link in the path): it was unmounted", strings.Join(stray, ", "), dest)
	}
	return nil
}
