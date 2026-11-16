// Package hostdir holds what is known of a directory of the host that a volume gives to jails: whether it is still
// on its mount. The helper makes the probe (it alone may look below the directories the host operator allows); the
// layers above only read the answer.
package hostdir

import (
	"context"
	"jailops.net/jailops/internal/supervise"
	"time"
)

// Probe is the answer of a probe of a host directory.
type Probe struct {
	// Mounted says that a mount point lies on the way to the directory, so that it is the mount's and not an empty
	// directory of the host left behind when the mount went away.
	Mounted  bool
	Writable bool
	// Detail says what is wrong when the directory is not usable.
	Detail string
}

// Usable reports whether the directory may be given to a jail: it is on a mount and, when a file was asked for (write),
// a file could be made in it.
func (p Probe) Usable(write bool) bool { return p.Mounted && (!write || p.Writable) }

// Lost is the reason shown for a directory that is not usable: the detail the probe gave or, when a write was asked for
// and the directory only takes no file, what that means.
func (p Probe) Lost(write bool) string {
	switch {
	case p.Usable(write):
		return ""
	case p.Detail != "":
		return p.Detail
	case !p.Mounted:
		return "the directory is not on a mount"
	}
	return "no file can be created in the directory"
}

// Timeout is how long a probe may take. A share that stopped answering (a network mount that hangs) makes a look at it
// block, and a watch or a jail start must not wait for it: no answer in time is a lost directory.
const Timeout = 10 * time.Second

// Within runs a probe and gives up after d: the probe goroutine is left to finish on its own, and the answer is a lost
// directory that does not answer.
func Within(ctx context.Context, d time.Duration, probe func(context.Context) (Probe, error)) (Probe, error) {
	type result struct {
		p   Probe
		err error
	}
	ch := make(chan result, 1)
	go func() {
		var p Probe
		var err error
		if perr := supervise.Guard(nil, "host-directory-probe", func() { p, err = probe(ctx) }); perr != nil {
			err = perr
		}
		ch <- result{p, err}
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.p, r.err
	case <-t.C:
		return Probe{Detail: "the directory does not answer"}, nil
	case <-ctx.Done():
		return Probe{}, ctx.Err()
	}
}
