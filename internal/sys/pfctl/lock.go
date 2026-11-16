package pfctl

import (
	"context"
	"os"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// LockPath is the file that serialises the changes to the packet filter across processes: the helper serves requests
// concurrently, and the hooks of jail.conf run in processes of their own, one for each jail that starts. pf(4) refuses
// a second ruleset transaction that begins while another one is open ("Device busy"), so changes are made one at a
// time. Reading needs no lock.
var LockPath = "/var/run/jailops-pf.lock"

// mutates reports whether a pfctl command line changes the packet filter: a load (-f without -n), a flush (-F, -k) or
// a change of a table.
func mutates(args []string) bool {
	if slices.Contains(args, "-n") {
		return false
	}
	if slices.Contains(args, "-F") || slices.Contains(args, "-k") || slices.Contains(args, "-f") {
		return true
	}
	if i := slices.Index(args, "-T"); i >= 0 && i+1 < len(args) {
		switch args[i+1] {
		case "add", "delete", "flush", "replace", "kill", "expire", "zero":
			return true
		}
	}
	return false
}

// lockPF takes the lock and returns the function that releases it. Where the file cannot be opened (a process that is
// not root, a test) nothing is locked.
func lockPF(ctx context.Context) (func(), error) {
	f, err := os.OpenFile(LockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
		}
		if err != unix.EWOULDBLOCK && err != unix.EINTR {
			f.Close()
			return func() {}, nil
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
