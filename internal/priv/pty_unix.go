//go:build linux

package priv

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openPTY allocates a pseudo-terminal pair: it opens /dev/ptmx (what
// posix_openpt does), unlocks and "grants" the slave, finds its name and opens
// it. (FreeBSD has its own in pty_freebsd.go.)
// fionread is FIONREAD: the bytes waiting to be read.
const fionread = 0x541b

func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	if err := unlockpt(fd); err != nil {
		master.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
