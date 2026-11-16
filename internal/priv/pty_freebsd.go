//go:build freebsd

package priv

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fionread is FIONREAD, _IOR('f', 127, int): the bytes waiting to be read.
const fionread = 0x4004667f

// fiodgname is FIODGNAME, _IOW('f', 120, struct fiodgname_arg) on LP64: the
// ioctl that returns the devfs name of a descriptor's device.
const fiodgname = 0x80106678

type fiodgnameArg struct {
	Len int32
	Buf unsafe.Pointer
}

// openPTY allocates a pseudo-terminal pair the way posix_openpt(3) does on
// FreeBSD: the posix_openpt system call returns the master (there is no
// /dev/ptmx), FIODGNAME names the slave below /dev (pts/<n>), and grantpt and
// unlockpt have nothing to do for pts(4).
func openPTY() (master, slave *os.File, err error) {
	fd, _, errno := unix.Syscall(unix.SYS_POSIX_OPENPT, uintptr(unix.O_RDWR|unix.O_NOCTTY), 0, 0)
	if errno != 0 {
		return nil, nil, fmt.Errorf("posix_openpt: %w", errno)
	}
	_ = unix.SetNonblock(int(fd), true) // so that the runtime poller owns reads and writes
	master = os.NewFile(fd, "ptm")
	name := make([]byte, 128)
	arg := fiodgnameArg{Len: int32(len(name)), Buf: unsafe.Pointer(&name[0])}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, fiodgname, uintptr(unsafe.Pointer(&arg))); errno != 0 {
		master.Close()
		return nil, nil, fmt.Errorf("naming the pty slave: %w", errno)
	}
	n := 0
	for n < len(name) && name[n] != 0 {
		n++
	}
	slave, err = os.OpenFile("/dev/"+string(name[:n]), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
