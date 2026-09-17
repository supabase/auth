//go:build unix || linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || aix

package cmd

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func setReusePort(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) // #nosec G115
	}); err != nil {
		return err
	}
	return serr
}
