//go:build !unix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !solaris && !aix

package cmd

import "syscall"

func setReusePort(c syscall.RawConn) error {
	return nil
}
