//go:build linux || darwin

package platform

import "golang.org/x/sys/unix"

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	return err == nil
}

func disableEcho(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }, nil
}
