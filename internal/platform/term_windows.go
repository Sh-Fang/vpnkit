package platform

import "golang.org/x/sys/windows"

func isTerminal(fd int) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}

func disableEcho(fd int) (func(), error) {
	h := windows.Handle(fd)
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	mode := old&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT
	if err := windows.SetConsoleMode(h, mode); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, old) }, nil
}
