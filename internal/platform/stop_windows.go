package platform

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows 无法向另一个控制台进程投递 Ctrl+C，down 改为置位 up 创建的命名事件，
// 让 up 走与 SIGTERM 相同的正常清理流程（docs/08 §4）。
// 用 Local\ 命名空间：up 与 down 在同一登录会话内运行。
func stopEventName(pid int) (*uint16, error) {
	return windows.UTF16PtrFromString(fmt.Sprintf(`Local\vpnkit-stop-%d`, pid))
}

// StopContext 创建本进程的停止事件，返回一个在事件被置位时取消的 context。
func StopContext(parent context.Context) (context.Context, func(), error) {
	name, err := stopEventName(os.Getpid())
	if err != nil {
		return parent, func() {}, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil {
		return parent, func() {}, fmt.Errorf("创建停止事件: %w", err)
	}
	// 第二个事件只用于让等待 goroutine 在 release 时退出。
	quit, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(ev)
		return parent, func() {}, fmt.Errorf("创建停止事件: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		r, err := windows.WaitForMultipleObjects([]windows.Handle{ev, quit}, false, windows.INFINITE)
		if err == nil && r == windows.WAIT_OBJECT_0 {
			cancel()
		}
	}()
	release := func() {
		_ = windows.SetEvent(quit)
		<-exited
		windows.CloseHandle(ev)
		windows.CloseHandle(quit)
		cancel()
	}
	return ctx, release, nil
}

// requestStop 置位 pid 的停止事件；对方未创建事件（例如旧版本）时返回错误。
func requestStop(pid int) error {
	name, err := stopEventName(pid)
	if err != nil {
		return err
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h)
}

// waitExit 等待进程退出，超时返回 false。
func waitExit(pid int, ms uint32) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return !ProcessAlive(pid)
	}
	defer windows.CloseHandle(h)
	r, err := windows.WaitForSingleObject(h, ms)
	return err == nil && r == windows.WAIT_OBJECT_0
}
