package platform

import (
	"os"

	"golang.org/x/sys/windows"
)

// Privileged 判断当前进程是否以管理员身份运行（docs/08 §3）。
func Privileged() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// ProcessAlive 判断 pid 是否存在。
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// gracefulStopMs 略长于 docs/08 §4 规定的 10 秒清理时限，给 up 自身的超时留出余量。
const gracefulStopMs = 12_000

// Terminate 先通过停止事件请求 up 正常退出；事件不可用或超时未退出时强制结束，
// 残留路由与 NRPT 由调用方随后按 state.json 清理。
func Terminate(pid int) error {
	if requestStop(pid) == nil && waitExit(pid, gracefulStopMs) {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

const ElevateHint = "请以管理员身份运行"
