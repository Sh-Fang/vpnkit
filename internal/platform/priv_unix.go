//go:build !windows

package platform

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Privileged 判断能否创建 TUN、改路由（docs/08 §3）。
func Privileged() bool {
	if os.Geteuid() == 0 {
		return true
	}
	return runtime.GOOS == "linux" && hasCapNetAdmin()
}

// hasCapNetAdmin 读 /proc/self/status 的 CapEff，CAP_NET_ADMIN 是第 12 位。
func hasCapNetAdmin() bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<12) != 0
		}
	}
	return false
}

// ProcessAlive 判断 pid 是否存在（EPERM 说明存在但属于他人）。
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// Terminate 请求进程优雅退出（SIGTERM，触发其 down 流程）。
func Terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

// ElevateHint 是权限不足时的提示。
const ElevateHint = "请用 sudo 运行（或为二进制授予 CAP_NET_ADMIN）"
