//go:build !windows

package platform

import "context"

// StopContext 返回一个在 down 请求停止时取消的 context。
// Unix 上 down 直接发 SIGTERM，由调用方的 signal.NotifyContext 处理，这里无需额外通道。
func StopContext(parent context.Context) (context.Context, func(), error) {
	return parent, func() {}, nil
}
