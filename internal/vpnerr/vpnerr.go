// Package vpnerr 定义错误类别与退出码映射（docs/00 §4.3）。
//
// 各业务包返回自己的具体哨兵错误，并用 fmt.Errorf("%w: %w", vpnerr.ErrX, specific)
// 同时挂上类别；CLI 只按类别映射退出码，不靠字符串匹配（AGENTS.md §3）。
package vpnerr

import "errors"

var (
	ErrUsage      = errors.New("参数错误")
	ErrAuth       = errors.New("认证失败")
	ErrTunnel     = errors.New("隧道建立失败")
	ErrPermission = errors.New("权限不足")
	ErrNetConfig  = errors.New("网络配置失败")
	ErrRejected   = errors.New("服务端拒绝")
)

// ExitCode 把错误映射为 docs/00 §4.3 的退出码。
func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, ErrUsage):
		return 2
	case errors.Is(err, ErrAuth):
		return 3
	case errors.Is(err, ErrTunnel):
		return 4
	case errors.Is(err, ErrPermission):
		return 5
	case errors.Is(err, ErrNetConfig):
		return 6
	case errors.Is(err, ErrRejected):
		return 7
	default:
		return 1
	}
}
