// Package route 负责路由与 DNS 分流的下发、记录与回滚（docs/07）。
//
// 命令生成是纯函数（按 goos 参数分支，任意平台都能单测）；执行通过 Runner 注入，
// 真实执行、--dry-run 打印、测试记录三种实现共用同一套逻辑。
package route

import "net/netip"

// Plan 是要下发到系统的分流配置。
type Plan struct {
	Device      string
	TapIP       netip.Addr
	MTU         int
	Routes      []netip.Prefix
	Bypass      []netip.Addr // 隧道服务端地址，防回环（docs/07 §2.2）
	DNSServers  []netip.Addr
	DNSSuffixes []string
}

// Result 是下发结果；部分网段失败不算整体失败（docs/07 §2.4）。
type Result struct {
	RoutesOK     []netip.Prefix
	RoutesFailed []string
	DNSEnabled   bool
	Warnings     []string
}
