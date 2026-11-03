package testserver

import (
	"net/netip"
	"sort"
	"time"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// Step 是控制通道剧本中的一步（docs/11 §2.3）。
// 文档示例为 YAML；依赖白名单不允许 YAML 库，剧本以 Go 预置，语义一致。
type Step struct {
	Cmd       *int32       // 发送一条只有命令码的 serverMsg
	SendIP    *wire.SendIP // 发送 SEND_IP（按候选布局编码）
	Raw       []byte       // 原样发送 40 字节（如错误魔数）
	Sleep     time.Duration
	Heartbeat bool // 进入循环：每 HeartbeatEvery 发一次 15，直到连接关闭
	Close     bool // 主动关闭连接
	Hold      bool // 什么都不发，保持连接直到客户端关闭
}

// Script 按本令牌第几次建立控制通道（从 1 开始）给出步骤，便于编排"先忙后成功"。
type Script func(attempt int) []Step

func cmd(c int32) Step { return Step{Cmd: &c} }

// DefaultSendIP 是剧本默认下发的地址（docs/11 §2.3）。
var DefaultSendIP = wire.SendIP{
	TapIP: netip.MustParseAddr("10.8.0.2"),
	LanIP: netip.MustParseAddr("10.8.0.1"),
}

func sendIP(mod func(*wire.SendIP)) Step {
	s := DefaultSendIP
	if mod != nil {
		mod(&s)
	}
	return Step{SendIP: &s}
}

func happySteps() []Step {
	return []Step{sendIP(nil), cmd(wire.CmdIPValid), cmd(wire.CmdGroupIDValid), {Heartbeat: true}}
}

// KickDelay 是 kick/shutdown/reset 剧本在运行后多久发出命令。
var KickDelay = 500 * time.Millisecond

var scripts = map[string]Script{
	"happy": func(int) []Step { return happySteps() },
	"busy-then-ok": func(n int) []Step {
		if n <= 3 {
			return []Step{cmd(wire.CmdBusyIPInUse), {Hold: true}}
		}
		return happySteps()
	},
	"kick": func(int) []Step {
		return []Step{sendIP(nil), cmd(wire.CmdIPValid), cmd(wire.CmdGroupIDValid), {Sleep: KickDelay}, cmd(wire.CmdIPKick), {Hold: true}}
	},
	"shutdown": func(int) []Step {
		return []Step{sendIP(nil), cmd(wire.CmdIPValid), cmd(wire.CmdGroupIDValid), {Sleep: KickDelay}, cmd(wire.CmdShutdown), {Hold: true}}
	},
	"reset": func(n int) []Step {
		if n == 1 {
			return []Step{sendIP(nil), cmd(wire.CmdIPValid), cmd(wire.CmdGroupIDValid), {Sleep: KickDelay}, cmd(wire.CmdServerReset), {Close: true}}
		}
		return happySteps()
	},
	"drop": func(n int) []Step {
		if n == 1 {
			return []Step{sendIP(nil), {Sleep: KickDelay}, {Close: true}}
		}
		return happySteps()
	},
	"bad-magic": func(int) []Step {
		return []Step{{Raw: append([]byte("XXXX"), make([]byte, 36)...)}, {Hold: true}}
	},
	"silent":      func(int) []Step { return []Step{sendIP(nil), {Hold: true}} },
	"big-packets": func(int) []Step { return happySteps() },
	"bad-sendip": func(int) []Step {
		return []Step{sendIP(func(s *wire.SendIP) { s.TapIP = netip.IPv4Unspecified() }), {Hold: true}}
	},
	"enc-required": func(int) []Step {
		return []Step{sendIP(func(s *wire.SendIP) { s.Enc = 1 }), cmd(wire.CmdIPValid), cmd(wire.CmdGroupIDValid), {Heartbeat: true}}
	},
	"no-valid": func(int) []Step { return []Step{sendIP(nil), {Heartbeat: true}} },
	"unknown-cmd": func(int) []Step {
		return []Step{sendIP(nil), cmd(wire.CmdIPValid), cmd(99), cmd(wire.CmdRecovered), {Heartbeat: true}}
	},
}

// ScriptNames 列出预置剧本。
func ScriptNames() []string {
	var out []string
	for k := range scripts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
