// Package command 把控制通道上的命令码映射为客户端动作，并给出重连退避策略（docs/04）。
package command

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// Action 是收到命令后客户端应做的事（docs/04 §1）。
type Action int

const (
	ActConfigure    Action = iota // 0 SEND_IP：进入配置阶段
	ActLog                        // 4/10/11：仅记录
	ActHeartbeat                  // 15：刷新对端活跃时间
	ActReconnectNow               // 3：立即重连，不退避
	ActBackoff                    // 5/6/7/9：退避后重连
	ActStop                       // 8/14：转 Stopped，不重连
	ActUnknown                    // 其他：记录并忽略，不断开
)

func (a Action) String() string {
	return [...]string{"configure", "log", "heartbeat", "reconnect_now", "backoff", "stop", "unknown"}[a]
}

// Decision 是对一条命令的判定。
type Decision struct {
	Code   int32
	Name   string
	Action Action
	Policy Policy // 仅 ActBackoff / ActReconnectNow 有意义
}

var names = map[int32]string{
	wire.CmdSendIP:         "SEND_IP",
	wire.CmdServerReset:    "SERVER_RESET",
	wire.CmdRecovered:      "RECOVERED",
	wire.CmdBusyIPInUse:    "RECONNECTLATER_IPISBUSY",
	wire.CmdBusyMemoryPool: "RECONNECTLATER_MEMORYPOOL",
	wire.CmdBusySystem:     "RECONNECTLATER_SYSTEMISBUSY",
	wire.CmdShutdown:       "SHUTDOWN",
	wire.CmdBusyConflict:   "RECONNECTLATER_CONFLICT",
	wire.CmdIPValid:        "IPVALID",
	wire.CmdGroupIDValid:   "GROUPIDVALID",
	wire.CmdIPKick:         "IPKICK",
	wire.CmdHeartbeat:      "HEARTBEAT",
}

// Name 返回命令名；未知码返回 UNKNOWN(n)。
func Name(code int32) string {
	if n, ok := names[code]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// Classify 实现 docs/04 §1 的命令表。
func Classify(code int32) Decision {
	d := Decision{Code: code, Name: Name(code)}
	switch code {
	case wire.CmdSendIP:
		d.Action = ActConfigure
	case wire.CmdRecovered, wire.CmdIPValid, wire.CmdGroupIDValid:
		d.Action = ActLog
	case wire.CmdHeartbeat:
		d.Action = ActHeartbeat
	case wire.CmdServerReset:
		d.Action, d.Policy = ActReconnectNow, PolicyReset
	case wire.CmdBusyIPInUse, wire.CmdBusyMemoryPool, wire.CmdBusySystem:
		d.Action, d.Policy = ActBackoff, PolicyBusy
	case wire.CmdBusyConflict:
		d.Action, d.Policy = ActBackoff, PolicyConflict
	case wire.CmdShutdown, wire.CmdIPKick:
		d.Action = ActStop
	default:
		d.Action = ActUnknown
	}
	return d
}

// Policy 是一类重连的退避参数（docs/04 §5）。
type Policy struct {
	Name       string
	Base       time.Duration
	Max        time.Duration
	MaxRetries int // 0 表示不限
}

var (
	PolicyReset    = Policy{Name: "reset", Base: 0, Max: 0, MaxRetries: 0}
	PolicyBusy     = Policy{Name: "busy", Base: 5 * time.Second, Max: 60 * time.Second, MaxRetries: 6}
	PolicyConflict = Policy{Name: "conflict", Base: 30 * time.Second, Max: 300 * time.Second, MaxRetries: 4}
	PolicyNetwork  = Policy{Name: "network", Base: 2 * time.Second, Max: 30 * time.Second, MaxRetries: 0}
)

// Delay 返回第 attempt 次（从 1 开始）重试前的等待：指数翻倍、封顶、±20% 抖动。
// rnd 返回 [0,1)，传 nil 用全局随机源；测试可传固定值。
func (p Policy) Delay(attempt int, rnd func() float64) time.Duration {
	if p.Base <= 0 || attempt < 1 {
		return 0
	}
	d := p.Base
	for i := 1; i < attempt && d < p.Max; i++ {
		d *= 2
	}
	if p.Max > 0 && d > p.Max {
		d = p.Max
	}
	if rnd == nil {
		rnd = rand.Float64
	}
	// 抖动避免多客户端同时重连（docs/04 §5）
	jitter := 0.8 + 0.4*rnd()
	return time.Duration(float64(d) * jitter)
}

// Exhausted 判断第 attempt 次重试是否已超过上限。
func (p Policy) Exhausted(attempt int) bool {
	return p.MaxRetries > 0 && attempt > p.MaxRetries
}

// KickReason 是被踢下线的原因（docs/04 §6）。
type KickReason struct {
	Kind string // normal | session_switch | generic
	Code uint32
}

func (k KickReason) Message() string {
	switch k.Kind {
	case "normal":
		return "账号已在其他位置登录"
	case "session_switch":
		return "会话已被切换到其他线路/节点"
	}
	return fmt.Sprintf("被服务端踢下线（原因码 %d）", k.Code)
}

// ParseKickReason 从 IPKICK 参数中取原因。
// 原因字段的位置与取值文档未给出，属假设点 kick_reason：取偏移 8 的小端 u32，0=normal、1=session_switch。
func ParseKickReason(msg []byte) KickReason {
	if len(msg) < 12 {
		return KickReason{Kind: "generic"}
	}
	code := binary.LittleEndian.Uint32(msg[8:12])
	switch code {
	case 0:
		return KickReason{Kind: "normal", Code: code}
	case 1:
		return KickReason{Kind: "session_switch", Code: code}
	}
	return KickReason{Kind: "generic", Code: code}
}
