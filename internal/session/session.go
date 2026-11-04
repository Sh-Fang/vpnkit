// Package session 编排一次 up 的完整生命周期并驱动状态机（docs/01 §2、§4，docs/04 §5、§7）。
package session

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/command"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/route"
	"github.com/Sh-Fang/vpnkit/internal/tunnel"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// State 是对外暴露的状态字符串（docs/01 §4）。
type State string

const (
	Idle           State = "idle"
	Authenticating State = "authenticating"
	Connecting     State = "connecting"
	WaitAddress    State = "wait_address"
	Configuring    State = "configuring"
	Running        State = "running"
	Backoff        State = "backoff"
	Stopped        State = "stopped"
)

var (
	ErrStopped          = errors.New("服务端终止了会话")
	ErrRetriesExhausted = errors.New("重连次数超过上限")
	ErrNoRoutes         = errors.New("资源列表中没有可路由的内网网段")
	ErrDeviceLost       = errors.New("TUN 设备异常关闭")
)

// AuthAPI 是 session 对认证层的依赖（便于测试替换）。
type AuthAPI interface {
	FetchConf(ctx context.Context, token string) (auth.Conf, []string, error)
	FetchResources(ctx context.Context, token string) (auth.Resources, error)
}

// Network 是 session 对路由/DNS 层的依赖。Apply 失败时必须已自行回滚；Teardown 必须幂等。
type Network interface {
	Apply(ctx context.Context, p route.Plan) (route.Result, error)
	Teardown(ctx context.Context) error
}

// maintainer 是 Network 的可选能力：运行期间周期检查被外部改动的网络配置并修复。
type maintainer interface {
	Maintain(ctx context.Context) []string
}

// maintainInterval 是 maintainer 的检查周期。
var maintainInterval = 30 * time.Second

// TunnelParams 是隧道相关配置（来自 config.Tunnel）。
type TunnelParams struct {
	MTU               int
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	ConnectTimeout    time.Duration
	HandshakeTimeout  time.Duration
	ValidWait         time.Duration
	CtrlConnType      uint32
	TokenEncoding     string
	DataOpcode        uint32
	RC4KeyHex         string
	DataConnUp        uint32
	DataConnDown      uint32
	Transport         string
	Templates         tunnel.Templates
}

type Options struct {
	Server      string // 网关主机名或 IP（HTTPS 与默认隧道地址）
	Port        int    // 网关 HTTPS 端口，conf.csp 未给隧道端口时沿用
	Token       string
	Auth        AuthAPI
	Tunnel      TunnelParams
	ExtraRoutes []string
	DNSSuffixes []string
	DNSServers  []string
	OpenDevice  func(mtu int) (platform.Device, error)
	Network     Network
	Log         *slog.Logger
	// PolicyFor 允许测试缩放退避时长；nil 时原样使用 docs/04 §5 的策略。
	PolicyFor func(command.Policy) command.Policy
	// Resolve 解析隧道主机名；nil 时用系统解析器。
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// OnStatus 在每次状态变化时回调（在 session goroutine 中同步调用，不得阻塞）。
	OnStatus func(Status)
}

// Stats 是数据面统计。
type Stats struct {
	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	Dropped   uint64 `json:"tx_dropped"`
}

// Status 是 status 子命令展示的快照。
type Status struct {
	State        State     `json:"state"`
	Since        time.Time `json:"since"`
	Server       string    `json:"server"`
	TunnelAddr   string    `json:"tunnel_addr,omitempty"`
	Device       string    `json:"device,omitempty"`
	TapIP        string    `json:"tap_ip,omitempty"`
	LanIP        string    `json:"lan_ip,omitempty"`
	MTU          int       `json:"mtu,omitempty"`
	Enc          uint32    `json:"enc"`
	Zip          uint32    `json:"zip"`
	UDPPort      uint32    `json:"udp_port"`
	Routes       []string  `json:"routes"`
	RoutesFailed []string  `json:"routes_failed,omitempty"`
	DNSEnabled   bool      `json:"dns_enabled"`
	DNSServers   []string  `json:"dns_servers,omitempty"`
	DNSSuffixes  []string  `json:"dns_suffixes,omitempty"`
	RecvLimit    int64     `json:"recv_limit_bps,omitempty"`
	SendLimit    int64     `json:"send_limit_bps,omitempty"`
	Reconnects   int       `json:"reconnects"`
	StopReason   string    `json:"stop_reason,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	Warnings     []string  `json:"warnings,omitempty"`
	Stats        Stats     `json:"stats"`
}

// Session 是一次 up 的运行实例。
type Session struct {
	o   Options
	log *slog.Logger

	mu     sync.Mutex
	status Status

	tx, txb, rx, rxb, dropped atomic.Uint64

	dev       platform.Device
	devName   string
	pkts      chan []byte
	devErr    chan error
	netActive bool
	curTap    netip.Addr
	stopping  atomic.Bool
}

func New(o Options) *Session {
	if o.PolicyFor == nil {
		o.PolicyFor = func(p command.Policy) command.Policy { return p }
	}
	if o.Resolve == nil {
		o.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		}
	}
	t := &o.Tunnel
	if t.HeartbeatTimeout <= 0 {
		t.HeartbeatTimeout = 30 * time.Second
	}
	if t.MTU == 0 {
		t.MTU = 1400
	}
	return &Session{
		o:      o,
		log:    logx.Or(o.Log),
		status: Status{State: Idle, Since: time.Now(), Server: o.Server},
		pkts:   make(chan []byte, 512),
		devErr: make(chan error, 1),
	}
}

// Status 返回当前快照（含实时统计）。
func (s *Session) Status() Status {
	s.mu.Lock()
	st := s.status
	s.mu.Unlock()
	st.Stats = Stats{TxPackets: s.tx.Load(), TxBytes: s.txb.Load(), RxPackets: s.rx.Load(), RxBytes: s.rxb.Load(), Dropped: s.dropped.Load()}
	return st
}

func (s *Session) update(f func(*Status)) {
	s.mu.Lock()
	f(&s.status)
	s.mu.Unlock()
	if s.o.OnStatus != nil {
		s.o.OnStatus(s.Status())
	}
}

func (s *Session) setState(st State, args ...any) {
	s.mu.Lock()
	prev := s.status.State
	s.mu.Unlock()
	if prev == st {
		return
	}
	s.log.Info("状态转换", append([]any{"from", prev, "to", st}, args...)...)
	s.update(func(x *Status) { x.State, x.Since = st, time.Now() })
}

func (s *Session) warn(msg string, args ...any) {
	s.log.Warn(msg, args...)
	s.update(func(x *Status) { x.Warnings = append(x.Warnings, msg) })
}

// prepared 是认证阶段得到的、整个会话期间不变的信息。
type prepared struct {
	addrs      []string
	mtu        int
	routes     []netip.Prefix
	bypass     []netip.Addr
	dnsServers []netip.Addr
	suffixes   []string
}

// Run 执行 up 直到 ctx 取消（返回 nil）或遇到不可恢复的错误。返回前一定已完成回滚。
func (s *Session) Run(ctx context.Context) (err error) {
	defer func() {
		s.stopping.Store(true)
		s.teardown()
		if err != nil {
			s.update(func(x *Status) { x.LastError = err.Error() })
			if errors.Is(err, ErrStopped) {
				s.setState(Stopped)
			}
		}
		s.setState(Idle)
	}()

	s.setState(Authenticating)
	p, err := s.prepare(ctx)
	if err != nil {
		return err
	}

	tcfg := tunnel.Config{
		Token:            s.o.Token,
		TokenEncoding:    s.o.Tunnel.TokenEncoding,
		CtrlConnType:     s.o.Tunnel.CtrlConnType,
		ConnectTimeout:   s.o.Tunnel.ConnectTimeout,
		HandshakeTimeout: s.o.Tunnel.HandshakeTimeout,
		Templates:        s.o.Tunnel.Templates,
		Log:              s.log,
	}
	everRunning := false
	attempts := map[string]int{}

	// backoff 等待一段退避；返回 false 表示应结束 Run（err 已设置或 ctx 取消）。
	backoff := func(pol command.Policy, reason string) (bool, error) {
		pol = s.o.PolicyFor(pol)
		attempts[pol.Name]++
		n := attempts[pol.Name]
		if pol.Exhausted(n) {
			return false, fmt.Errorf("%w: %w: %s（策略 %s 已重试 %d 次）", vpnerr.ErrRejected, ErrRetriesExhausted, reason, pol.Name, pol.MaxRetries)
		}
		d := pol.Delay(n, nil)
		s.setState(Backoff, "reason", reason, "policy", pol.Name, "attempt", n, "delay", d.Round(time.Millisecond))
		s.update(func(x *Status) { x.Reconnects++ })
		select {
		case <-ctx.Done():
			return false, nil
		case e := <-s.devErr:
			return false, e
		case <-time.After(d):
			return true, nil
		}
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		s.setState(Connecting)
		ctl, first, addr, err := s.dialControl(ctx, tcfg, p.addrs)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !everRunning {
				return err
			}
			s.log.Warn("控制通道建立失败", "err", err)
			if ok, e := backoff(command.PolicyNetwork, "网络断开"); !ok {
				return e
			}
			continue
		}
		s.update(func(x *Status) { x.TunnelAddr = addr })
		tcfg.Addr = addr

		// WaitAddress：等 SEND_IP，期间处理繁忙/终止类命令（docs/04 §7）
		s.setState(WaitAddress)
		msg := first
		var sendIP []byte
		var next func() (bool, error)
		for sendIP == nil && next == nil {
			code, _, _ := wire.ParseServerMsg(msg)
			d := command.Classify(code)
			s.log.Debug("命令", "code", code, "name", d.Name, "hex", hex.EncodeToString(msg))
			switch d.Action {
			case command.ActConfigure:
				sendIP = msg
				continue
			case command.ActBackoff:
				ctl.Close()
				next = func() (bool, error) { return backoff(d.Policy, d.Name) }
				continue
			case command.ActReconnectNow:
				ctl.Close()
				next = func() (bool, error) { s.log.Info("服务端要求立即重连", "code", code); return true, nil }
				continue
			case command.ActStop:
				ctl.Close()
				return s.stopErr(d, msg)
			default:
				s.logCommand(d, msg)
			}
			if msg, err = s.readWithTimeout(ctl); err != nil {
				ctl.Close()
				if !everRunning {
					return fmt.Errorf("%w: 等待分配地址时连接中断: %w", vpnerr.ErrTunnel, err)
				}
				next = func() (bool, error) { return backoff(command.PolicyNetwork, "等待地址时断开") }
			}
		}
		if next != nil {
			if ok, e := next(); !ok {
				return e
			}
			continue
		}

		// Configuring
		s.setState(Configuring)
		sip, upC, downC, err := s.configure(ctx, sendIP, p)
		if err != nil {
			ctl.Close()
			return err
		}
		arg := binary.BigEndian.Uint32(sip.TapIP.AsSlice())
		logx.Assumption(s.log, "data_conn", fmt.Sprintf("up=%d down=%d arg=tapip", s.o.Tunnel.DataConnUp, s.o.Tunnel.DataConnDown))
		up, err := tunnel.DialData(ctx, tcfg, s.o.Tunnel.DataConnUp, arg, wire.AckDataUp)
		var down net.Conn
		if err == nil {
			down, err = tunnel.DialData(ctx, tcfg, s.o.Tunnel.DataConnDown, arg, wire.AckDataDown)
			if err != nil {
				up.Close()
			}
		}
		if err != nil {
			ctl.Close()
			if ctx.Err() != nil {
				return nil
			}
			if !everRunning {
				return err
			}
			if ok, e := backoff(command.PolicyNetwork, "数据通道建立失败"); !ok {
				return e
			}
			continue
		}

		s.setState(Running, "tap_ip", sip.TapIP, "routes", len(p.routes))
		everRunning = true
		attempts = map[string]int{}
		out := s.runConn(ctx, ctl, up, down, upC, downC)
		switch out.kind {
		case outCancel:
			return nil
		case outFatal:
			return out.err
		case outStop:
			return s.stopErr(out.decision, out.msg)
		case outReconnectNow:
			s.log.Info("服务端要求立即重连", "code", out.decision.Code)
			continue
		case outBackoff:
			if ok, e := backoff(out.decision.Policy, out.decision.Name); !ok {
				return e
			}
		case outNet:
			s.log.Warn("连接断开", "reason", out.reason)
			if ok, e := backoff(command.PolicyNetwork, out.reason); !ok {
				return e
			}
		}
	}
}

func (s *Session) readWithTimeout(ctl *tunnel.Control) ([]byte, error) {
	// 读阻塞由 runConn 外的连接关闭或心跳超时兜底；WaitAddress 阶段用 heartbeat_timeout 限时。
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() { b, err := ctl.ReadMsg(); ch <- res{b, err} }()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(s.o.Tunnel.HeartbeatTimeout):
		ctl.Close()
		<-ch
		return nil, errors.New("等待命令超时")
	}
}

func (s *Session) logCommand(d command.Decision, msg []byte) {
	switch d.Action {
	case command.ActUnknown:
		s.log.Warn("未知命令，记录并忽略", "code", d.Code, "hex", hex.EncodeToString(msg))
	case command.ActLog:
		s.log.Info("命令", "name", d.Name)
	}
}

func (s *Session) stopErr(d command.Decision, msg []byte) error {
	reason := "服务端强制断开（SHUTDOWN）"
	if d.Code == wire.CmdIPKick {
		k := command.ParseKickReason(msg)
		logx.Assumption(s.log, "kick_reason", k.Kind, "code", k.Code, "hex", hex.EncodeToString(msg))
		reason = k.Message()
	}
	s.log.Error("会话被终止，不再重连", "code", d.Code, "name", d.Name, "reason", reason)
	s.update(func(x *Status) { x.StopReason = reason })
	return fmt.Errorf("%w: %w: %s", vpnerr.ErrRejected, ErrStopped, reason)
}

func (s *Session) prepare(ctx context.Context) (*prepared, error) {
	conf, warns, err := s.o.Auth.FetchConf(ctx, s.o.Token)
	if err != nil {
		return nil, err
	}
	for _, w := range warns {
		s.warn(w)
	}
	res, err := s.o.Auth.FetchResources(ctx, s.o.Token)
	if err != nil {
		return nil, err
	}
	logx.Assumption(s.log, "is_hid_user", conf.IsHidUser, "present", conf.IsHidUserSet)
	if conf.Compress != 0 {
		s.warn("conf.csp 声明启用压缩，按无压缩处理（docs/04 §3.1）")
	}
	p := &prepared{mtu: s.o.Tunnel.MTU}
	if conf.MTU > 0 && conf.MTU < p.mtu {
		p.mtu = conf.MTU
	}
	if p.mtu > 1400 {
		p.mtu = 1400 // docs/07 §4：上限 min(网关下发值, 1400)
	}

	routes := append([]netip.Prefix(nil), res.Prefixes...)
	for _, r := range s.o.ExtraRoutes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			a, err2 := netip.ParseAddr(r)
			if err2 != nil {
				s.warn("忽略非法的 split.extra_routes 条目 " + r)
				continue
			}
			pfx = netip.PrefixFrom(a, 32)
		}
		routes = append(routes, pfx)
	}
	for _, r := range auth.MergePrefixes(routes) {
		if r.Bits() == 0 {
			// 默认路由神圣不可侵犯（README 设计原则 1）
			s.warn("资源列表包含 0.0.0.0/0，已忽略，不接管默认路由")
			continue
		}
		if !r.Addr().Is4() {
			continue
		}
		p.routes = append(p.routes, r)
	}
	if len(p.routes) == 0 {
		return nil, fmt.Errorf("%w: %w", vpnerr.ErrNetConfig, ErrNoRoutes)
	}
	if len(p.routes) > 64 {
		s.warn(fmt.Sprintf("内网网段 %d 条，超过 64，建议改用更粗的汇总路由", len(p.routes)))
	}

	seen := map[string]bool{}
	for _, sfx := range append(append([]string(nil), res.Suffixes...), s.o.DNSSuffixes...) {
		if sfx != "" && !seen[sfx] {
			seen[sfx] = true
			p.suffixes = append(p.suffixes, sfx)
		}
	}
	servers := s.o.DNSServers
	if len(servers) == 0 {
		servers = conf.TunDNS
	}
	for _, sv := range servers {
		if a, err := netip.ParseAddr(sv); err == nil && a.Is4() {
			p.dnsServers = append(p.dnsServers, a)
		}
	}
	switch {
	case len(p.suffixes) == 0:
		s.warn("没有内网域名后缀，不修改 DNS；内网域名可能需要用 IP 访问，可用 --dns-suffix 补充")
	case len(p.dnsServers) == 0:
		s.warn("有内网域名后缀但没有隧道 DNS 服务器，禁用 DNS 分区")
		p.suffixes = nil
	}

	// 隧道地址：Mline 候选线路优先，否则网关主机 + Htp.port（docs/09 §3）
	port := conf.Port
	if port == 0 {
		port = s.o.Port
	}
	if conf.MlineEnabled && len(conf.Lines) > 0 {
		p.addrs = conf.Lines
	} else {
		p.addrs = []string{net.JoinHostPort(s.o.Server, strconv.Itoa(port))}
	}
	// 防回环：所有候选线路的服务端地址都要走物理接口（docs/07 §2.2）
	for i, a := range p.addrs {
		host, port, _ := net.SplitHostPort(a)
		ips, err := s.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: 解析隧道地址 %s: %w", vpnerr.ErrTunnel, host, err)
		}
		p.bypass = append(p.bypass, ips...)
		// 用解析出的 IP 连接，保证连接目标正是加了防回环路由的地址
		p.addrs[i] = net.JoinHostPort(ips[0].String(), port)
	}
	// 隧道 DNS 服务器不在内网网段内时，分区解析的查询会经默认路由从物理网卡发出（docs/07 §3）。
	if len(p.suffixes) > 0 {
	dnsLoop:
		for _, d := range p.dnsServers {
			for _, r := range p.routes {
				if r.Contains(d) {
					continue dnsLoop
				}
			}
			if slices.Contains(p.bypass, d) {
				s.warn(fmt.Sprintf("隧道 DNS 服务器 %s 与隧道服务端地址相同，不为其加隧道路由", d))
				continue
			}
			p.routes = append(p.routes, netip.PrefixFrom(d, 32))
			s.log.Info("隧道 DNS 服务器不在内网网段内，补充主机路由", "dns", d)
		}
	}
	if s.o.Tunnel.Transport == "udp" {
		s.warn("UDP 承载尚未实现（P5），使用 TCP")
	}
	s.update(func(x *Status) {
		x.MTU = p.mtu
		x.RecvLimit, x.SendLimit = conf.RecvLimit, conf.SendLimit
	})
	s.log.Info("认证信息就绪", "routes", len(p.routes), "dns_suffixes", len(p.suffixes), "tunnel", p.addrs)
	return p, nil
}

func (s *Session) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	ips, err := s.o.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, ip := range ips {
		if ip = ip.Unmap(); ip.Is4() {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("没有 IPv4 地址")
	}
	return out, nil
}

func (s *Session) dialControl(ctx context.Context, cfg tunnel.Config, addrs []string) (*tunnel.Control, []byte, string, error) {
	var lastErr error
	for _, a := range addrs {
		cfg.Addr = a
		ctl, first, err := tunnel.DialControl(ctx, cfg)
		if err == nil {
			return ctl, first, a, nil
		}
		lastErr = err
		if ctx.Err() != nil || errors.Is(err, tunnel.ErrTokenLength) {
			break
		}
		if len(addrs) > 1 {
			s.log.Warn("线路不可用，尝试下一条", "addr", a, "err", err)
		}
	}
	return nil, nil, "", lastErr
}

// configure 解析 SEND_IP 并在需要时创建 TUN、下发路由/DNS。
func (s *Session) configure(ctx context.Context, msg []byte, p *prepared) (wire.SendIP, tunnel.Cipher, tunnel.Cipher, error) {
	s.log.Debug("SEND_IP", "hex", hex.EncodeToString(msg))
	logx.Assumption(s.log, "sendip_layout", wire.SendIPLayoutV1.Name)
	sip, err := wire.ParseSendIP(msg, wire.SendIPLayoutV1)
	if err != nil {
		s.log.Error("SEND_IP 合理性检查失败，疑似负载布局不符", "err", err, "hex", hex.EncodeToString(msg))
		return sip, nil, nil, fmt.Errorf("%w: %w", vpnerr.ErrTunnel, err)
	}
	s.log.Info("分配地址", "tap_ip", sip.TapIP, "lan_ip", sip.LanIP, "enc", sip.Enc, "zip", sip.Zip, "udp_port", sip.UDPPort)
	if sip.Zip != 0 {
		s.warn("SEND_IP zip != 0，按无压缩处理（docs/04 §3.1）")
	}
	upC, downC, err := tunnel.NewCiphers(sip.Enc, tunnel.StaticKey(s.o.Tunnel.RC4KeyHex), s.log)
	if err != nil {
		s.log.Error("服务端要求加密，密钥派生未实现", "enc", sip.Enc)
		return sip, nil, nil, err
	}
	s.update(func(x *Status) {
		x.TapIP, x.LanIP = sip.TapIP.String(), sip.LanIP.String()
		x.Enc, x.Zip, x.UDPPort = sip.Enc, sip.Zip, sip.UDPPort
	})

	if s.netActive && s.curTap == sip.TapIP {
		return sip, upC, downC, nil // 重连后地址不变：沿用已有路由与 DNS
	}
	if s.netActive {
		s.log.Info("虚拟地址变化，重新下发网络配置", "old", s.curTap, "new", sip.TapIP)
		if err := s.o.Network.Teardown(ctx); err != nil {
			s.log.Warn("撤销旧网络配置时出错", "err", err)
		}
		s.netActive = false
	}
	if s.dev == nil {
		dev, err := s.o.OpenDevice(p.mtu)
		if err != nil {
			return sip, nil, nil, fmt.Errorf("%w: 创建 TUN 设备: %w", vpnerr.ErrNetConfig, err)
		}
		name, _ := dev.Name()
		s.dev, s.devName = dev, name
		s.update(func(x *Status) { x.Device = name })
		go s.devReader(dev)
	}
	res, err := s.o.Network.Apply(ctx, route.Plan{
		Device: s.devName, TapIP: sip.TapIP, MTU: p.mtu, Routes: p.routes,
		Bypass: p.bypass, DNSServers: p.dnsServers, DNSSuffixes: p.suffixes,
	})
	if err != nil {
		return sip, nil, nil, fmt.Errorf("%w: %w", vpnerr.ErrNetConfig, err)
	}
	s.netActive, s.curTap = true, sip.TapIP
	for _, w := range res.Warnings {
		s.warn(w)
	}
	s.update(func(x *Status) {
		x.Routes = x.Routes[:0]
		for _, r := range res.RoutesOK {
			x.Routes = append(x.Routes, r.String())
		}
		x.RoutesFailed = res.RoutesFailed
		x.DNSEnabled = res.DNSEnabled
		x.DNSServers, x.DNSSuffixes = nil, p.suffixes
		for _, d := range p.dnsServers {
			x.DNSServers = append(x.DNSServers, d.String())
		}
	})
	return sip, upC, downC, nil
}

// devReader 在整个会话期间读取 TUN，把包放入队列；无连接时丢弃，避免阻塞系统。
func (s *Session) devReader(dev platform.Device) {
	buf := make([]byte, 65535)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			if !s.stopping.Load() {
				select {
				case s.devErr <- fmt.Errorf("%w: %w: %w", vpnerr.ErrNetConfig, ErrDeviceLost, err):
				default:
				}
			}
			return
		}
		if n == 0 {
			continue
		}
		p := append([]byte(nil), buf[:n]...)
		select {
		case s.pkts <- p:
		default:
			s.dropped.Add(1)
		}
	}
}

type outKind int

const (
	outCancel outKind = iota
	outFatal
	outStop
	outReconnectNow
	outBackoff
	outNet
)

type outcome struct {
	kind     outKind
	decision command.Decision
	msg      []byte
	reason   string
	err      error
}

// runConn 运行 Running 态的五个 goroutine（docs/01 §3），返回第一个导致离开 Running 的事件。
// 返回前所有 goroutine 均已退出、连接均已关闭。
func (s *Session) runConn(ctx context.Context, ctl *tunnel.Control, up, down net.Conn, upC, downC tunnel.Cipher) outcome {
	cctx, cancel := context.WithCancel(ctx)
	events := make(chan outcome, 8)
	emit := func(o outcome) {
		select {
		case events <- o:
		default:
		}
	}
	var lastRx atomic.Int64
	lastRx.Store(time.Now().UnixNano())
	touch := func() { lastRx.Store(time.Now().UnixNano()) }
	var seen10, seen11 atomic.Bool
	var wg sync.WaitGroup
	t := s.o.Tunnel

	// 已有排队的旧包属于上一条连接，丢弃
	for len(s.pkts) > 0 {
		<-s.pkts
	}

	wg.Add(1)
	go func() { // ctrlLoop
		defer wg.Done()
		for {
			msg, err := ctl.ReadMsg()
			if err != nil {
				emit(outcome{kind: outNet, reason: "控制通道断开: " + err.Error()})
				return
			}
			touch()
			code, _, perr := wire.ParseServerMsg(msg)
			if perr != nil {
				s.log.Warn("控制通道收到非法消息", "hex", hex.EncodeToString(msg))
				continue
			}
			d := command.Classify(code)
			s.log.Debug("命令", "code", code, "name", d.Name, "hex", hex.EncodeToString(msg))
			switch d.Action {
			case command.ActHeartbeat:
			case command.ActLog:
				if code == wire.CmdIPValid {
					seen10.Store(true)
				}
				if code == wire.CmdGroupIDValid {
					seen11.Store(true)
				}
				s.logCommand(d, msg)
			case command.ActStop:
				emit(outcome{kind: outStop, decision: d, msg: msg})
				return
			case command.ActReconnectNow:
				emit(outcome{kind: outReconnectNow, decision: d})
				return
			case command.ActBackoff:
				emit(outcome{kind: outBackoff, decision: d})
				return
			case command.ActConfigure:
				s.log.Warn("运行中再次收到 SEND_IP，忽略", "hex", hex.EncodeToString(msg))
			default:
				s.logCommand(d, msg)
			}
		}
	}()

	wg.Add(1)
	go func() { // rxLoop
		defer wg.Done()
		fr := tunnel.NewFrameReader(down, downC, s.statusMTU(), s.log)
		buf := make([]byte, 65535)
		for {
			n, err := fr.ReadPacket(buf)
			if err != nil {
				if errors.Is(err, wire.ErrFrameLength) {
					s.log.Error("下行数据帧格式错误", "err", err)
				}
				emit(outcome{kind: outNet, reason: "下行数据通道断开: " + err.Error()})
				return
			}
			touch()
			s.rx.Add(1)
			s.rxb.Add(uint64(n))
			if _, err := s.dev.Write(buf[:n]); err != nil && !s.stopping.Load() {
				s.log.Debug("写 TUN 失败", "err", err)
			}
		}
	}()

	wg.Add(1)
	go func() { // txLoop
		defer wg.Done()
		fw := tunnel.NewFrameWriter(up, t.DataOpcode, upC, s.log)
		for {
			select {
			case <-cctx.Done():
				return
			case p := <-s.pkts:
				if err := fw.WritePacket(p); err != nil {
					emit(outcome{kind: outNet, reason: "上行数据通道断开: " + err.Error()})
					return
				}
				s.tx.Add(1)
				s.txb.Add(uint64(len(p)))
			}
		}
	}()

	if t.HeartbeatInterval > 0 {
		wg.Add(1)
		go func() { // heartbeat
			defer wg.Done()
			tk := time.NewTicker(t.HeartbeatInterval)
			defer tk.Stop()
			fails := 0
			for {
				select {
				case <-cctx.Done():
					return
				case <-tk.C:
					if err := ctl.SendHeartbeat(t.HeartbeatInterval); err != nil {
						fails++
						s.log.Warn("心跳发送失败", "consecutive", fails, "err", err)
						// 连续 3 次失败才重连（docs/04 §4）
						if fails >= 3 {
							emit(outcome{kind: outNet, reason: "心跳连续 3 次发送失败"})
							return
						}
					} else {
						fails = 0
					}
				}
			}
		}()
	}

	if m, ok := s.o.Network.(maintainer); ok {
		wg.Add(1)
		go func() { // 网络配置巡检
			defer wg.Done()
			tk := time.NewTicker(maintainInterval)
			defer tk.Stop()
			for {
				select {
				case <-cctx.Done():
					return
				case <-tk.C:
					for _, w := range m.Maintain(cctx) {
						s.warn(w)
					}
				}
			}
		}()
	}

	wg.Add(1)
	go func() { // watchdog
		defer wg.Done()
		step := t.HeartbeatTimeout / 4
		if step > time.Second {
			step = time.Second
		}
		tk := time.NewTicker(step)
		defer tk.Stop()
		var validTimer <-chan time.Time
		if t.ValidWait > 0 {
			validTimer = time.After(t.ValidWait)
		}
		for {
			select {
			case <-cctx.Done():
				return
			case <-validTimer:
				logx.Assumption(s.log, "valid_10_11", fmt.Sprintf("ipvalid=%v groupidvalid=%v", seen10.Load(), seen11.Load()))
				if !seen10.Load() || !seen11.Load() {
					s.warn(fmt.Sprintf("进入运行 %s 后仍未收到 IPVALID/GROUPIDVALID（10=%v 11=%v），继续运行", t.ValidWait, seen10.Load(), seen11.Load()))
				}
			case <-tk.C:
				// heartbeat_timeout 内没有任何入站字节才判定掉线（docs/04 §4）
				if time.Since(time.Unix(0, lastRx.Load())) > t.HeartbeatTimeout {
					emit(outcome{kind: outNet, reason: "心跳超时：" + t.HeartbeatTimeout.String() + " 内无任何入站数据"})
					return
				}
			}
		}
	}()

	var out outcome
	select {
	case <-ctx.Done():
		out = outcome{kind: outCancel}
	case e := <-s.devErr:
		out = outcome{kind: outFatal, err: e}
	case out = <-events:
	}
	cancel()
	ctl.Close()
	up.Close()
	down.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		s.log.Error("goroutine 未能在 10 秒内退出")
	}
	return out
}

func (s *Session) statusMTU() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.MTU > 0 {
		return s.status.MTU
	}
	return 1400
}

// teardown 严格逆序撤销：路由/DNS → TUN（docs/01 §2）。每步独立、可重复。
func (s *Session) teardown() {
	if s.netActive || s.dev != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.o.Network.Teardown(ctx); err != nil {
			s.log.Error("撤销网络配置时出错", "err", err)
		}
		s.netActive = false
	}
	if s.dev != nil {
		_ = s.dev.Close()
		s.dev = nil
	}
}

// DryRun 只执行认证阶段（拉 conf/rclist、解析隧道地址），返回将要下发的计划。
// 不建立任何隧道连接（AGENTS.md §4：--dry-run 不发隧道流量）。Device 与 TapIP 由调用方填占位。
func (s *Session) DryRun(ctx context.Context) (route.Plan, error) {
	p, err := s.prepare(ctx)
	if err != nil {
		return route.Plan{}, err
	}
	return route.Plan{MTU: p.mtu, Routes: p.routes, Bypass: p.bypass, DNSServers: p.dnsServers, DNSSuffixes: p.suffixes}, nil
}
