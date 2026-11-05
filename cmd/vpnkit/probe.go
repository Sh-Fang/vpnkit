package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/tunnel"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"probe", "对网关做一次只读探测，用来确认某步的线格式假设", cmdProbe})
}

// cmdProbe 是联调用的定点探测：只回答一个问题，不配置网络、不起隧道会话。
//
// 存在的理由：docs/03 §4.4 那套 L3 流协议的几个字段（凭据前段、消息长度、
// IP 字节序）都还没在真网关上验证过。与其把整条隧道跑起来再猜是哪一步错，
// 不如单独把这一步拿出来，让它自己报出网关的真实回执。
func cmdProbe(a *app, args []string) error {
	if len(args) == 0 || args[0] != "l3" {
		return fmt.Errorf("%w: 用法：vpnkit probe l3 [--server …]", vpnerr.ErrUsage)
	}
	fs := flag.NewFlagSet("probe l3", flag.ContinueOnError)
	var sf serverFlags
	sf.register(fs)
	if err := a.parse(fs, args[1:]); err != nil {
		return err
	}
	sf.apply(a)
	if err := a.initLog(); err != nil {
		return err
	}
	if err := a.cfg.Validate(true); err != nil {
		return err
	}
	dir, err := fsutil.EnsureDir()
	if err != nil {
		return err
	}
	sess, err := auth.LoadSession(dir, a.cfg.Server.Host)
	if err != nil {
		return err
	}
	a.log.Info("探测目标", "server", sess.Server, "user", sess.User, "twfid", logx.Mask(sess.TwfID))

	ctx, cancel := context.WithTimeout(context.Background(), 4*a.g.timeout)
	defer cancel()
	addr := net.JoinHostPort(sess.Server, strconv.Itoa(sess.Port))

	// 第 1 步：隧道凭据前段（docs/03 §4.4）。
	agent, err := tunnel.AgentToken(ctx, addr, sess.TwfID, nil, a.g.timeout)
	if err != nil {
		return fmt.Errorf("%w: 取隧道凭据前段失败: %w", vpnerr.ErrTunnel, err)
	}
	fmt.Fprintf(a.stdout, "凭据前段：%d 字节，前 4 字节 %02X%02X…，末字节 %02X（期望 00）\n",
		len(agent), agent[0], agent[1], agent[len(agent)-1])

	tok, err := tunnel.EncodeToken(sess.TwfID, a.cfg.Tunnel.TokenEncoding)
	if err != nil {
		return err
	}
	tcfg := tunnel.Config{
		Addr:             addr,
		Token:            sess.TwfID,
		TokenEncoding:    a.cfg.Tunnel.TokenEncoding,
		ConnectTimeout:   a.cfg.Tunnel.ConnectTimeout.Duration,
		HandshakeTimeout: a.cfg.Tunnel.HandshakeTimeout.Duration,
		Templates:        tunnel.DefaultTemplates(),
		Log:              a.log,
	}

	// 第 2 步：查地址。这条连接必须保持打开——网关把地址绑在它上面，
	// 关掉之后建流会静默无回执（docs/03 §4.4）。
	qc, err := tunnel.L3Conn(ctx, tcfg)
	if err != nil {
		return fmt.Errorf("%w: 建立查询连接失败: %w", vpnerr.ErrTunnel, err)
	}
	defer qc.Close()
	if qm, err := tunnel.BuildL3Msg(tunnel.CtSendIP, agent, tok, tunnel.ArgSendIP); err == nil {
		// 结构留证：凭据段逐字节掩码，其余照打（docs/03 §4.4 的字段位置就是靠这个对出来的）。
		fmt.Fprintf(a.stdout, "查询消息：[16:48] 为凭据前段（已掩码）%s\n", hexMaskedCred(qm, 16, 48))
	}
	ip, sm, err := tunnel.QueryIP(qc, agent, tok, a.g.timeout)
	if err != nil {
		return fmt.Errorf("%w: %w", vpnerr.ErrTunnel, err)
	}
	fmt.Fprintf(a.stdout, "分配地址：%d.%d.%d.%d（状态码 %d）\n", ip[0], ip[1], ip[2], ip[3], sm.Status)
	fmt.Fprintf(a.stdout, "  回执载荷：%s\n", hex.EncodeToString(sm.Payload))

	// 第 3 步：开四条流，确认应答码与 docs/03 §4.4 一致。
	streams := []struct {
		connType uint32
		want     int32
		label    string
	}{
		{tunnel.CtStreamDownA, 2, "下行 A"},
		{tunnel.CtStreamDownB, 2, "下行 B"},
		{tunnel.CtStreamUpA, 1, "上行 A"},
		{tunnel.CtStreamUpB, 1, "上行 B"},
	}
	for _, s := range streams {
		conn, err := tunnel.L3Conn(ctx, tcfg)
		if err != nil {
			fmt.Fprintf(a.stdout, "%s（conn_type=%d）：连接失败 %v\n", s.label, s.connType, err)
			continue
		}
		got, err := tunnel.OpenStream(conn, s.connType, agent, tok, ip, s.want, a.g.timeout)
		if err != nil {
			fmt.Fprintf(a.stdout, "%s（conn_type=%d）：失败 %v\n", s.label, s.connType, err)
		} else {
			fmt.Fprintf(a.stdout, "%s（conn_type=%d）：应答码 %d ✓\n", s.label, s.connType, got.Status)
		}
		conn.Close()
	}

	// 第 4 步：数据面。发一个 DNS 查询看能不能收到回包（docs/03 §5 的帧格式仍待确认）。
	if len(sm.Payload) >= 12 {
		var dns [4]byte
		copy(dns[:], sm.Payload[8:12])
		fmt.Fprintf(a.stdout, "数据面：回执载荷 [8:12] 是 %d.%d.%d.%d，DNS 帧格式尚未验证，暂不发送\n",
			dns[0], dns[1], dns[2], dns[3])
	}
	return nil
}

// hexMaskedCred 输出十六进制，但把 [off, off+n) 这段（凭据前段 + 登录令牌）
// 逐字节打成 `****`。结构照样看得清，凭据不落终端、不进日志文件。
func hexMaskedCred(b []byte, off, n int) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if i >= off && i < off+n {
			sb.WriteString("****")
			continue
		}
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}
