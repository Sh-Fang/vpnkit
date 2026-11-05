package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

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

	// 第 2 步：两种消息长度各试一次，看网关认哪个。
	shapes := []struct {
		name string
		msg  func() []byte
	}{
		{"64 字节裸消息", func() []byte { return tunnel.BuildL3(tunnel.L3OpcodeIP, agent, tok, [4]byte{}) }},
		{"76 字节带前缀", func() []byte { return tunnel.BuildL3Wrapped(tunnel.L3OpcodeIP, agent, tok, [4]byte{}) }},
	}
	for _, s := range shapes {
		ip, raw, err := probeOnce(ctx, tcfg, s.msg(), a.g.timeout)
		if err != nil {
			fmt.Fprintf(a.stdout, "%s：失败 %v\n", s.name, err)
			if len(raw) > 0 {
				fmt.Fprintf(a.stdout, "  回执 %d 字节：%s\n", len(raw), hex.EncodeToString(raw))
			}
			fmt.Fprintf(a.stdout, "  发出：%s\n", hex.EncodeToString(s.msg()))
			continue
		}
		fmt.Fprintf(a.stdout, "%s：成功，分配地址 %d.%d.%d.%d（回执 %d 字节）\n",
			s.name, ip[0], ip[1], ip[2], ip[3], len(raw))
		fmt.Fprintf(a.stdout, "  回执前 16 字节：%s\n", hex.EncodeToString(raw[:min(16, len(raw))]))
	}
	return nil
}

// probeOnce 建一条隧道连接、发一条消息、读回执。
func probeOnce(ctx context.Context, cfg tunnel.Config, msg []byte, timeout time.Duration) ([4]byte, []byte, error) {
	conn, err := tunnel.L3Conn(ctx, cfg)
	if err != nil {
		return [4]byte{}, nil, err
	}
	defer conn.Close()
	ip, raw, err := tunnel.QueryIP(conn, msg, timeout)
	if errors.Is(err, tunnel.ErrL3Reply) {
		return ip, raw, err
	}
	return ip, raw, err
}
