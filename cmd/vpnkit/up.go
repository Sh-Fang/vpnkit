package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/route"
	"github.com/Sh-Fang/vpnkit/internal/session"
	"github.com/Sh-Fang/vpnkit/internal/tunnel"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"up", "建立隧道、安装分流（需要提权；--dry-run 只打印变更）", cmdUp})
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// statusFile 是 up 进程写给 status 子命令的快照。
type statusFile struct {
	PID       int            `json:"pid"`
	User      string         `json:"user"`
	TwfID     string         `json:"twfid_masked"`
	FakeTUN   bool           `json:"fake_tun,omitempty"`
	UpdatedAt time.Time      `json:"updated_at"`
	Session   session.Status `json:"session"`
}

func statusPath(dir string) string { return filepath.Join(dir, "status.json") }

func cmdUp(a *app, args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	var sf serverFlags
	sf.register(fs)
	dryRun := fs.Bool("dry-run", false, "只打印将要执行的路由与 DNS 变更，不建隧道、不落盘")
	fakeTUN := fs.Bool("fake-tun", false, "仅供测试：用内存 TUN，路由/DNS 只打印不执行，无需提权")
	transport := fs.String("transport", "", "承载方式 tcp|udp（覆盖 tunnel.transport）")
	var dnsSuffix multiFlag
	fs.Var(&dnsSuffix, "dns-suffix", "追加内网域名后缀（可重复）")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	sf.apply(a)
	if *transport != "" {
		a.cfg.Tunnel.Transport = *transport
	}
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
	ac, err := a.authClient()
	if err != nil {
		return err
	}

	cfgT := a.cfg.Tunnel
	opts := session.Options{
		Server: a.cfg.Server.Host,
		Port:   a.cfg.Server.Port,
		Token:  sess.TwfID,
		Auth:   ac,
		Tunnel: session.TunnelParams{
			MTU:               cfgT.MTU,
			HeartbeatInterval: cfgT.HeartbeatInterval.Duration,
			HeartbeatTimeout:  cfgT.HeartbeatTimeout.Duration,
			ConnectTimeout:    cfgT.ConnectTimeout.Duration,
			HandshakeTimeout:  cfgT.HandshakeTimeout.Duration,
			ValidWait:         cfgT.ValidWait.Duration,
			CtrlConnType:      uint32(cfgT.CtrlConnType),
			TokenEncoding:     cfgT.TokenEncoding,
			DataOpcode:        uint32(cfgT.DataOpcode),
			RC4KeyHex:         cfgT.RC4KeyHex,
			DataConnUp:        uint32(cfgT.DataConnUp),
			DataConnDown:      uint32(cfgT.DataConnDown),
			Transport:         cfgT.Transport,
			Templates:         tunnel.DefaultTemplates(),
		},
		ExtraRoutes: a.cfg.Split.ExtraRoutes,
		DNSSuffixes: append(append([]string(nil), a.cfg.DNS.Suffixes...), dnsSuffix...),
		DNSServers:  a.cfg.DNS.Servers,
		Log:         a.log,
	}
	a.log.Info("会话令牌", "server", sess.Server, "user", sess.User, "twfid", logx.Mask(sess.TwfID))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, releaseStop, err := platform.StopContext(ctx)
	if err != nil {
		a.log.Warn("无法创建停止事件，vpnkit down 将强制结束本进程", "err", err)
	}
	defer releaseStop()
	signal.Ignore(syscall.SIGHUP) // 终端断开不应导致掉线（docs/08 §4）

	expired := func(err error) error {
		if errors.Is(err, auth.ErrSessionExpired) {
			_ = auth.DeleteSession(dir, sess.Server)
			a.log.Error("会话已失效，已删除本地令牌，请重新 vpnkit login")
		}
		return err
	}

	if *dryRun {
		s := session.New(opts)
		plan, err := s.DryRun(ctx)
		if err != nil {
			return expired(err)
		}
		plan.Device = "<tun>"
		if runtime.GOOS == "windows" {
			plan.Device = route.WindowsAdapter
		}
		fmt.Fprintf(a.stdout, "# vpnkit up --dry-run（%s）：以下变更不会执行；<tapip> 待 SEND_IP 分配\n", runtime.GOOS)
		m := &route.Manager{GOOS: runtime.GOOS, R: &route.DryRunner{Out: a.stdout, Reader: route.ExecRunner{Log: a.log}}, Log: a.log}
		res, err := m.Apply(ctx, plan)
		if err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrNetConfig, err)
		}
		for _, w := range res.Warnings {
			fmt.Fprintln(a.stdout, "# 警告:", w)
		}
		fmt.Fprintf(a.stdout, "# 默认路由不变；内网网段 %d 条，DNS 分区后缀 %d 个\n", len(plan.Routes), len(plan.DNSSuffixes))
		return nil
	}

	if !*fakeTUN {
		if !platform.Privileged() {
			return fmt.Errorf("%w: up 需要创建 TUN 与修改路由，%s", vpnerr.ErrPermission, platform.ElevateHint)
		}
		if _, err := route.Recover(ctx, dir, route.ExecRunner{Log: a.log}, a.log, platform.ProcessAlive); err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrNetConfig, err)
		}
		opts.OpenDevice = func(mtu int) (platform.Device, error) {
			return platform.OpenTUN(platform.DefaultTUNName(), mtu, a.log)
		}
		opts.Network = &route.Manager{GOOS: runtime.GOOS, R: route.ExecRunner{Log: a.log}, Dir: dir, Log: a.log}
	} else {
		a.log.Warn("--fake-tun：使用内存 TUN，路由/DNS 只打印不执行，仅用于测试")
		opts.OpenDevice = func(mtu int) (platform.Device, error) { return platform.NewMemDevice("memtun0", mtu), nil }
		opts.Network = &route.Manager{GOOS: runtime.GOOS, R: &route.DryRunner{Out: a.stderr, Reader: route.ExecRunner{Log: a.log}}, Log: a.log}
	}

	sfile := statusFile{PID: os.Getpid(), User: sess.User, TwfID: logx.Mask(sess.TwfID), FakeTUN: *fakeTUN}
	kick := make(chan struct{}, 1)
	opts.OnStatus = func(session.Status) {
		select {
		case kick <- struct{}{}:
		default:
		}
	}
	s := session.New(opts)
	write := func() {
		sfile.Session, sfile.UpdatedAt = s.Status(), time.Now().UTC()
		if b, err := json.MarshalIndent(sfile, "", "  "); err == nil {
			_ = fsutil.WriteFile(statusPath(dir), b)
		}
	}
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		tk := time.NewTicker(2 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-kick:
			case <-tk.C:
			}
			write()
		}
	}()
	runDone := make(chan struct{})
	go func() {
		select {
		case <-runDone:
			return
		case <-ctx.Done():
		}
		// 信号到达后最多给 down 流程 10 秒（docs/08 §4）
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			a.log.Error("down 流程超过 10 秒，强制退出；残留配置将在下次 up/down 时按 state.json 清理")
			os.Exit(1)
		}
	}()

	err = s.Run(ctx)
	close(runDone)
	stop()
	<-writerDone
	write()
	if err == nil {
		a.log.Info("已断开，网络配置已恢复")
	}
	return expired(err)
}
