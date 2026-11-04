package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"login", "认证并保存会话令牌", cmdLogin})
	register(command{"logout", "清除本地令牌", cmdLogout})
}

// serverFlags 是需要连网关的命令共用的参数。
type serverFlags struct {
	server   string
	port     int
	insecure bool
	caFile   string
	certSHA  string
}

func (s *serverFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.server, "server", "", "网关地址（覆盖 server.host）")
	fs.IntVar(&s.port, "port", 0, "网关 HTTPS 端口（覆盖 server.port）")
	fs.BoolVar(&s.insecure, "insecure", false, "跳过网关证书校验（覆盖 server.insecure）")
	fs.StringVar(&s.caFile, "ca-file", "", "信任的 CA 证书 PEM（覆盖 server.ca_file）")
	fs.StringVar(&s.certSHA, "cert-sha256", "", "只信任这一张网关证书的 SHA-256 指纹（覆盖 server.cert_sha256）")
}

func (s *serverFlags) apply(a *app) {
	if s.server != "" {
		host := s.server
		// 接受 host:port 形式，便于直接粘贴测试服务地址
		if h, p, ok := strings.Cut(host, ":"); ok && !strings.Contains(p, ":") {
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
				host = h
				if s.port == 0 {
					s.port = port
				}
			}
		}
		a.cfg.Server.Host = host
	}
	if s.port != 0 {
		a.cfg.Server.Port = s.port
	}
	if s.insecure {
		a.cfg.Server.Insecure = true
	}
	if s.caFile != "" {
		a.cfg.Server.CAFile = s.caFile
	}
	if s.certSHA != "" {
		a.cfg.Server.CertSHA256 = s.certSHA
	}
}

func (a *app) authClient() (*auth.Client, error) {
	return auth.New(auth.Options{
		Server:            a.cfg.Server.Host,
		Port:              a.cfg.Server.Port,
		Insecure:          a.cfg.Server.Insecure,
		CAFile:            a.cfg.Server.CAFile,
		CertSHA256:        a.cfg.Server.CertSHA256,
		Timeout:           a.g.timeout,
		MitmField:         a.cfg.Auth.MitmField,
		SendRandCode:      a.cfg.Auth.SendRandCode,
		DeviceIDField:     a.cfg.Auth.DeviceIDField,
		RegisterDevice:    a.cfg.Auth.RegisterDevice,
		HIDEndpoint:       a.cfg.Auth.HIDEndpoint,
		HIDQuery:          a.cfg.Auth.HIDQuery,
		HIDField:          a.cfg.Auth.HIDField,
		HIDLanguage:       a.cfg.Auth.HIDLanguage,
		SubmitHIDEndpoint: a.cfg.Auth.SubmitHIDEndpoint,
		HardIDEndpoint:    a.cfg.Auth.HardIDEndpoint,
		Logger:            a.log,
	})
}

func cmdLogin(a *app, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	var sf serverFlags
	sf.register(fs)
	user := fs.String("user", "", "账号（覆盖 auth.user）")
	captcha := fs.String("captcha", "", "图形验证码（网关启用时）")
	registerDevice := fs.Bool("register-device", false, "网关要求 auth/hid 时提交本机特征码完成设备登记")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	sf.apply(a)
	if *user != "" {
		a.cfg.Auth.User = *user
	}
	if *registerDevice {
		a.cfg.Auth.RegisterDevice = true
	}
	if err := a.initLog(); err != nil {
		return err
	}
	if err := a.cfg.Validate(true); err != nil {
		return err
	}
	if a.cfg.Auth.User == "" {
		return fmt.Errorf("%w: 未指定账号：用 --user 或配置 auth.user", vpnerr.ErrUsage)
	}
	dir, err := fsutil.EnsureDir()
	if err != nil {
		return err
	}

	password := os.Getenv("VPNKIT_PASSWORD")
	if password == "" {
		password, err = platform.ReadPassword("密码: ", a.stderr)
		if err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrUsage, err)
		}
	}
	if password == "" {
		return fmt.Errorf("%w: 密码为空", vpnerr.ErrUsage)
	}

	prev, _ := auth.LoadSession(dir, a.cfg.Server.Host)
	devID, err := a.deviceIDForLogin(prev)
	if err != nil {
		return err
	}

	c, err := a.authClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*a.g.timeout)
	defer cancel()
	mac, host := "", ""
	if a.cfg.Auth.RegisterDevice {
		mac, host = hidExtras(a)
	}
	tok, err := c.Login(ctx, auth.LoginRequest{
		User: a.cfg.Auth.User, Password: password, Captcha: *captcha,
		DeviceID: devID, MACAddress: mac, Hostname: host,
	})
	password = ""
	if err != nil {
		return err
	}
	// 这步登录已经让网关认下这个特征码，立刻固化它：否则网卡列表一变（换 Wi-Fi、插网线、
	// 起 docker），下次算出来的值就变了，网关又当成新设备，重新要一遍审批（docs/06 §5）。
	if a.cfg.Auth.RegisterDevice && devID != "" {
		if err := pinDeviceID(a, devID); err != nil {
			a.log.Warn("固化设备标识失败，下次网络变化可能被网关当成新设备", "err", err)
		} else {
			a.log.Info("已固化设备标识", "devid", logx.Mask(devID))
		}
	}
	sess := &auth.Session{
		Server: a.cfg.Server.Host, Port: a.cfg.Server.Port, User: a.cfg.Auth.User,
		TwfID: tok, ObtainedAt: time.Now().UTC(), ExpiresHint: 3600,
	}
	// 顺带取一次 conf.csp：既验证令牌可用，也缓存 isHidUser 供下次 send_device_id=auto 决策。
	if conf, warns, err := c.FetchConf(ctx, tok); err == nil {
		for _, w := range warns {
			a.log.Warn(w)
		}
		hid := conf.IsHidUser
		if !conf.IsHidUserSet {
			a.log.Info("conf.csp 未提供 Other.isHidUser，按 0 处理")
		}
		logx.Assumption(a.log, "is_hid_user", hid, "present", conf.IsHidUserSet)
		sess.IsHidUser = &hid
		if hid == 1 && devID == "" && a.cfg.Auth.SendDeviceID == "auto" {
			a.log.Warn("该账号启用了设备绑定，但本次登录未上报设备标识；再执行一次 login 即会上报")
		}
	} else {
		a.log.Warn("登录成功但拉取 conf.csp 失败", "err", err)
	}
	if err := auth.SaveSession(dir, sess); err != nil {
		return err
	}
	a.log.Info("登录成功", "server", sess.Server, "user", sess.User, "twfid", logx.Mask(tok))
	fmt.Fprintf(a.stdout, "登录成功：%s@%s，令牌 %s 已保存到 %s\n", sess.User, sess.Server, logx.Mask(tok), auth.SessionPath(dir, sess.Server))
	return nil
}

func cmdLogout(a *app, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	server := fs.String("server", "", "网关地址；不指定时用配置或唯一的本地会话")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.initLog(); err != nil {
		return err
	}
	host, err := a.resolveSessionServer(*server)
	if err != nil {
		return err
	}
	if err := auth.DeleteSession(a.dir, host); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "已清除 %s 的本地令牌\n", host)
	return nil
}

// resolveSessionServer 决定操作哪个网关的会话：参数 > 配置 > 唯一的本地会话。
func (a *app) resolveSessionServer(flagServer string) (string, error) {
	if flagServer != "" {
		h, _, _ := strings.Cut(flagServer, ":")
		return h, nil
	}
	if a.cfg.Server.Host != "" {
		return a.cfg.Server.Host, nil
	}
	list := auth.ListSessions(a.dir)
	switch len(list) {
	case 0:
		return "", fmt.Errorf("%w: %w", vpnerr.ErrAuth, auth.ErrNoSession)
	case 1:
		return list[0], nil
	}
	return "", fmt.Errorf("%w: 存在多个网关的会话 %v，请用 --server 指定", vpnerr.ErrUsage, list)
}

// deviceIDForLogin 依据 auth.send_device_id 决定是否上报设备标识（docs/06 §6）。
func (a *app) deviceIDForLogin(prev *auth.Session) (string, error) {
	send := false
	switch a.cfg.Auth.SendDeviceID {
	case "always":
		send = true
	case "auto":
		send = prev != nil && prev.IsHidUser != nil && *prev.IsHidUser == 1
	}
	// 开启设备登记时必须带上特征码，否则 hid 这步没东西可提交。
	if a.cfg.Auth.RegisterDevice {
		send = true
	}
	if !send {
		return "", nil
	}
	id, err := deviceID(a)
	if err != nil {
		if a.cfg.Auth.SendDeviceID == "always" {
			return "", err
		}
		a.log.Warn("获取设备标识失败，本次不上报", "err", err)
		return "", nil
	}
	return id, nil
}

// deviceID 由 devid 子命令实现；P1 阶段尚未接入时返回明确错误。
var deviceID = func(*app) (string, error) {
	return "", errors.New("设备标识模块未接入")
}

// hidExtras 取 auth/hid 登记要连同特征码上报的本机 MAC 与主机名；由 devid 子命令接入。
var hidExtras = func(*app) (mac, host string) { return "", "" }

// pinDeviceID 把本次登录用的特征码固化下来；由 devid 子命令接入。
var pinDeviceID = func(*app, string) error { return errors.New("设备标识模块未接入") }
