package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/logx"
)

var (
	ErrAllRoutesFailed = errors.New("全部内网网段路由添加失败")
	ErrBypassRequired  = errors.New("隧道服务端地址落在内网网段内，但无法为其添加防回环路由")
	ErrAlreadyRunning  = errors.New("另一个 vpnkit 正在运行")
)

// Manager 实现 session.Network：先记后改，失败回滚，Teardown 幂等（docs/07 §1、§6）。
type Manager struct {
	GOOS string
	R    Runner
	// Dir 是 state.json 所在目录；空表示不记录（--dry-run）。
	Dir string
	Log *slog.Logger

	st *State
}

func (m *Manager) log() *slog.Logger { return logx.Or(m.Log) }

func (m *Manager) save() {
	if err := saveState(m.Dir, m.st); err != nil {
		m.log().Error("写 state.json 失败", "err", err)
	}
}

// Apply 依次下发：防回环路由 → TUN 地址/MTU → 内网网段路由 → 分区 DNS。
func (m *Manager) Apply(ctx context.Context, p Plan) (Result, error) {
	var res Result
	if m.st == nil {
		m.st = &State{PID: os.Getpid(), GOOS: m.GOOS, Tun: p.Device, StartedAt: time.Now().UTC()}
	}
	m.st.Tun = p.Device
	m.save()

	fail := func(err error) (Result, error) {
		if terr := m.Teardown(ctx); terr != nil {
			m.log().Error("回滚时出错", "err", terr)
		}
		return Result{}, err
	}

	// 1. 防回环：服务端地址必须走物理接口（docs/07 §2.2）
	for _, ip := range p.Bypass {
		if ip.IsLoopback() {
			continue
		}
		inRoutes := false
		for _, r := range p.Routes {
			if r.Contains(ip) {
				inRoutes = true
			}
		}
		out, err := m.R.Query(ctx, GatewayLookupCmd(m.GOOS, ip))
		var g Gateway
		if err == nil {
			g, err = ParseGateway(m.GOOS, string(out))
		}
		if err != nil {
			if inRoutes {
				return fail(fmt.Errorf("%w: %s: %v", ErrBypassRequired, ip, err))
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("查询 %s 的物理下一跳失败，跳过防回环路由（该地址不在内网网段内）: %v", ip, err))
			continue
		}
		if g.Local || g.Dev == p.Device {
			continue
		}
		m.st.BypassAdded = append(m.st.BypassAdded, ip.String())
		m.save()
		if out, err := m.R.Run(ctx, BypassAddCmd(m.GOOS, ip, g)); err != nil {
			m.st.BypassAdded = m.st.BypassAdded[:len(m.st.BypassAdded)-1]
			m.save()
			if alreadyExists(string(out), err) {
				// 已有明细路由：不覆盖、也不在 down 时删除别人的路由
				continue
			}
			if inRoutes {
				return fail(fmt.Errorf("%w: %s: %v", ErrBypassRequired, ip, err))
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("添加防回环路由 %s 失败: %v", ip, err))
		}
	}

	// 2. TUN 地址与 MTU（Windows 的 Wintun 由 netsh 配置，同样走这里）
	for _, c := range AddrCmds(m.GOOS, p.Device, p.TapIP, p.MTU) {
		if _, err := m.R.Run(ctx, c); err != nil {
			return fail(fmt.Errorf("配置 TUN 地址: %w", err))
		}
	}

	// 3. 内网网段：部分失败继续，全部失败回滚（docs/07 §2.4）
	for _, r := range p.Routes {
		m.st.RoutesAdded = append(m.st.RoutesAdded, r.String())
		m.save()
		out, err := m.R.Run(ctx, RouteAddCmd(m.GOOS, r, p.Device))
		if err != nil {
			m.st.RoutesAdded = m.st.RoutesAdded[:len(m.st.RoutesAdded)-1]
			m.save()
			reason := err.Error()
			if alreadyExists(string(out), err) {
				reason = "与已有路由冲突，已跳过，不覆盖现有路由"
			}
			m.log().Warn("网段路由添加失败", "route", r, "reason", reason)
			res.RoutesFailed = append(res.RoutesFailed, r.String()+": "+reason)
			continue
		}
		res.RoutesOK = append(res.RoutesOK, r)
	}
	if len(p.Routes) > 0 && len(res.RoutesOK) == 0 {
		return fail(fmt.Errorf("%w（%d 条）: %s", ErrAllRoutesFailed, len(p.Routes), strings.Join(res.RoutesFailed, "; ")))
	}

	// 4. 分区 DNS（docs/07 §3）；失败只告警，不影响路由
	if len(p.DNSSuffixes) > 0 && len(p.DNSServers) > 0 {
		ok, warns := m.applyDNS(ctx, p)
		res.DNSEnabled = ok
		res.Warnings = append(res.Warnings, warns...)
	}
	return res, nil
}

func (m *Manager) applyDNS(ctx context.Context, p Plan) (bool, []string) {
	var warns []string
	switch m.GOOS {
	case "darwin":
		any := false
		for _, sfx := range p.DNSSuffixes {
			path, content := ResolverFile(sfx, p.DNSServers)
			if b, err := m.R.ReadFile(path); err == nil && !strings.HasPrefix(string(b), "# managed by vpnkit") {
				warns = append(warns, fmt.Sprintf("%s 已存在且不是 vpnkit 创建的，跳过该后缀", path))
				continue
			}
			m.st.DNSFiles = append(m.st.DNSFiles, path)
			m.save()
			if err := m.R.WriteFile(path, content); err != nil {
				m.st.DNSFiles = m.st.DNSFiles[:len(m.st.DNSFiles)-1]
				m.save()
				warns = append(warns, fmt.Sprintf("写 %s 失败: %v", path, err))
				continue
			}
			any = true
		}
		return any, warns
	case "windows":
		m.st.NRPTAdded = append(m.st.NRPTAdded, p.DNSSuffixes...)
		m.save()
		if _, err := m.R.Run(ctx, WindowsNRPTAddCmd(p.DNSServers, p.DNSSuffixes)); err != nil {
			m.st.NRPTAdded = nil
			m.save()
			_, _ = m.R.Run(ctx, WindowsNRPTDelCmd())
			return false, append(warns, "添加 NRPT 规则失败，DNS 分区未启用: "+err.Error())
		}
		return true, warns
	default:
		if !m.R.LookPath("resolvectl") {
			// 不直接改 /etc/resolv.conf（docs/07 §3.3）
			return false, append(warns, "未找到 systemd-resolved（resolvectl），不支持分区 DNS；内网域名请手动配置，vpnkit 不会修改 /etc/resolv.conf")
		}
		m.st.ResolvectlLink = p.Device
		m.save()
		for _, c := range LinuxDNSCmds(p.Device, p.DNSServers, p.DNSSuffixes) {
			if _, err := m.R.Run(ctx, c); err != nil {
				_, _ = m.R.Run(ctx, LinuxDNSRevertCmd(p.Device))
				m.st.ResolvectlLink = ""
				m.save()
				return false, append(warns, "resolvectl 配置失败，DNS 分区未启用: "+err.Error())
			}
		}
		return true, warns
	}
}

// Teardown 按记录逆序撤销全部变更；清理失败不中断，收集后一并返回（docs/07 §6）。
func (m *Manager) Teardown(ctx context.Context) error {
	if m.st == nil {
		return nil
	}
	errs := Cleanup(ctx, m.R, m.st, m.log())
	if len(errs) == 0 {
		if err := removeState(m.Dir); err != nil {
			errs = append(errs, err)
		}
	} else {
		m.save() // 保留未清理成功的部分，下次 up 或 down 再试
	}
	m.st = nil
	return errors.Join(errs...)
}

// Cleanup 撤销 st 中记录的变更，成功撤销的条目从 st 中移除。
func Cleanup(ctx context.Context, r Runner, st *State, log *slog.Logger) []error {
	var errs []error
	goos := st.GOOS
	run := func(argv []string) error {
		out, err := r.Run(ctx, argv)
		if err != nil && !alreadyGone(string(out), err) {
			return err
		}
		return nil
	}
	// DNS
	if len(st.NRPTAdded) > 0 {
		if err := run(WindowsNRPTDelCmd()); err != nil {
			errs = append(errs, err)
		} else {
			st.NRPTAdded = nil
		}
	}
	if st.ResolvectlLink != "" {
		if err := run(LinuxDNSRevertCmd(st.ResolvectlLink)); err != nil {
			errs = append(errs, err)
		} else {
			st.ResolvectlLink = ""
		}
	}
	var keepFiles []string
	for _, f := range st.DNSFiles {
		if b, err := r.ReadFile(f); err == nil && !strings.HasPrefix(string(b), "# managed by vpnkit") {
			log.Warn("resolver 文件已被他人改写，不删除", "path", f)
			continue
		}
		if err := r.RemoveFile(f); err != nil {
			errs = append(errs, err)
			keepFiles = append(keepFiles, f)
		}
	}
	st.DNSFiles = keepFiles
	// 网段路由（逆序）
	var keepRoutes []string
	for i := len(st.RoutesAdded) - 1; i >= 0; i-- {
		pfx, err := netip.ParsePrefix(st.RoutesAdded[i])
		if err != nil {
			continue
		}
		if err := run(RouteDelCmd(goos, pfx, st.Tun)); err != nil {
			errs = append(errs, err)
			keepRoutes = append(keepRoutes, st.RoutesAdded[i])
		}
	}
	st.RoutesAdded = keepRoutes
	// 防回环路由
	var keepBypass []string
	for i := len(st.BypassAdded) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(st.BypassAdded[i])
		if err != nil {
			continue
		}
		if err := run(BypassDelCmd(goos, ip)); err != nil {
			errs = append(errs, err)
			keepBypass = append(keepBypass, st.BypassAdded[i])
		}
	}
	st.BypassAdded = keepBypass
	return errs
}

// Recover 处理上次异常退出留下的 state.json（docs/01 §5）。
// alive 判断记录中的进程是否仍在运行；仍在运行时拒绝继续，避免两个实例互相破坏路由表。
func Recover(ctx context.Context, dir string, r Runner, log *slog.Logger, alive func(int) bool) (bool, error) {
	st, err := LoadState(dir)
	if err != nil {
		return false, fmt.Errorf("读取 state.json: %w", err)
	}
	if st == nil {
		return false, nil
	}
	if st.PID != os.Getpid() && alive(st.PID) {
		return false, fmt.Errorf("%w（pid %d）；先执行 vpnkit down", ErrAlreadyRunning, st.PID)
	}
	log = logx.Or(log)
	log.Warn("检测到上次异常退出的残留配置，开始清理", "pid", st.PID, "routes", len(st.RoutesAdded), "bypass", len(st.BypassAdded))
	if errs := Cleanup(ctx, r, st, log); len(errs) > 0 {
		_ = saveState(dir, st)
		return true, fmt.Errorf("清理残留配置未完全成功: %w", errors.Join(errs...))
	}
	return true, removeState(dir)
}

func alreadyExists(out string, err error) bool {
	s := strings.ToLower(out + " " + err.Error())
	return strings.Contains(s, "file exists") || strings.Contains(s, "already exists") || strings.Contains(s, "object already exists")
}

// alreadyGone 识别"要删的东西已经不在了"，让清理保持幂等。
func alreadyGone(out string, err error) bool {
	s := strings.ToLower(out + " " + err.Error())
	for _, k := range []string{"no such process", "not in table", "cannot find device", "element not found", "no such file", "not found", "does not exist"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}
