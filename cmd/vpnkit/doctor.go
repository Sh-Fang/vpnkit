package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/route"
)

func init() {
	register(command{"doctor", "环境自检（权限、TUN 设备、路由工具）", cmdDoctor})
}

type check struct {
	Name   string `json:"name"`
	Level  string `json:"level"` // ok | warn | fail
	Detail string `json:"detail"`
}

var errDoctorFailed = errors.New("环境自检存在失败项")

func cmdDoctor(a *app, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.initLog(); err != nil {
		return err
	}
	var cs []check
	add := func(name, level, detail string) { cs = append(cs, check{name, level, detail}) }

	add("平台", "ok", runtime.GOOS+"/"+runtime.GOARCH)
	if platform.Privileged() {
		add("权限", "ok", "当前进程可创建 TUN 与修改路由")
	} else {
		add("权限", "warn", "up/down 需要提权："+platform.ElevateHint)
	}

	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			add("TUN 设备", "fail", "/dev/net/tun 不存在（需加载 tun 内核模块）")
		} else {
			add("TUN 设备", "ok", "/dev/net/tun")
		}
	case "darwin":
		add("TUN 设备", "ok", "utun 由内核提供")
	case "windows":
		exe, _ := os.Executable()
		dll := filepath.Join(filepath.Dir(exe), "wintun.dll")
		if _, err := os.Stat(dll); err != nil {
			add("TUN 设备", "warn", "未在程序目录找到 wintun.dll（从 wintun.net 获取并放在 vpnkit.exe 旁）；也可能被杀毒软件拦截")
		} else {
			add("TUN 设备", "ok", dll)
		}
	}

	tools := map[string][]string{
		"linux":   {"ip"},
		"darwin":  {"route", "ifconfig", "netstat"},
		"windows": {"netsh", "route", "powershell"},
	}[runtime.GOOS]
	for _, t := range tools {
		if p, err := exec.LookPath(t); err != nil {
			add("路由工具 "+t, "fail", "未找到；Linux 请安装 iproute2")
		} else {
			add("路由工具 "+t, "ok", p)
		}
	}
	switch runtime.GOOS {
	case "linux":
		if p, err := exec.LookPath("resolvectl"); err != nil {
			add("DNS 分区", "warn", "未找到 resolvectl（systemd-resolved），DNS 分区不可用，vpnkit 不会改 /etc/resolv.conf")
		} else {
			add("DNS 分区", "ok", p)
		}
	case "darwin":
		add("DNS 分区", "ok", route.ResolverDir)
	case "windows":
		add("DNS 分区", "ok", "NRPT（Add-DnsClientNrptRule）")
	}

	if a.cfg.Server.Host == "" {
		add("配置", "warn", "未配置 server.host："+a.cfg.Path)
	} else if err := a.cfg.Validate(true); err != nil {
		add("配置", "fail", err.Error())
	} else {
		add("配置", "ok", a.cfg.Path)
	}
	for _, w := range a.cfg.Warnings {
		add("配置", "warn", w)
	}
	if os.Getenv("VPNKIT_PASSWORD") != "" {
		add("环境变量", "warn", "VPNKIT_PASSWORD 已设置（值已屏蔽），用完请清除")
	}
	if host := a.cfg.Server.Host; host != "" {
		if _, err := auth.LoadSession(a.dir, host); err != nil {
			add("会话", "warn", "没有 "+host+" 的本地令牌，先执行 vpnkit login")
		} else {
			add("会话", "ok", auth.SessionPath(a.dir, host))
		}
	}
	if st, _ := route.LoadState(a.dir); st != nil {
		if platform.ProcessAlive(st.PID) {
			add("运行状态", "ok", fmt.Sprintf("vpnkit 正在运行（pid %d）", st.PID))
		} else {
			add("运行状态", "warn", "存在上次异常退出的残留配置，下次 up 或 down 会自动清理")
		}
	}

	failed := false
	for _, c := range cs {
		if c.Level == "fail" {
			failed = true
		}
	}
	if a.g.json {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"ok": !failed, "checks": cs})
	} else {
		mark := map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}
		for _, c := range cs {
			fmt.Fprintf(a.stdout, "[%s] %-12s %s\n", mark[c.Level], c.Name, c.Detail)
		}
	}
	if failed {
		return errDoctorFailed
	}
	return nil
}
