package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/route"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

func init() {
	register(command{"down", "拆除隧道、恢复网络", cmdDown})
}

func readStatus(dir string) (*statusFile, error) {
	b, err := os.ReadFile(statusPath(dir))
	if err != nil {
		return nil, err
	}
	var s statusFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func cmdDown(a *app, args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.initLog(); err != nil {
		return err
	}
	st, err := route.LoadState(a.dir)
	if err != nil {
		return err
	}
	pid := 0
	if st != nil {
		pid = st.PID
	} else if sf, err := readStatus(a.dir); err == nil && sf.Session.State != "idle" {
		pid = sf.PID // --fake-tun 运行不写 state.json
	}
	if pid != 0 && pid != os.Getpid() && platform.ProcessAlive(pid) {
		a.log.Info("通知 vpnkit 进程退出", "pid", pid)
		if err := platform.Terminate(pid); err != nil {
			return fmt.Errorf("%w: 无法通知进程 %d: %v；%s", vpnerr.ErrPermission, pid, err, platform.ElevateHint)
		}
		deadline := time.Now().Add(15 * time.Second)
		for platform.ProcessAlive(pid) && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if platform.ProcessAlive(pid) {
			return fmt.Errorf("进程 %d 在 15 秒内未退出", pid)
		}
		st, _ = route.LoadState(a.dir)
	}
	if st != nil {
		// 进程已不在却留有记录：异常退出或 Windows 强制结束，按记录清理
		if !platform.Privileged() {
			return fmt.Errorf("%w: 存在残留网络配置需要清理，%s", vpnerr.ErrPermission, platform.ElevateHint)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := route.Recover(ctx, a.dir, route.ExecRunner{Log: a.log}, a.log, platform.ProcessAlive); err != nil {
			return fmt.Errorf("%w: %w", vpnerr.ErrNetConfig, err)
		}
	}
	if pid == 0 && st == nil {
		fmt.Fprintln(a.stdout, "没有运行中的 vpnkit")
		return nil
	}
	fmt.Fprintln(a.stdout, "已断开，路由与 DNS 已恢复")
	return nil
}
