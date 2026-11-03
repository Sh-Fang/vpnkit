package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/devid"
	"github.com/Sh-Fang/vpnkit/internal/platform"
)

func init() {
	register(command{"status", "打印状态与统计", cmdStatus})
}

func cmdStatus(a *app, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	showDevid := fs.Bool("show-devid", false, "在输出中包含设备标识（默认不含，docs/06 §6）")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.initLog(); err != nil {
		return err
	}
	sf, err := readStatus(a.dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	running := sf != nil && sf.PID != os.Getpid() && platform.ProcessAlive(sf.PID) && sf.Session.State != "idle"
	out := map[string]any{"running": running}
	if sf != nil {
		if !running {
			sf.Session.State = "idle"
		}
		out["pid"] = sf.PID
		out["user"] = sf.User
		out["twfid"] = sf.TwfID
		out["updated_at"] = sf.UpdatedAt
		out["session"] = sf.Session
	} else {
		out["session"] = map[string]any{"state": "idle"}
	}
	if *showDevid {
		if id, _, err := devid.Get(a.dir, devid.SystemSource{}); err == nil {
			out["device_id"] = id
		}
	}
	if a.g.json {
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if sf == nil {
		fmt.Fprintln(a.stdout, "状态: idle（从未运行）")
		return nil
	}
	s := sf.Session
	fmt.Fprintf(a.stdout, "状态:     %s", s.State)
	if !running {
		fmt.Fprint(a.stdout, "（以下为最后一次运行的记录）")
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintf(a.stdout, "网关:     %s  用户 %s  令牌 %s\n", s.Server, sf.User, sf.TwfID)
	if s.TunnelAddr != "" {
		fmt.Fprintf(a.stdout, "隧道:     %s\n", s.TunnelAddr)
	}
	if s.TapIP != "" {
		fmt.Fprintf(a.stdout, "虚拟 IP:  %s（设备 %s，MTU %d）\n", s.TapIP, s.Device, s.MTU)
		fmt.Fprintf(a.stdout, "下发参数: enc=%d zip=%d udpport=%d\n", s.Enc, s.Zip, s.UDPPort)
	}
	fmt.Fprintf(a.stdout, "内网网段: %d 条 %s\n", len(s.Routes), strings.Join(s.Routes, " "))
	for _, f := range s.RoutesFailed {
		fmt.Fprintf(a.stdout, "  失败:   %s\n", f)
	}
	if s.DNSEnabled {
		fmt.Fprintf(a.stdout, "DNS 分区: %s → %s\n", strings.Join(s.DNSSuffixes, ","), strings.Join(s.DNSServers, ","))
	} else {
		fmt.Fprintln(a.stdout, "DNS 分区: 未启用（内网域名可能需要用 IP 访问）")
	}
	if s.RecvLimit > 0 || s.SendLimit > 0 {
		fmt.Fprintf(a.stdout, "服务端限速: 下行 %d bps / 上行 %d bps\n", s.RecvLimit, s.SendLimit)
	}
	fmt.Fprintf(a.stdout, "统计:     发 %d 包 / %d 字节，收 %d 包 / %d 字节，丢弃 %d，重连 %d 次\n",
		s.Stats.TxPackets, s.Stats.TxBytes, s.Stats.RxPackets, s.Stats.RxBytes, s.Stats.Dropped, s.Reconnects)
	if s.StopReason != "" {
		fmt.Fprintf(a.stdout, "终止原因: %s\n", s.StopReason)
	}
	if s.LastError != "" {
		fmt.Fprintf(a.stdout, "最后错误: %s\n", s.LastError)
	}
	for _, w := range s.Warnings {
		fmt.Fprintf(a.stdout, "警告:     %s\n", w)
	}
	return nil
}
