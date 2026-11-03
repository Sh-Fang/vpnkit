package route

import (
	"bufio"
	"fmt"
	"net/netip"
	"strings"
)

// WindowsAdapter 是 Windows 上 Wintun 适配器的固定名字（docs/08 §2.4）。
const WindowsAdapter = "vpnkit"

// ResolverDir 是 macOS 分区 DNS 目录（docs/07 §3.3）。
const ResolverDir = "/etc/resolver"

func addrStr(a netip.Addr) string {
	if !a.IsValid() {
		return "<tapip>"
	}
	return a.String()
}

// AddrCmds 配置 TUN 地址与 MTU（docs/08 §2.2–2.4）。
func AddrCmds(goos, dev string, tap netip.Addr, mtu int) [][]string {
	ip := addrStr(tap)
	switch goos {
	case "darwin":
		return [][]string{
			{"ifconfig", dev, "inet", ip, ip, "netmask", "255.255.255.255"},
			{"ifconfig", dev, "mtu", fmt.Sprint(mtu), "up"},
		}
	case "windows":
		return [][]string{
			{"netsh", "interface", "ipv4", "set", "address", "name=" + dev, "static", ip, "255.255.255.255"},
			{"netsh", "interface", "ipv4", "set", "subinterface", dev, fmt.Sprintf("mtu=%d", mtu), "store=active"},
		}
	default:
		return [][]string{
			{"ip", "addr", "add", ip + "/32", "dev", dev},
			{"ip", "link", "set", dev, "mtu", fmt.Sprint(mtu), "up"},
		}
	}
}

// RouteAddCmd / RouteDelCmd 生成内网网段路由命令（docs/07 §2.3）。
func RouteAddCmd(goos string, p netip.Prefix, dev string) []string {
	switch goos {
	case "darwin":
		if p.Bits() == 32 {
			return []string{"route", "-n", "add", "-host", p.Addr().String(), "-interface", dev}
		}
		return []string{"route", "-n", "add", "-net", p.String(), "-interface", dev}
	case "windows":
		return []string{"netsh", "interface", "ipv4", "add", "route", p.String(), dev, "0.0.0.0", "store=active"}
	default:
		return []string{"ip", "route", "add", p.String(), "dev", dev}
	}
}

func RouteDelCmd(goos string, p netip.Prefix, dev string) []string {
	switch goos {
	case "darwin":
		if p.Bits() == 32 {
			return []string{"route", "-n", "delete", "-host", p.Addr().String(), "-interface", dev}
		}
		return []string{"route", "-n", "delete", "-net", p.String(), "-interface", dev}
	case "windows":
		return []string{"netsh", "interface", "ipv4", "delete", "route", p.String(), dev}
	default:
		return []string{"ip", "route", "del", p.String(), "dev", dev}
	}
}

// Gateway 是某个目的地址当前走的物理下一跳。
type Gateway struct {
	Via   string // 下一跳 IP；空表示直连
	Dev   string // 出接口名（Windows 为接口序号）
	Local bool   // 目的地址是本机地址，无需防回环路由
}

// GatewayLookupCmd 查询目的地址当前的下一跳。
func GatewayLookupCmd(goos string, ip netip.Addr) []string {
	switch goos {
	case "darwin":
		return []string{"route", "-n", "get", ip.String()}
	case "windows":
		return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf(`Find-NetRoute -RemoteIPAddress %s | Where-Object { $_.NextHop } | Select-Object -First 1 | ForEach-Object { "$($_.InterfaceIndex) $($_.NextHop)" }`, ip)}
	default:
		return []string{"ip", "-4", "route", "get", ip.String()}
	}
}

// ParseGateway 解析 GatewayLookupCmd 的输出。
func ParseGateway(goos, out string) (Gateway, error) {
	var g Gateway
	switch goos {
	case "darwin":
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "gateway":
				g.Via = v
			case "interface":
				g.Dev = v
			}
		}
		if g.Dev == "lo0" {
			g.Local = true
		}
	case "windows":
		f := strings.Fields(out)
		if len(f) >= 2 {
			g.Dev, g.Via = f[0], f[1]
			if g.Via == "0.0.0.0" {
				g.Via = ""
			}
		}
	default:
		f := strings.Fields(out)
		if len(f) > 0 && f[0] == "local" {
			g.Local = true
		}
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				g.Via = f[i+1]
			case "dev":
				g.Dev = f[i+1]
			}
		}
	}
	if g.Dev == "" && !g.Local {
		return g, fmt.Errorf("无法从输出中解析出接口: %q", strings.TrimSpace(out))
	}
	return g, nil
}

// BypassAddCmd / BypassDelCmd 为服务端地址加走物理接口的 /32 明细路由（docs/07 §2.2）。
func BypassAddCmd(goos string, ip netip.Addr, g Gateway) []string {
	switch goos {
	case "darwin":
		if g.Via != "" && !strings.HasPrefix(g.Via, "link#") {
			return []string{"route", "-n", "add", "-host", ip.String(), g.Via}
		}
		return []string{"route", "-n", "add", "-host", ip.String(), "-interface", g.Dev}
	case "windows":
		via := g.Via
		if via == "" {
			via = "0.0.0.0"
		}
		return []string{"route", "add", ip.String(), "mask", "255.255.255.255", via, "if", g.Dev}
	default:
		if g.Via != "" {
			return []string{"ip", "route", "add", ip.String() + "/32", "via", g.Via, "dev", g.Dev}
		}
		return []string{"ip", "route", "add", ip.String() + "/32", "dev", g.Dev}
	}
}

func BypassDelCmd(goos string, ip netip.Addr) []string {
	switch goos {
	case "darwin":
		return []string{"route", "-n", "delete", "-host", ip.String()}
	case "windows":
		return []string{"route", "delete", ip.String()}
	default:
		return []string{"ip", "route", "del", ip.String() + "/32"}
	}
}

// LinuxDNSCmds 用 systemd-resolved 做分区解析（docs/07 §3.3）。"~" 前缀表示仅路由匹配域。
func LinuxDNSCmds(dev string, servers []netip.Addr, suffixes []string) [][]string {
	dns := []string{"resolvectl", "dns", dev}
	for _, s := range servers {
		dns = append(dns, s.String())
	}
	dom := []string{"resolvectl", "domain", dev}
	for _, s := range suffixes {
		dom = append(dom, "~"+s)
	}
	return [][]string{dns, dom}
}

func LinuxDNSRevertCmd(dev string) []string { return []string{"resolvectl", "revert", dev} }

// NRPTComment 用于精确清理 vpnkit 添加的 NRPT 规则（docs/07 §3.3）。
const NRPTComment = "vpnkit"

func WindowsNRPTAddCmd(servers []netip.Addr, suffixes []string) []string {
	var ns, ss []string
	for _, s := range suffixes {
		ns = append(ns, fmt.Sprintf(`".%s"`, s))
	}
	for _, s := range servers {
		ss = append(ss, fmt.Sprintf(`"%s"`, s))
	}
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Add-DnsClientNrptRule -Namespace %s -NameServers %s -Comment "%s"`, strings.Join(ns, ","), strings.Join(ss, ","), NRPTComment)}
}

func WindowsNRPTDelCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object {$_.Comment -eq "%s"} | Remove-DnsClientNrptRule -Force`, NRPTComment)}
}

// ResolverFile 返回 macOS /etc/resolver/<suffix> 的路径与内容。首行标记归属，清理时据此判断。
func ResolverFile(suffix string, servers []netip.Addr) (string, string) {
	var sb strings.Builder
	sb.WriteString("# managed by vpnkit; removed on vpnkit down\n")
	for _, s := range servers {
		fmt.Fprintf(&sb, "nameserver %s\n", s)
	}
	return ResolverDir + "/" + suffix, sb.String()
}

// ShellQuote 把命令行渲染成可复制执行的形式（--dry-run 输出用）。
func ShellQuote(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"'$|&;<>(){}*?~`\\") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}
