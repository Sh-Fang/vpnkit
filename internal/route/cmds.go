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

// NRPTPolicyKey 是组策略 NRPT 键。它存在时（即使为空）Windows 忽略全部本地 NRPT 规则（docs/07 §3.3）。
const NRPTPolicyKey = `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`

// WindowsNRPTPolicyQueryCmd 输出 "absent"，或 "<子键数> <值数>"。
func WindowsNRPTPolicyQueryCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; if (Test-Path -LiteralPath $k) { '{0} {1}' -f @(Get-ChildItem -LiteralPath $k).Count, @((Get-Item -LiteralPath $k).Property).Count } else { 'absent' }`, NRPTPolicyKey)}
}

// WindowsNRPTPolicyRemoveCmd 只在键为空时删除；执行时再检查一次，避免删掉期间被组策略写入的内容。
func WindowsNRPTPolicyRemoveCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; if (@(Get-ChildItem -LiteralPath $k).Count -eq 0 -and @((Get-Item -LiteralPath $k).Property).Count -eq 0) { Remove-Item -LiteralPath $k } else { exit 3 }`, NRPTPolicyKey)}
}

// WindowsNRPTPolicyRestoreCmd 重建空键；已存在时不动（New-Item -Force 会清空已有键）。
func WindowsNRPTPolicyRestoreCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; if (-not (Test-Path -LiteralPath $k)) { New-Item -Path $k | Out-Null }`, NRPTPolicyKey)}
}

// ParseNRPTPolicy 解析 WindowsNRPTPolicyQueryCmd 的输出。
func ParseNRPTPolicy(out string) (exists, empty bool, err error) {
	f := strings.Fields(out)
	if len(f) == 1 && f[0] == "absent" {
		return false, false, nil
	}
	if len(f) != 2 {
		return false, false, fmt.Errorf("无法解析组策略 NRPT 键查询结果 %q", strings.TrimSpace(out))
	}
	return true, f[0] == "0" && f[1] == "0", nil
}

func WindowsNRPTDelCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-DnsClientNrptRule | Where-Object {$_.Comment -eq "%s"} | Remove-DnsClientNrptRule -Force`, NRPTComment)}
}

// ProxySettingsKey 是当前用户的系统代理设置；Clash 等工具开"系统代理"时写的就是这里。
const ProxySettingsKey = `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// proxyNotify 通知 WinINet 设置已变（INTERNET_OPTION_SETTINGS_CHANGED=39、REFRESH=37），浏览器据此重读代理例外。
const proxyNotify = `Add-Type -Namespace vpnkit -Name WinINet -MemberDefinition '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h, int o, System.IntPtr b, int l);'; [void][vpnkit.WinINet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0); [void][vpnkit.WinINet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)`

const proxyCurrent = `$cur=@(((Get-ItemProperty -LiteralPath $k -Name ProxyOverride -ErrorAction SilentlyContinue).ProxyOverride -split ';') | Where-Object { $_ })`

// WindowsProxyBypassQueryCmd 输出系统代理例外列表（ProxyOverride，分号分隔）。
func WindowsProxyBypassQueryCmd() []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; (Get-ItemProperty -LiteralPath $k -Name ProxyOverride -ErrorAction SilentlyContinue).ProxyOverride`, ProxySettingsKey)}
}

// WindowsProxyBypassAddCmd 把 entries 中尚未存在的条目追加到系统代理例外末尾。
func WindowsProxyBypassAddCmd(entries []string) []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; $add=@(%s); %s; $new=$cur + @($add | Where-Object { $cur -notcontains $_ }); Set-ItemProperty -LiteralPath $k -Name ProxyOverride -Value ($new -join ';'); %s`,
			ProxySettingsKey, psList(entries), proxyCurrent, proxyNotify)}
}

// WindowsProxyBypassDelCmd 只删除 entries 中的条目，其余例外保持原样。
func WindowsProxyBypassDelCmd(entries []string) []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`$k='%s'; $del=@(%s); %s; $new=@($cur | Where-Object { $del -notcontains $_ }); Set-ItemProperty -LiteralPath $k -Name ProxyOverride -Value ($new -join ';'); %s`,
			ProxySettingsKey, psList(entries), proxyCurrent, proxyNotify)}
}

func psList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return strings.Join(q, ",")
}

// ParseProxyBypass 解析 WindowsProxyBypassQueryCmd 的输出。
func ParseProxyBypass(out string) []string {
	var r []string
	for _, e := range strings.Split(strings.TrimSpace(out), ";") {
		if e = strings.TrimSpace(e); e != "" {
			r = append(r, e)
		}
	}
	return r
}

// maxBypassExpand 是非整字节网段展开成通配条目的上限；超过时退到更粗的一级。
const maxBypassExpand = 16

// ProxyBypassEntries 把内网网段与域名后缀换成系统代理例外条目。
// WinINet 例外只认通配符，不认 CIDR，所以网段按整字节边界写成 "10.*"、"172.16.*"。
func ProxyBypassEntries(routes []netip.Prefix, suffixes []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(e string) {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, r := range routes {
		if !r.Addr().Is4() {
			continue
		}
		r = r.Masked()
		bits := r.Bits() / 8 * 8
		if bits < r.Bits() && 1<<(bits+8-r.Bits()) <= maxBypassExpand {
			bits += 8
		}
		if bits == 0 {
			continue
		}
		base := r.Addr().As4()
		n := 1
		if bits > r.Bits() {
			n = 1 << (bits - r.Bits())
		}
		for i := 0; i < n; i++ {
			o := base
			o[bits/8-1] += byte(i)
			parts := make([]string, bits/8)
			for j := range parts {
				parts[j] = fmt.Sprint(o[j])
			}
			e := strings.Join(parts, ".")
			if bits < 32 {
				e += ".*"
			}
			add(e)
		}
	}
	for _, s := range suffixes {
		if !validBypassHost(s) {
			continue
		}
		add(s)
		add("*." + s)
	}
	return out
}

func validBypassHost(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
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
