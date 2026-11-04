//go:build !linux

package devid

import "strings"

// virtualPrefixes 是非 Linux 平台退化用的虚拟接口名前缀（docs/06 §3.3）。
var virtualPrefixes = []string{
	"lo", "utun", "tun", "tap", "bridge", "vmnet", "vethernet", "docker", "veth", "virbr",
	"br-", "vboxnet", "awdl", "llw", "gif", "stf", "anpi", "ap", "wg", "zt", "tailscale",
	"ham", "ppp", "vnic", "vpnkit", "ipsec", "isatap", "teredo", "npcap", "bluetooth",
}

func physicalIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	return true
}
