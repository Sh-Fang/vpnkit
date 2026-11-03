// Package devid 计算并持久化设备标识（docs/06）。
package devid

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

var (
	ErrNoFingerprintSource = errors.New("devid: 既没有物理网卡 MAC，也没有卷序列号")
	ErrBadFormat           = errors.New("devid: 设备标识必须是 32 位大写十六进制")
)

var reID = regexp.MustCompile(`^[0-9A-F]{32}$`)

// Valid 判断是否符合 [0-9A-F]{32}。
func Valid(s string) bool { return reID.MatchString(s) }

// Iface 是计算指纹所需的网卡信息。
type Iface struct {
	Name     string
	MAC      string
	Loopback bool
}

// FingerprintParts 是规范化后的指纹要素。
type FingerprintParts struct {
	MACList      string // 按接口名排序、大写、无分隔符拼接
	VolumeSerial string // 已按 %02x%02X%02x%02x 格式化
}

// Source 抽象指纹来源，便于测试注入。
type Source interface {
	Interfaces() ([]Iface, error)
	VolumeSerial() (uint32, bool, error)
}

// SystemSource 读取本机真实信息。
type SystemSource struct{}

func (SystemSource) Interfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		out = append(out, Iface{Name: i.Name, MAC: i.HardwareAddr.String(), Loopback: i.Flags&net.FlagLoopback != 0})
	}
	return out, nil
}

func (SystemSource) VolumeSerial() (uint32, bool, error) { return platform.VolumeSerial() }

// 虚拟接口名前缀（docs/06 §2.1）。按小写比较。
var virtualPrefixes = []string{
	"lo", "utun", "tun", "tap", "bridge", "vmnet", "vethernet", "docker", "veth", "virbr",
	"br-", "vboxnet", "awdl", "llw", "gif", "stf", "anpi", "ap", "wg", "zt", "tailscale",
	"ham", "ppp", "vnic", "vpnkit", "ipsec", "isatap", "teredo", "npcap", "bluetooth",
}

func isVirtual(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// Collect 把来源规范化为指纹要素（docs/06 §2.1、§2.2）。
func Collect(src Source) (FingerprintParts, error) {
	var p FingerprintParts
	ifs, err := src.Interfaces()
	if err != nil {
		return p, err
	}
	ifs = append([]Iface(nil), ifs...) // 不改动调用方的切片
	sort.Slice(ifs, func(i, j int) bool { return ifs[i].Name < ifs[j].Name })
	var sb strings.Builder
	for _, i := range ifs {
		if i.Loopback || isVirtual(i.Name) {
			continue
		}
		mac := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(i.MAC))
		if mac == "" || strings.Trim(mac, "0") == "" {
			continue
		}
		sb.WriteString(mac)
	}
	p.MACList = sb.String()
	if serial, ok, err := src.VolumeSerial(); err == nil && ok {
		p.VolumeSerial = FormatVolumeSerial(serial)
	}
	return p, nil
}

// FormatVolumeSerial 按 "%02x%02X%02x%02x" 格式化，第二字节大写——
// 照抄原客户端的既有行为（服务端按其输出登记过），不要"修正"（docs/06 §2.2）。
func FormatVolumeSerial(v uint32) string {
	return fmt.Sprintf("%02x%02X%02x%02x", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// buildPlaintext 决定要素拼接次序（docs/06 §3，TODO(待实测)）；将来确认次序后只改这里。
func buildPlaintext(p FingerprintParts) (string, error) {
	if p.MACList != "" {
		return p.MACList, nil
	}
	if p.VolumeSerial != "" {
		return p.VolumeSerial, nil
	}
	return "", ErrNoFingerprintSource
}

// Compute 实时计算设备标识。
func Compute(src Source) (string, error) {
	p, err := Collect(src)
	if err != nil {
		return "", err
	}
	pt, err := buildPlaintext(p)
	if err != nil {
		return "", err
	}
	return wire.MD5Upper(pt), nil
}

// CachePath 返回 device-id 文件路径。
func CachePath(dir string) string { return filepath.Join(dir, "device-id") }

// Get 按 docs/06 §2 的优先级取值：合法缓存 > 实时计算。fromCache 指示来源。
func Get(dir string, src Source) (id string, fromCache bool, err error) {
	if b, err := os.ReadFile(CachePath(dir)); err == nil {
		if s := strings.TrimSpace(string(b)); Valid(s) {
			return s, true, nil
		}
	}
	id, err = Compute(src)
	return id, false, err
}

// Pin 固化本机标识（docs/06 §5）。仅用于本机，不得跨机器使用。
func Pin(dir, value string) error {
	if !Valid(value) {
		return ErrBadFormat
	}
	return fsutil.WriteFile(CachePath(dir), []byte(value+"\n"))
}
