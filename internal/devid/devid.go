// Package devid 计算并持久化设备特征码（docs/06）。
package devid

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
)

// Iface 是一张网卡，Physical 由平台判定（Linux 看 sysfs 的 device 链接）。
type Iface struct {
	Name     string
	MAC      string // 内核给出的形式，冒号分隔
	Loopback bool
	Physical bool
}

// Source 抽象特征码的三路来源，便于测试注入。
type Source interface {
	Interfaces() ([]Iface, error)
	DiskSerial() (string, bool, error)
	Hostname() (string, error)
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
		out = append(out, Iface{
			Name:     i.Name,
			MAC:      i.HardwareAddr.String(),
			Loopback: i.Flags&net.FlagLoopback != 0,
			Physical: physicalIface(i.Name),
		})
	}
	return out, nil
}

func (SystemSource) Hostname() (string, error) { return os.Hostname() }

func (SystemSource) DiskSerial() (string, bool, error) { return diskSerial() }

// MACField 把内核形式的 MAC 转成原客户端格式：小写、连字符分隔（docs/06 §3.3）。
func MACField(raw string) string {
	hexOnly := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(raw)))
	if len(hexOnly) != 12 || strings.Trim(hexOnly, "0") == "" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(hexOnly[i : i+2])
	}
	return b.String()
}

// SelectMAC 取按接口名排序后第一张有真实硬件的网卡（docs/06 §3.3）。
func SelectMAC(ifs []Iface) (string, bool) {
	sorted := append([]Iface(nil), ifs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, i := range sorted {
		if i.Loopback || !i.Physical {
			continue
		}
		if mac := MACField(i.MAC); mac != "" {
			return mac, true
		}
	}
	return "", false
}

// Parts 是一次取数的原始结果，保留失败原因便于诊断。
type Parts struct {
	DiskSerial string
	DiskOK     bool
	DiskErr    error
	MAC        string
	HostName   string
}

// Inspect 读取三路来源，不判定成败。
func Inspect(src Source) Parts {
	var p Parts
	if serial, ok, err := src.DiskSerial(); err != nil {
		p.DiskErr = err
	} else if ok {
		p.DiskSerial, p.DiskOK = serial, true
	}
	if ifs, err := src.Interfaces(); err == nil {
		p.MAC, _ = SelectMAC(ifs)
	}
	if host, err := src.Hostname(); err == nil {
		p.HostName = host
	}
	return p
}

// Build 把取数结果合成三段值。
func (p Parts) Build() (HardID, error) { return Build(p.DiskSerial, p.MAC, p.HostName) }

// Compute 实时计算三段值。
func Compute(src Source) (HardID, error) { return Inspect(src).Build() }

// CachePath 返回 device-id 文件路径。
func CachePath(dir string) string { return filepath.Join(dir, "device-id") }

// Load 按 docs/06 §5 的优先级取值：已固化 > 实时计算。
//
// 固化文件里若只有第一段（早期版本写下的），另两段用本机现值补齐。
func Load(dir string, src Source) (id HardID, fromCache bool, err error) {
	if b, rerr := os.ReadFile(CachePath(dir)); rerr == nil {
		if parsed, perr := Parse(string(b)); perr == nil {
			if parsed.MAC != "" && parsed.HostName != "" {
				return parsed, true, nil
			}
			local := Inspect(src)
			if parsed.MAC == "" {
				parsed.MAC = local.MAC
			}
			if parsed.HostName == "" {
				parsed.HostName = HostNameField(local.HostName)
			}
			if parsed.MAC == "" {
				parsed.MAC = noMACPlaceholder
			}
			return parsed, true, nil
		}
	}
	id, err = Compute(src)
	return id, false, err
}

// Pin 固化三段值（docs/06 §5）。仅用于本机，不得跨机器使用。
func Pin(dir string, h HardID) error {
	if !h.Valid() {
		return ErrBadFormat
	}
	return fsutil.WriteFile(CachePath(dir), []byte(h.String()+"\n"))
}
