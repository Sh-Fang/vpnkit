// Package devid 计算并持久化设备特征码（docs/06）。
package devid

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

// hexDigits 是原客户端使用的十六进制字母表，大写（docs/06 §3.2）。
const hexDigits = "0123456789ABCDEF"

// noMACPlaceholder 是拿不到 MAC 时原客户端补进第二段的固定值（docs/06 §3.3）。
const noMACPlaceholder = "00-00-00-00-00-00"

var (
	// ErrNoFingerprintSource 表示磁盘序列号与物理网卡 MAC 都取不到。
	ErrNoFingerprintSource = errors.New("devid: 既没有磁盘序列号，也没有物理网卡 MAC")
	// ErrBadFormat 表示三段值的形状不符合网关要求。
	ErrBadFormat = errors.New("devid: 设备特征码必须是 <32 位大写十六进制>|<MAC>|<base64 主机名>")
	// ErrUnsupported 表示当前平台没有实现取数。
	ErrUnsupported = errors.New("devid: 当前平台不支持计算设备特征码")
)

var reHID = regexp.MustCompile(`^[0-9A-F]{32}$`)

// HardID 是 auth/hid 这一步要提交的三段值（docs/06 §3.1）。
//
// 三段来自客户端本机计算，网关只按字符串登记，不校验它是否真由本机算出。
type HardID struct {
	HID      string // 第一段：32 位大写十六进制，磁盘/网卡指纹的折叠结果
	MAC      string // 第二段：aa-bb-cc-dd-ee-ff，小写连字符
	HostName string // 第三段：标准 base64 编码的主机名
}

// String 按网关与官方 SDK 约定的 `hid|macAddress|hostName` 拼接（docs/06 §3.1）。
func (h HardID) String() string { return h.HID + "|" + h.MAC + "|" + h.HostName }

// Valid 判断三段值形状是否可用。
func (h HardID) Valid() bool { return reHID.MatchString(h.HID) }

// Parse 解析 `hid|macAddress|hostName`；形状不符时返回 ErrBadFormat。
func Parse(s string) (HardID, error) {
	parts := strings.Split(strings.TrimSpace(s), "|")
	if len(parts) == 1 {
		// 只给了第一段：形状合法，另两段留给调用方用本机值补齐。
		parts = append(parts, "", "")
	}
	if len(parts) != 3 {
		return HardID{}, ErrBadFormat
	}
	h := HardID{HID: parts[0], MAC: parts[1], HostName: parts[2]}
	if !h.Valid() {
		return HardID{}, ErrBadFormat
	}
	return h, nil
}

// MD5Hex 返回大写十六进制 MD5（32 字符）。
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Fold 把两份 32 字符特征码逐字符折叠成一份（docs/06 §3.2）。
//
// 取的是字符码点低四位的和对 16 取余，而不是十六进制位值——
// 这是原客户端的实际行为，ABCDEF 的“值”因此是 1..6，不要"修正"。
func Fold(a, b string) (string, error) {
	if len(a) != 32 || len(b) != 32 {
		return "", ErrBadFormat
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = hexDigits[(int(a[i])%16+int(b[i])%16)%16]
	}
	return string(out), nil
}

// HostNameField 返回第三段：标准 base64（带 = 补位）的主机名（docs/06 §3.3）。
func HostNameField(host string) string {
	return base64.StdEncoding.EncodeToString([]byte(host))
}

// Build 按原客户端次序合成三段值（docs/06 §3.2）。
//
// diskSerial 是 ATA 序列号原文；原客户端在送进 MD5 前会自己补一个换行，
// 这个换行是它行为的一部分，不能省。diskSerial 或 mac 至少有一个非空。
func Build(diskSerial, mac, host string) (HardID, error) {
	var acc string
	if diskSerial != "" {
		acc = MD5Hex(diskSerial + "\n")
	}
	if mac != "" {
		folded := MD5Hex(mac)
		if acc == "" {
			acc = folded
		} else {
			var err error
			if acc, err = Fold(acc, folded); err != nil {
				return HardID{}, err
			}
		}
	}
	if acc == "" {
		return HardID{}, ErrNoFingerprintSource
	}
	macField := mac
	if macField == "" {
		macField = noMACPlaceholder
	}
	return HardID{HID: acc, MAC: macField, HostName: HostNameField(host)}, nil
}
