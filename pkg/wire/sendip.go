package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// FieldEnc 是 SEND_IP 字段的编码方式。
type FieldEnc int

const (
	EncIPv4BE FieldEnc = iota // IPv4，网络序
	EncU32LE                  // u32 小端
)

// LayoutField 描述 serverMsg 内一个字段的位置（偏移相对整条 40 字节消息）。
type LayoutField struct {
	Name string
	Off  int
	Len  int
	Enc  FieldEnc
}

// SendIPLayout 是表驱动的负载布局（docs/04 §3.0）。联调后只改表，不改代码。
type SendIPLayout struct {
	Name   string
	Fields []LayoutField
}

// SendIPLayoutV1 是 docs/04 §3.0 的候选布局。
var SendIPLayoutV1 = SendIPLayout{
	Name: "candidate-v1",
	Fields: []LayoutField{
		{"tapip", 8, 4, EncIPv4BE},
		{"lanip", 12, 4, EncIPv4BE},
		{"enc", 16, 4, EncU32LE},
		{"zip", 20, 4, EncU32LE},
		{"udpport", 24, 4, EncU32LE},
	},
}

// SendIP 是分配地址命令的参数（docs/04 §3）。
type SendIP struct {
	TapIP   netip.Addr
	LanIP   netip.Addr
	Enc     uint32
	Zip     uint32
	UDPPort uint32
}

var ErrSendIPLayout = errors.New("wire: SEND_IP 负载与布局不符")

// ParseSendIP 按布局解析完整的 40 字节 serverMsg 并做合理性检查。
func ParseSendIP(msg []byte, layout SendIPLayout) (SendIP, error) {
	var s SendIP
	if len(msg) < ServerMsgLen {
		return s, fmt.Errorf("%w: 长度 %d", ErrSendIPLayout, len(msg))
	}
	for _, f := range layout.Fields {
		if f.Off < 0 || f.Off+f.Len > len(msg) || f.Len != 4 {
			return s, fmt.Errorf("%w: 布局字段 %s 越界", ErrSendIPLayout, f.Name)
		}
		raw := msg[f.Off : f.Off+f.Len]
		switch f.Enc {
		case EncIPv4BE:
			a := netip.AddrFrom4([4]byte(raw))
			switch f.Name {
			case "tapip":
				s.TapIP = a
			case "lanip":
				s.LanIP = a
			}
		case EncU32LE:
			v := binary.LittleEndian.Uint32(raw)
			switch f.Name {
			case "enc":
				s.Enc = v
			case "zip":
				s.Zip = v
			case "udpport":
				s.UDPPort = v
			}
		}
	}
	return s, s.Check()
}

// Check 是 docs/04 §3.0 的合理性检查；失败通常意味着布局猜错了。
func (s SendIP) Check() error {
	t := s.TapIP
	switch {
	case !t.IsValid() || !t.Is4():
		return fmt.Errorf("%w: tapip 缺失", ErrSendIPLayout)
	case t.IsUnspecified():
		return fmt.Errorf("%w: tapip 为 0.0.0.0", ErrSendIPLayout)
	case t == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: tapip 为广播地址", ErrSendIPLayout)
	case t.IsMulticast():
		return fmt.Errorf("%w: tapip %s 为组播地址", ErrSendIPLayout, t)
	case t.IsLoopback():
		return fmt.Errorf("%w: tapip %s 为回环地址", ErrSendIPLayout, t)
	case s.Enc > 1:
		return fmt.Errorf("%w: enc=%d 不在 {0,1}", ErrSendIPLayout, s.Enc)
	case s.Zip > 1:
		return fmt.Errorf("%w: zip=%d 不在 {0,1}", ErrSendIPLayout, s.Zip)
	case s.UDPPort > 65535:
		return fmt.Errorf("%w: udpport=%d 超出 65535", ErrSendIPLayout, s.UDPPort)
	}
	return nil
}

// EncodeSendIP 按布局编码 40 字节 serverMsg（供假服务端与测试使用）。
func EncodeSendIP(s SendIP, layout SendIPLayout) []byte {
	b := BuildServerMsg(CmdSendIP, nil)
	for _, f := range layout.Fields {
		raw := b[f.Off : f.Off+f.Len]
		switch f.Name {
		case "tapip", "lanip":
			a := s.TapIP
			if f.Name == "lanip" {
				a = s.LanIP
			}
			if a.Is4() {
				copy(raw, a.AsSlice())
			}
		case "enc":
			binary.LittleEndian.PutUint32(raw, s.Enc)
		case "zip":
			binary.LittleEndian.PutUint32(raw, s.Zip)
		case "udpport":
			binary.LittleEndian.PutUint32(raw, s.UDPPort)
		}
	}
	return b
}
