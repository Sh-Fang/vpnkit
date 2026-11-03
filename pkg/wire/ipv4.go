package wire

import (
	"encoding/binary"
	"net/netip"
)

// IPv4Summary 是 trace 日志用的 IP 头摘要（docs/11 §8.1）：只取头部，不碰负载。
type IPv4Summary struct {
	Src, Dst netip.Addr
	Proto    uint8
	Len      int
}

// SummarizeIPv4 解析 IPv4 头；不是合法 IPv4 时 ok=false。
func SummarizeIPv4(p []byte) (s IPv4Summary, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return s, false
	}
	s.Src = netip.AddrFrom4([4]byte(p[12:16]))
	s.Dst = netip.AddrFrom4([4]byte(p[16:20]))
	s.Proto = p[9]
	s.Len = int(binary.BigEndian.Uint16(p[2:4]))
	return s, true
}

// IPv4Checksum 计算 RFC 1071 校验和。
func IPv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
