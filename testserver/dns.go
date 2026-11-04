package testserver

import (
	"encoding/binary"
	"net/netip"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// DNSAnswerIP 是假 DNS 对任意 A 查询的应答地址，落在联调用的 198.18.0.0/24 内，便于接着 ping。
var DNSAnswerIP = netip.MustParseAddr("198.18.0.10")

// DNSReply 对发往 53 端口的 UDP 查询构造应答：A 查询回 DNSAnswerIP，其他类型回空的 NOERROR。
// 只认单问题、无压缩指针的查询；不符合时返回 nil。name 为查询的域名，供调用方留痕。
func DNSReply(p []byte) (reply []byte, name string) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 17 {
		return nil, ""
	}
	ihl := int(p[0]&0x0f) * 4
	if len(p) < ihl+8+12 || binary.BigEndian.Uint16(p[ihl+2:]) != 53 {
		return nil, ""
	}
	q := p[ihl+8:]
	if binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil, ""
	}
	// 解析 QNAME，得到问题段结尾
	off := 12
	for {
		if off >= len(q) {
			return nil, ""
		}
		l := int(q[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 != 0 || off+1+l > len(q) {
			return nil, ""
		}
		if name != "" {
			name += "."
		}
		name += string(q[off+1 : off+1+l])
		off += 1 + l
	}
	if off+4 > len(q) {
		return nil, ""
	}
	qtype := binary.BigEndian.Uint16(q[off:])
	question := q[12 : off+4]

	msg := make([]byte, 12, 12+len(question)+16)
	copy(msg[0:2], q[0:2])
	binary.BigEndian.PutUint16(msg[2:], 0x8180)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, question...)
	if qtype == 1 {
		binary.BigEndian.PutUint16(msg[6:], 1)
		// 指向问题段 QNAME 的压缩指针、A、IN、TTL 60、4 字节地址
		msg = append(msg, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		msg = append(msg, DNSAnswerIP.AsSlice()...)
	}

	r := make([]byte, 28+len(msg))
	r[0] = 0x45
	binary.BigEndian.PutUint16(r[2:], uint16(len(r)))
	r[8] = 64
	r[9] = 17
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	binary.BigEndian.PutUint16(r[10:], wire.IPv4Checksum(r[:20]))
	copy(r[20:22], p[ihl+2:ihl+4])
	copy(r[22:24], p[ihl:ihl+2])
	binary.BigEndian.PutUint16(r[24:], uint16(8+len(msg)))
	copy(r[28:], msg)
	// UDP 校验和：伪首部 + UDP 段；结果为 0 时按 RFC 768 写 0xffff
	pseudo := make([]byte, 12+8+len(msg))
	copy(pseudo[0:8], r[12:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:], uint16(8+len(msg)))
	copy(pseudo[12:], r[20:])
	cs := wire.IPv4Checksum(pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(r[26:], cs)
	return r, name
}
