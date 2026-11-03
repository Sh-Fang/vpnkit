// Package wire 是线格式的纯函数编解码（docs/03、docs/04）。
// 无副作用、不 import 任何 internal 包；所有构造函数返回新分配的切片，调用方可自由修改。
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// 线格式长度（docs/03 §3）。改这些常量必须让测试失败（AGENTS.md §2）。
const (
	ClientHelloLen = 82
	ServerHelloLen = 122
	CCSFinishedLen = 43
	ClientMsgLen   = 76
	ServerMsgLen   = 40
	FrameHeaderLen = 12
	TokenLen       = 16
)

// 魔数（docs/03 §4）。
const (
	ClientMagic = "JJYY"
	ServerMagic = "AABB"
)

// 命令码（docs/04 §1）。
const (
	CmdSendIP           int32 = 0
	CmdServerReset      int32 = 3
	CmdRecovered        int32 = 4
	CmdBusyIPInUse      int32 = 5
	CmdBusyMemoryPool   int32 = 6
	CmdBusySystem       int32 = 7
	CmdShutdown         int32 = 8
	CmdBusyConflict     int32 = 9
	CmdIPValid          int32 = 10
	CmdGroupIDValid     int32 = 11
	CmdIPKick           int32 = 14
	CmdHeartbeat        int32 = 15
	AckDataUp           int32 = 1 // 数据通道应答码：上行（docs/03 §4.3）
	AckDataDown         int32 = 2 // 数据通道应答码：下行
	DefaultCtrlConnType       = 1
)

// clientHello 是 docs/03 §2.1 的 82 字节模板。
var clientHello = [ClientHelloLen]byte{
	0x16, 0x03, 0x01, 0x00, 0x4d, 0x01, 0x00, 0x00, 0x49, 0x03, 0x01, 0x46, 0x83, 0x74, 0x24, 0x01,
	0x43, 0x16, 0x29, 0x1f, 0x95, 0x3e, 0xc9, 0x63, 0xb9, 0xfc, 0xb6, 0x16, 0x00, 0xaa, 0x20, 0x15,
	0xeb, 0x75, 0x07, 0x59, 0x40, 0x8b, 0x8d, 0x0c, 0xe1, 0x60, 0x43, 0x20, 0xb1, 0x65, 0xf6, 0x7f,
	0x5a, 0x6d, 0x2c, 0x54, 0xd2, 0x71, 0x69, 0x97, 0x72, 0x58, 0x65, 0xc3, 0x40, 0x9a, 0x8a, 0x0f,
	0xcd, 0x81, 0xd8, 0x2e, 0xdb, 0x7b, 0x8f, 0xf7, 0x1b, 0xc1, 0x80, 0xc6, 0x00, 0x02, 0x00, 0x39,
	0x01, 0x00,
}

// ccsFinished 是 docs/03 §2.2 的 43 字节模板。
var ccsFinished = [CCSFinishedLen]byte{
	0x14, 0x03, 0x01, 0x00, 0x01, 0x01, 0x16, 0x03, 0x01, 0x00, 0x20, 0x2b, 0xd1, 0xdf, 0x0e, 0xe2,
	0x4c, 0xda, 0x7a, 0x36, 0x0e, 0xde, 0x24, 0x81, 0xb9, 0x79, 0x32, 0x67, 0x8f, 0xf2, 0x88, 0x8c,
	0xef, 0xa3, 0x7e, 0x50, 0x1c, 0x09, 0x6b, 0x09, 0x9c, 0x5a, 0x0d,
}

// ClientMsgPrefix 是 clientMsg 前 8 字节模板（docs/03 §4.1）。
// 记录头声明长度 0x3c 与实际 76 字节不自洽，已知且照抄，不要"修正"。
var defaultClientMsgPrefix = [8]byte{0x17, 0x03, 0x01, 0x00, 0x3c, 0x00, 0x00, 0x00}

// BuildClientHello 返回 82 字节 ClientHello 的副本。
func BuildClientHello() []byte { b := clientHello; return b[:] }

// BuildCCSFinished 返回 43 字节 CCS+Finished 的副本。
func BuildCCSFinished() []byte { b := ccsFinished; return b[:] }

// DefaultClientMsgPrefix 返回 clientMsg 前缀模板的副本。
func DefaultClientMsgPrefix() [8]byte { return defaultClientMsgPrefix }

var (
	ErrBadServerMsg   = errors.New("wire: serverMsg 魔数不是 AABB")
	ErrShortServerMsg = errors.New("wire: serverMsg 过短")
	ErrFrameLength    = errors.New("wire: 数据帧长度字段非法")
)

// BuildClientMsg 用默认前缀构造 76 字节 clientMsg。connType<2 合法（控制通道）。
func BuildClientMsg(connType uint32, token [TokenLen]byte, arg uint32) ([]byte, error) {
	return BuildClientMsgWithPrefix(defaultClientMsgPrefix, connType, token, arg)
}

// BuildClientMsgWithPrefix 允许替换前缀模板（docs/03 §2.4）。
func BuildClientMsgWithPrefix(prefix [8]byte, connType uint32, token [TokenLen]byte, arg uint32) ([]byte, error) {
	b := make([]byte, ClientMsgLen)
	copy(b[0:8], prefix[:])
	copy(b[8:12], ClientMagic)
	binary.LittleEndian.PutUint32(b[12:16], connType)
	copy(b[48:64], token[:])
	binary.BigEndian.PutUint32(b[72:76], ClientMsgTrailer(connType, arg))
	return b, nil
}

// ClientMsgTrailer 计算偏移 72 的尾部标志（docs/03 §4.1）。
func ClientMsgTrailer(connType, arg uint32) uint32 {
	switch {
	case connType < 2:
		return 0xFFFFFFFF
	case connType >= 5 && connType <= 8:
		return arg
	default:
		return 0
	}
}

// ParseClientMsg 解析 clientMsg（供假服务端与测试使用）。
func ParseClientMsg(b []byte) (connType uint32, token [TokenLen]byte, trailer uint32, err error) {
	if len(b) != ClientMsgLen {
		return 0, token, 0, fmt.Errorf("wire: clientMsg 长度 %d != %d", len(b), ClientMsgLen)
	}
	if string(b[8:12]) != ClientMagic {
		return 0, token, 0, fmt.Errorf("wire: clientMsg 魔数不是 JJYY")
	}
	copy(token[:], b[48:64])
	return binary.LittleEndian.Uint32(b[12:16]), token, binary.BigEndian.Uint32(b[72:76]), nil
}

// ParseServerMsg 校验魔数并返回状态码与偏移 8 起的参数副本（docs/03 §4.2）。
// 只要求至少 8 字节：命令参数的未知部分一律忽略，便于向前兼容（docs/04 §2）。
func ParseServerMsg(b []byte) (status int32, payload []byte, err error) {
	if len(b) < 8 {
		return 0, nil, ErrShortServerMsg
	}
	if string(b[0:4]) != ServerMagic {
		return 0, nil, ErrBadServerMsg
	}
	return int32(binary.LittleEndian.Uint32(b[4:8])), append([]byte(nil), b[8:]...), nil
}

// BuildServerMsg 构造 40 字节 serverMsg（供假服务端与测试使用）。payload 超长部分截断。
func BuildServerMsg(status int32, payload []byte) []byte {
	b := make([]byte, ServerMsgLen)
	copy(b[0:4], ServerMagic)
	binary.LittleEndian.PutUint32(b[4:8], uint32(status))
	copy(b[8:], payload)
	return b
}

// BuildDataFrame 构造 12 字节头 + 裸 IPv4 的数据帧（docs/03 §5）。头部三个 u32 均为小端。
func BuildDataFrame(opcode uint32, ipPacket []byte) []byte {
	b := make([]byte, FrameHeaderLen+len(ipPacket))
	PutFrameHeader(b, opcode, uint32(len(b)))
	copy(b[FrameHeaderLen:], ipPacket)
	return b
}

// PutFrameHeader 就地写入帧头，供收发热路径复用缓冲区。
func PutFrameHeader(b []byte, opcode, total uint32) {
	binary.LittleEndian.PutUint32(b[0:4], opcode)
	binary.LittleEndian.PutUint32(b[4:8], total)
	binary.LittleEndian.PutUint32(b[8:12], 0)
}

// ParseFrameHeader 解析帧头。
func ParseFrameHeader(h []byte) (opcode, total, reserved uint32) {
	return binary.LittleEndian.Uint32(h[0:4]), binary.LittleEndian.Uint32(h[4:8]), binary.LittleEndian.Uint32(h[8:12])
}

// ParseDataFrame 解析一个完整数据帧；长度字段必须等于实际长度。
func ParseDataFrame(b []byte) (opcode uint32, ipPacket []byte, err error) {
	if len(b) < FrameHeaderLen {
		return 0, nil, ErrFrameLength
	}
	op, total, _ := ParseFrameHeader(b)
	if int(total) != len(b) {
		return 0, nil, fmt.Errorf("%w: 字段 %d 实际 %d", ErrFrameLength, total, len(b))
	}
	return op, append([]byte(nil), b[FrameHeaderLen:]...), nil
}
