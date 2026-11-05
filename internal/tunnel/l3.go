package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// L3 流协议的常量（docs/03 §4.4）。
//
// 这套消息是 docs/03 §4.1 那个 76 字节 clientMsg 去掉 12 字节前缀后的裸体：
// 两者字段一一对齐，只有"32 字节保留区"在裸体里是 agentToken。
const (
	L3MsgLen   = 64 // 裸消息
	L3OpcodeIP = 0  // 查询分配到的 IP
	L3OpSend   = 5  // 上行（写）流
	L3OpRecv   = 6  // 下行（读）流
)

// ErrL3Reply 表示 L3 消息的回执不是预期形状。
var ErrL3Reply = errors.New("L3 消息回执形状不符")

// BuildL3 构造 64 字节裸 L3 消息（docs/03 §4.4）。
func BuildL3(op uint32, agent [AgentTokenLen]byte, token [wire.TokenLen]byte, ip [4]byte) []byte {
	b := make([]byte, L3MsgLen)
	binary.LittleEndian.PutUint32(b[0:4], op)
	copy(b[4:36], agent[:])
	copy(b[36:52], token[:])
	// [52:60] 保留零
	copy(b[60:64], ip[:])
	return b
}

// BuildL3Wrapped 构造 76 字节消息：12 字节前缀 + 上面的 64 字节体（docs/03 §4.4）。
//
// 前缀刻意沿用 docs/03 §4.1 的模板，包括那个长度字段与实际长度不自洽的
// `17 03 01 00 3c`——它是抓下来的常量，不是可以"算对"的东西。
func BuildL3Wrapped(op uint32, agent [AgentTokenLen]byte, token [wire.TokenLen]byte, ip [4]byte) []byte {
	p := wire.DefaultClientMsgPrefix()
	body := BuildL3(op, agent, token, ip)
	b := make([]byte, 0, wire.ClientMsgLen)
	b = append(b, p[:]...)
	b = append(b, wire.ClientMagic...)
	b = append(b, body...)
	return b
}

// QueryIP 在已建好的隧道连接上执行一次 L3 IP 查询，返回网关分配的地址与原始回执。
//
// 回执形状：首字节状态码 0，`[4:8]` 是分配到的 IP（网络序四字节）。
func QueryIP(conn net.Conn, msg []byte, timeout time.Duration) ([4]byte, []byte, error) {
	var ip [4]byte
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return ip, nil, fmt.Errorf("发送 L3 查询: %w", err)
	}
	// 不读到 EOF：回执是定长 128 字节，多读会挂住。
	buf := make([]byte, 128)
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return ip, buf[:n], fmt.Errorf("读取 L3 查询回执: %w", err)
	}
	reply := buf[:n]
	if reply[0] != 0 {
		return ip, reply, fmt.Errorf("%w: 状态码 %d", ErrL3Reply, reply[0])
	}
	copy(ip[:], reply[4:8])
	return ip, reply, nil
}

// L3StreamOpen 在已建好的隧道连接上打开一条流（上行 5 / 下行 6），
// 校验回执首字节与期望的应答码一致（docs/03 §4.4）。
//
// 这里的应答码和控制通道上 serverMsg 的状态码是两套编号：控制通道用 "AABB"+int32，
// L3 流只用一个字节。
func L3StreamOpen(conn net.Conn, msg []byte, want byte, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("发送 L3 建流: %w", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("读取 L3 建流回执: %w", err)
	}
	reply := buf[:n]
	if reply[0] != want {
		return reply, fmt.Errorf("%w: 期望 0x%02x，收到 0x%02x", ErrL3Reply, want, reply[0])
	}
	return reply, nil
}

// ReverseIP 把四字节地址倒序——L3 消息里的 IP 字段是倒着写的（docs/03 §4.4）。
//
// 这一处最容易错：按"网络序 u32"去填会得到完全相反的字节序，
// 网关要么拒绝，要么把你当成另一个地址。
func ReverseIP(ip [4]byte) [4]byte { return [4]byte{ip[3], ip[2], ip[1], ip[0]} }

// L3Conn 打开一条隧道连接并完成 docs/03 §3 的前三步（82 / 122 / 43），
// 之后由调用方决定发哪种消息。cfg 只用到地址、模板与超时。
func L3Conn(ctx context.Context, cfg Config) (net.Conn, error) {
	cfg.defaults()
	conn, err := cfg.dial(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if _, err := conn.Write(cfg.Templates.ClientHello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 ClientHello: %w", err)
	}
	// 122 字节读完即丢弃，与 docs/03 §3 一致：这一层不做任何校验。
	hello := make([]byte, wire.ServerHelloLen)
	if _, err := io.ReadFull(conn, hello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取服务端握手响应: %w", err)
	}
	if _, err := conn.Write(cfg.Templates.CCSFinished); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 CCS+Finished: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
