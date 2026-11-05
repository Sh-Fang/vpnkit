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

// 已验证的 conn_type（docs/03 §4.4，本网关实测）。
//
// 关键结论：返回分配地址的不是"控制通道"，而是 conn_type 0；而且那条连接必须
// 一直开着，否则后面建流拿不到任何回执。凭据、令牌、地址三样都要出现在每条
// 连接的消息里。
const (
	CtSendIP         uint32 = 0 // 查询分配地址；arg 恒为 0xFFFFFFFF
	CtStreamDownA    uint32 = 5 // 应答码 2
	CtStreamUpA      uint32 = 6 // 应答码 1
	CtStreamUpB      uint32 = 7 // 应答码 1
	CtStreamDownB    uint32 = 8 // 应答码 2
	ArgSendIP               = 0xFFFFFFFF
	ServerMsgPayload        = 32
)

// ErrL3Reply 表示 L3 消息的回执不是预期形状。
var ErrL3Reply = errors.New("L3 消息回执形状不符")

// BuildL3Msg 构造 76 字节 clientMsg，并在 [16:48] 填入凭据前段（docs/03 §4.4）。
//
// 这个字段在旧记录里写作"保留 32 字节零"。它不是保留区：填零也能握手、
// 也能收到回执，但永远拿不到地址——因为网关根本不认为这是同一次会话。
func BuildL3Msg(connType uint32, agent [AgentTokenLen]byte, token [wire.TokenLen]byte, arg uint32) ([]byte, error) {
	b, err := wire.BuildClientMsg(connType, token, arg)
	if err != nil {
		return nil, err
	}
	copy(b[16:48], agent[:])
	return b, nil
}

// ServerMsg 是一条 40 字节回执（docs/03 §4.2）。
type ServerMsg struct {
	Status  int32
	Payload []byte
}

// ReadServerMsg 读取并解析一条 40 字节回执。
func ReadServerMsg(conn net.Conn, timeout time.Duration) (ServerMsg, error) {
	var m ServerMsg
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	b := make([]byte, wire.ServerMsgLen)
	// 定长读取，不能读到 EOF（docs/03 §3）。
	if _, err := io.ReadFull(conn, b); err != nil {
		return m, err
	}
	status, payload, err := wire.ParseServerMsg(b)
	if err != nil {
		return m, fmt.Errorf("%w: %w", ErrL3Reply, err)
	}
	return ServerMsg{Status: status, Payload: payload}, nil
}

// QueryIP 在 conn_type 0 的连接上查询分配地址（docs/03 §4.4）。
//
// 调用方必须保持这条连接打开直到隧道结束：网关把地址绑定在这条连接上，
// 连接一关，后续建流就静默失败（没有回执，也不会报错）。
func QueryIP(conn net.Conn, agent [AgentTokenLen]byte, token [wire.TokenLen]byte, timeout time.Duration) ([4]byte, ServerMsg, error) {
	var ip [4]byte
	msg, err := BuildL3Msg(CtSendIP, agent, token, ArgSendIP)
	if err != nil {
		return ip, ServerMsg{}, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return ip, ServerMsg{}, fmt.Errorf("发送地址查询: %w", err)
	}
	m, err := ReadServerMsg(conn, timeout)
	if err != nil {
		return ip, m, fmt.Errorf("读取地址查询回执: %w", err)
	}
	if m.Status != wire.CmdSendIP {
		return ip, m, fmt.Errorf("%w: 状态码 %d（期望 %d）", ErrL3Reply, m.Status, wire.CmdSendIP)
	}
	if len(m.Payload) < 4 {
		return ip, m, fmt.Errorf("%w: 载荷只有 %d 字节", ErrL3Reply, len(m.Payload))
	}
	copy(ip[:], m.Payload[0:4])
	return ip, m, nil
}

// OpenStream 打开一条数据流并校验应答码（docs/03 §4.4）。
//
// arg 必须是**倒序**的分配地址：按网络序 u32 填会得到完全相反的字节序，
// 网关不回执，也不报错——只是什么都不给。
func OpenStream(conn net.Conn, connType uint32, agent [AgentTokenLen]byte, token [wire.TokenLen]byte, ip [4]byte, want int32, timeout time.Duration) (ServerMsg, error) {
	msg, err := BuildL3Msg(connType, agent, token, binary.LittleEndian.Uint32(ip[:]))
	if err != nil {
		return ServerMsg{}, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(msg); err != nil {
		return ServerMsg{}, fmt.Errorf("发送建流（conn_type=%d）: %w", connType, err)
	}
	m, err := ReadServerMsg(conn, timeout)
	if err != nil {
		return m, fmt.Errorf("读取建流回执（conn_type=%d）: %w", connType, err)
	}
	if m.Status != want {
		return m, fmt.Errorf("%w: conn_type=%d 应答 %d（期望 %d）", ErrL3Reply, connType, m.Status, want)
	}
	return m, nil
}

// L3Conn 打开一条隧道连接并完成 docs/03 §3 的前三步（82 / 122 / 43）。
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
