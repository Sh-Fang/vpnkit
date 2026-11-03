package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// Config 是建立隧道连接所需的参数。
type Config struct {
	Addr             string // host:port
	Token            string
	TokenEncoding    string // ascii | hex
	CtrlConnType     uint32
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	Templates        Templates
	Log              *slog.Logger
	// Dial 非空时替换默认拨号（测试用）。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (c *Config) defaults() {
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 10 * time.Second
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 15 * time.Second
	}
	if c.Templates.ClientHello == nil {
		c.Templates = DefaultTemplates()
	}
	c.Log = logx.Or(c.Log)
}

func (c *Config) dial(ctx context.Context) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if c.Dial != nil {
		conn, err = c.Dial(dctx, "tcp", c.Addr)
	} else {
		var d net.Dialer
		conn, err = d.DialContext(dctx, "tcp", c.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: 连接 %s: %w", vpnerr.ErrTunnel, c.Addr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}
	return conn, nil
}

// stage 名称与字节数对应 docs/03 §3 的 82/122/43/76/40。
type stage struct {
	n     int
	name  string
	bytes int
}

var stages = [...]stage{
	{1, "send ClientHello", wire.ClientHelloLen},
	{2, "recv ServerHello", wire.ServerHelloLen},
	{3, "send CCS+Finished", wire.CCSFinishedLen},
	{4, "send clientMsg", wire.ClientMsgLen},
	{5, "recv serverMsg", wire.ServerMsgLen},
}

// Handshake 在已建立的连接上执行 docs/03 §3 的第 2–6 步，返回 40 字节 serverMsg（已校验魔数）。
func Handshake(ctx context.Context, conn net.Conn, cfg Config, connType, arg uint32) ([]byte, error) {
	cfg.defaults()
	log := cfg.Log
	tok, err := EncodeToken(cfg.Token, cfg.TokenEncoding)
	if err != nil {
		return nil, err
	}
	cmsg, err := wire.BuildClientMsgWithPrefix(cfg.Templates.ClientMsgPrefix, connType, tok, arg)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	cur := stages[0]
	fail := func(err error) ([]byte, error) {
		return nil, classify(ctx, err, cur, connType)
	}
	write := func(s stage, b []byte) error {
		cur = s
		if _, err := conn.Write(b); err != nil {
			return err
		}
		log.Debug("握手", "stage", s.n, "step", s.name, "bytes", len(b), "conn_type", connType)
		return nil
	}
	read := func(s stage) ([]byte, error) {
		cur = s
		b := make([]byte, s.bytes)
		// 固定长度读取，绝不读到 EOF（docs/03 §3）
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		log.Debug("握手", "stage", s.n, "step", s.name, "bytes", len(b), "conn_type", connType)
		return b, nil
	}

	if err := write(stages[0], cfg.Templates.ClientHello); err != nil {
		return fail(err)
	}
	// 122 字节读完即丢弃，不做校验（docs/03 §3）
	if _, err := read(stages[1]); err != nil {
		return fail(err)
	}
	if err := write(stages[2], cfg.Templates.CCSFinished); err != nil {
		return fail(err)
	}
	log.Debug("clientMsg", "hex", logx.Hex(cmsg, logx.Span{Off: 48, Len: wire.TokenLen}))
	if err := write(stages[3], cmsg); err != nil {
		return fail(err)
	}
	smsg, err := read(stages[4])
	if err != nil {
		return fail(err)
	}
	log.Debug("serverMsg", "hex", hex.EncodeToString(smsg), "conn_type", connType)
	if _, _, err := wire.ParseServerMsg(smsg); err != nil {
		return nil, tunnelErr(err, "收到 %s", hex.EncodeToString(smsg))
	}
	_ = conn.SetDeadline(time.Time{})
	return smsg, nil
}

func classify(ctx context.Context, err error, s stage, connType uint32) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	where := fmt.Sprintf("第 %d 步 %s（conn_type=%d）", s.n, s.name, connType)
	var ne net.Error
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return tunnelErr(ErrHandshakeTimeout, "%s", where)
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed):
		hint := ""
		if s.n >= 4 {
			// docs/03 §2.3：76/40 步失败时提示可能需要真实 TLS 记录层
			hint = "；若模板已被接受（前三步成功），疑似服务端期待真实 TLS 记录层"
		}
		return tunnelErr(ErrHandshakeRejected, "%s: %v%s", where, err, hint)
	}
	return fmt.Errorf("%w: %s: %w", vpnerr.ErrTunnel, where, err)
}

// logAssumptions 记录握手相关的假设点（docs/11 §8.2）。
func logAssumptions(cfg Config) {
	logx.Assumption(cfg.Log, "handshake_template", cfg.Templates.Fingerprint())
	logx.Assumption(cfg.Log, "clientmsg_prefix", hex.EncodeToString(cfg.Templates.ClientMsgPrefix[:]))
	logx.Assumption(cfg.Log, "ctrl_conn_type", cfg.CtrlConnType)
	logx.Assumption(cfg.Log, "token_encoding", encodingName(cfg.TokenEncoding))
}

// Control 是控制通道（docs/03 §4.3 conn_type<2）。
type Control struct {
	conn net.Conn
	hb   []byte
	wmu  sync.Mutex
	log  *slog.Logger
}

// DialControl 建立控制通道，返回连接与握手第 5 步收到的首条命令。
func DialControl(ctx context.Context, cfg Config) (*Control, []byte, error) {
	cfg.defaults()
	logAssumptions(cfg)
	conn, err := cfg.dial(ctx)
	if err != nil {
		return nil, nil, err
	}
	first, err := Handshake(ctx, conn, cfg, cfg.CtrlConnType, 0)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	tok, _ := EncodeToken(cfg.Token, cfg.TokenEncoding)
	// 心跳内容：docs/04 §4 只说"与命令通道上其他报文一致"，取控制通道 clientMsg 原样重发。
	hb, _ := wire.BuildClientMsgWithPrefix(cfg.Templates.ClientMsgPrefix, cfg.CtrlConnType, tok, 0)
	logx.Assumption(cfg.Log, "heartbeat_format", "clientmsg-repeat")
	return &Control{conn: conn, hb: hb, log: cfg.Log}, first, nil
}

// ReadMsg 读取下一条 40 字节命令。
func (c *Control) ReadMsg() ([]byte, error) {
	b := make([]byte, wire.ServerMsgLen)
	if _, err := io.ReadFull(c.conn, b); err != nil {
		return nil, err
	}
	return b, nil
}

// SendHeartbeat 发送一次客户端心跳。
func (c *Control) SendHeartbeat(timeout time.Duration) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := c.conn.Write(c.hb)
	_ = c.conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *Control) Close() error { return c.conn.Close() }

// DialData 建立一条数据通道并校验应答码（docs/03 §4.3）。
func DialData(ctx context.Context, cfg Config, connType, arg uint32, wantAck int32) (net.Conn, error) {
	cfg.defaults()
	conn, err := cfg.dial(ctx)
	if err != nil {
		return nil, err
	}
	smsg, err := Handshake(ctx, conn, cfg, connType, arg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	ack, _, _ := wire.ParseServerMsg(smsg)
	if ack != wantAck {
		conn.Close()
		return nil, tunnelErr(ErrUnexpectedAck, "conn_type=%d 期望 %d 实际 %d（%s）", connType, wantAck, ack, hex.EncodeToString(smsg))
	}
	return conn, nil
}
