package testserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"crypto/rc4"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// TunnelConfig 控制假隧道端。
type TunnelConfig struct {
	Auth           *AuthServer
	Script         string
	HeartbeatEvery time.Duration // 默认 10s
	// RC4Key 非空时，enc=1 的会话用它加解密数据面。
	RC4Key []byte
	Logf   func(format string, a ...any)
}

// TunnelServer 实现 docs/03 的握手与数据通道，并对 ICMP echo 请求作答，便于端到端验证。
type TunnelServer struct {
	cfg    TunnelConfig
	script Script

	mu       sync.Mutex
	attempts map[string]int
	sess     map[string]*tsession

	// 统计，供测试断言
	CtrlConns       atomic.Int64
	ClientHeartbeat atomic.Int64
	UpPackets       atomic.Int64
	DNSQueries      atomic.Int64
	lastCtrlType    atomic.Int64
	lastDataTrailer sync.Map // connType → trailer
}

type tsession struct {
	mu     sync.Mutex
	down   net.Conn
	downC  *rc4.Cipher
	enc    bool
	wakeup chan struct{}
}

func NewTunnelServer(cfg TunnelConfig) (*TunnelServer, error) {
	sc, ok := scripts[cfg.Script]
	if !ok {
		return nil, fmt.Errorf("未知剧本 %q，可选 %v", cfg.Script, ScriptNames())
	}
	if cfg.HeartbeatEvery == 0 {
		cfg.HeartbeatEvery = 10 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &TunnelServer{cfg: cfg, script: sc, attempts: map[string]int{}, sess: map[string]*tsession{}}, nil
}

// Serve 接受连接直到 l 关闭。
func (s *TunnelServer) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// LastCtrlConnType 返回最近一次控制通道的 conn_type。
func (s *TunnelServer) LastCtrlConnType() int64 { return s.lastCtrlType.Load() }

// DataTrailer 返回指定 conn_type 数据通道最近一次的尾部标志。
func (s *TunnelServer) DataTrailer(connType uint32) (uint32, bool) {
	v, ok := s.lastDataTrailer.Load(connType)
	if !ok {
		return 0, false
	}
	return v.(uint32), true
}

func (s *TunnelServer) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	hello := make([]byte, wire.ClientHelloLen)
	if _, err := io.ReadFull(c, hello); err != nil || !bytes.Equal(hello, wire.BuildClientHello()) {
		s.cfg.Logf("拒绝：ClientHello 不符")
		return
	}
	sh := make([]byte, wire.ServerHelloLen)
	copy(sh, []byte{0x16, 0x03, 0x01, 0x00, 0x75}) // 内容无意义，客户端读完即丢弃
	if _, err := c.Write(sh); err != nil {
		return
	}
	ccs := make([]byte, wire.CCSFinishedLen)
	if _, err := io.ReadFull(c, ccs); err != nil || !bytes.Equal(ccs, wire.BuildCCSFinished()) {
		s.cfg.Logf("拒绝：CCS+Finished 不符")
		return
	}
	cm := make([]byte, wire.ClientMsgLen)
	if _, err := io.ReadFull(c, cm); err != nil {
		return
	}
	connType, tok, trailer, err := wire.ParseClientMsg(cm)
	if err != nil || !bytes.Equal(cm[:8], []byte{0x17, 0x03, 0x01, 0x00, 0x3c, 0, 0, 0}) {
		s.cfg.Logf("拒绝：clientMsg 格式不符 %v", err)
		return
	}
	token := string(tok[:])
	if s.cfg.Auth != nil && !s.cfg.Auth.ValidToken(token) {
		s.cfg.Logf("拒绝：会话令牌无效")
		return
	}
	_ = c.SetDeadline(time.Time{})
	switch {
	case connType < 2:
		if trailer != 0xFFFFFFFF {
			s.cfg.Logf("拒绝：控制通道尾部标志 %#x", trailer)
			return
		}
		s.lastCtrlType.Store(int64(connType))
		s.control(c, token)
	case connType == 6 || connType == 7:
		s.lastDataTrailer.Store(connType, trailer)
		s.up(c, token)
	case connType == 5 || connType == 8:
		s.lastDataTrailer.Store(connType, trailer)
		s.down(c, token)
	default:
		s.cfg.Logf("拒绝：未知 conn_type %d", connType)
	}
}

func (s *TunnelServer) session(token string) *tsession {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.sess[token]
	if ts == nil {
		ts = &tsession{wakeup: make(chan struct{})}
		s.sess[token] = ts
	}
	return ts
}

func (s *TunnelServer) control(c net.Conn, token string) {
	s.CtrlConns.Add(1)
	s.mu.Lock()
	s.attempts[token]++
	n := s.attempts[token]
	s.mu.Unlock()
	s.cfg.Logf("控制通道 #%d 剧本 %s", n, s.cfg.Script)

	closed := make(chan struct{})
	go func() {
		// 吸收客户端心跳（76 字节 clientMsg 重发）
		buf := make([]byte, wire.ClientMsgLen)
		for {
			if _, err := io.ReadFull(c, buf); err != nil {
				close(closed)
				return
			}
			if string(buf[8:12]) == wire.ClientMagic {
				s.ClientHeartbeat.Add(1)
			}
		}
	}()
	send := func(b []byte) bool {
		_, err := c.Write(b)
		return err == nil
	}
	for _, st := range s.script(n) {
		switch {
		case st.SendIP != nil:
			ts := s.session(token)
			ts.mu.Lock()
			ts.enc = st.SendIP.Enc != 0
			ts.mu.Unlock()
			if !send(wire.EncodeSendIP(*st.SendIP, wire.SendIPLayoutV1)) {
				return
			}
		case st.Cmd != nil:
			if !send(wire.BuildServerMsg(*st.Cmd, nil)) {
				return
			}
		case st.Raw != nil:
			if !send(st.Raw) {
				return
			}
		case st.Sleep > 0:
			select {
			case <-time.After(st.Sleep):
			case <-closed:
				return
			}
		case st.Close:
			return
		case st.Hold:
			<-closed
			return
		case st.Heartbeat:
			t := time.NewTicker(s.cfg.HeartbeatEvery)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if !send(wire.BuildServerMsg(wire.CmdHeartbeat, nil)) {
						return
					}
				case <-closed:
					return
				}
			}
		}
	}
	<-closed
}

func (s *TunnelServer) newCipher() *rc4.Cipher {
	c, _ := rc4.NewCipher(s.cfg.RC4Key)
	return c
}

func (s *TunnelServer) down(c net.Conn, token string) {
	if _, err := c.Write(wire.BuildServerMsg(wire.AckDataDown, nil)); err != nil {
		return
	}
	ts := s.session(token)
	ts.mu.Lock()
	ts.down = c
	if ts.enc && len(s.cfg.RC4Key) > 0 {
		ts.downC = s.newCipher()
	}
	ts.mu.Unlock()
	if s.cfg.Script == "big-packets" {
		go s.pushBig(ts)
	}
	_, _ = io.Copy(io.Discard, c) // 保持到客户端关闭
	ts.mu.Lock()
	if ts.down == c {
		ts.down = nil
	}
	ts.mu.Unlock()
}

func (s *TunnelServer) sendDown(ts *tsession, ip []byte) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.down == nil {
		return errors.New("no down channel")
	}
	f := wire.BuildDataFrame(0, ip)
	if ts.downC != nil {
		ts.downC.XORKeyStream(f[wire.FrameHeaderLen:], f[wire.FrameHeaderLen:])
	}
	_, err := ts.down.Write(f)
	return err
}

func (s *TunnelServer) up(c net.Conn, token string) {
	if _, err := c.Write(wire.BuildServerMsg(wire.AckDataUp, nil)); err != nil {
		return
	}
	ts := s.session(token)
	ts.mu.Lock()
	var upC *rc4.Cipher
	if ts.enc && len(s.cfg.RC4Key) > 0 {
		upC = s.newCipher()
	}
	ts.mu.Unlock()
	hdr := make([]byte, wire.FrameHeaderLen)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		_, total, _ := wire.ParseFrameHeader(hdr)
		if total < wire.FrameHeaderLen || total > 65535 {
			s.cfg.Logf("上行帧长度非法 %d", total)
			return
		}
		body := make([]byte, total-wire.FrameHeaderLen)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		if upC != nil {
			upC.XORKeyStream(body, body)
		}
		s.UpPackets.Add(1)
		if reply := EchoReply(body); reply != nil {
			_ = s.sendDown(ts, reply)
		}
		if reply, name := DNSReply(body); reply != nil {
			s.DNSQueries.Add(1)
			s.cfg.Logf("DNS 查询 %s", name)
			_ = s.sendDown(ts, reply)
		}
	}
}

func (s *TunnelServer) pushBig(ts *tsession) {
	for i := 0; i < 50; i++ {
		pkt := BuildUDP(netip.MustParseAddr("10.0.0.1"), DefaultSendIP.TapIP, 1400-28)
		if s.sendDown(ts, pkt) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// EchoReply 对 ICMP echo 请求构造应答；其他包返回 nil。
func EchoReply(p []byte) []byte {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 1 {
		return nil
	}
	ihl := int(p[0]&0x0f) * 4
	if len(p) < ihl+8 || p[ihl] != 8 {
		return nil
	}
	r := append([]byte(nil), p...)
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	r[8] = 64
	r[10], r[11] = 0, 0
	binary.BigEndian.PutUint16(r[10:], wire.IPv4Checksum(r[:ihl]))
	r[ihl] = 0 // echo reply
	r[ihl+2], r[ihl+3] = 0, 0
	binary.BigEndian.PutUint16(r[ihl+2:], wire.IPv4Checksum(r[ihl:]))
	return r
}

// BuildEchoRequest 构造一个 ICMP echo 请求（测试用）。
func BuildEchoRequest(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[10:], wire.IPv4Checksum(p[:20]))
	p[20] = 8
	binary.BigEndian.PutUint16(p[24:], id)
	binary.BigEndian.PutUint16(p[26:], seq)
	copy(p[28:], payload)
	binary.BigEndian.PutUint16(p[22:], wire.IPv4Checksum(p[20:]))
	return p
}

// BuildUDP 构造一个指定负载长度的 UDP/IPv4 包（UDP 校验和置 0）。
func BuildUDP(src, dst netip.Addr, payloadLen int) []byte {
	p := make([]byte, 28+payloadLen)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[10:], wire.IPv4Checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:], 9999)
	binary.BigEndian.PutUint16(p[22:], 9999)
	binary.BigEndian.PutUint16(p[24:], uint16(8+payloadLen))
	return p
}
