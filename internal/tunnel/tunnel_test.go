package tunnel

import (
	"bytes"
	"context"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
	"github.com/Sh-Fang/vpnkit/testserver"
)

const testToken = "0123456789abcdef"

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func debugLogger() (*slog.Logger, *syncBuf) {
	b := &syncBuf{}
	l, _, _ := logx.Setup(logx.Options{Level: logx.LevelTrace, Stderr: b})
	return l, b
}

func startServer(t *testing.T, script string, mod func(*testserver.TunnelConfig)) (*testserver.TunnelServer, string) {
	t.Helper()
	as, err := testserver.NewAuthServer(testserver.AuthConfig{})
	if err != nil {
		t.Fatal(err)
	}
	as.AddSession(testToken, "alice")
	cfg := testserver.TunnelConfig{Auth: as, Script: script, HeartbeatEvery: 50 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	ts, err := testserver.NewTunnelServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go ts.Serve(l)
	return ts, l.Addr().String()
}

func baseCfg(addr string, log *slog.Logger) Config {
	return Config{Addr: addr, Token: testToken, CtrlConnType: 1, HandshakeTimeout: 2 * time.Second, Log: log}
}

func TestControlHandshakeHappy(t *testing.T) {
	ts, addr := startServer(t, "happy", nil)
	log, buf := debugLogger()
	ctl, first, err := DialControl(context.Background(), baseCfg(addr, log))
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	code, _, _ := wire.ParseServerMsg(first)
	if code != wire.CmdSendIP {
		t.Fatalf("first command %d", code)
	}
	sip, err := wire.ParseSendIP(first, wire.SendIPLayoutV1)
	if err != nil || sip.TapIP.String() != "10.8.0.2" {
		t.Fatalf("%+v %v", sip, err)
	}
	// docs/00 §5 P2：--verbose 能看到五段字节数 82/122/43/76/40
	out := buf.String()
	var got []string
	for _, m := range regexp.MustCompile(`stage=(\d) step="[^"]+" bytes=(\d+)`).FindAllStringSubmatch(out, -1) {
		got = append(got, m[2])
	}
	if strings.Join(got, "/") != "82/122/43/76/40" {
		t.Fatalf("stages %v\n%s", got, out)
	}
	for _, k := range []string{"handshake_template value=docs03-v1", "clientmsg_prefix value=170301003c000000", "ctrl_conn_type value=1", "token_encoding value=ascii", "heartbeat_format"} {
		if !strings.Contains(out, "assumption="+k) {
			t.Errorf("missing assumption %s", k)
		}
	}
	// 令牌在 hex dump 中被掩码
	if strings.Contains(out, "30313233343536373839616263646566") {
		t.Fatal("token bytes leaked in clientMsg hex")
	}
	if ts.LastCtrlConnType() != 1 {
		t.Fatal("conn_type")
	}
	// 控制通道后续命令
	for _, want := range []int32{wire.CmdIPValid, wire.CmdGroupIDValid, wire.CmdHeartbeat} {
		m, err := ctl.ReadMsg()
		if err != nil {
			t.Fatal(err)
		}
		if c, _, _ := wire.ParseServerMsg(m); c != want {
			t.Fatalf("got %d want %d", c, want)
		}
	}
	if err := ctl.SendHeartbeat(time.Second); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for ts.ClientHeartbeat.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ts.ClientHeartbeat.Load() == 0 {
		t.Fatal("server did not see heartbeat")
	}
}

func TestCtrlConnTypeZero(t *testing.T) {
	ts, addr := startServer(t, "happy", nil)
	cfg := baseCfg(addr, nil)
	cfg.CtrlConnType = 0
	ctl, _, err := DialControl(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctl.Close()
	if ts.LastCtrlConnType() != 0 {
		t.Fatal("conn_type 0 should be sent as-is")
	}
}

func TestBadMagic(t *testing.T) {
	_, addr := startServer(t, "bad-magic", nil)
	_, _, err := DialControl(context.Background(), baseCfg(addr, nil))
	if !errors.Is(err, ErrBadServerMsg) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
}

func TestHandshakeRejected(t *testing.T) {
	_, addr := startServer(t, "happy", nil)
	cfg := baseCfg(addr, nil)
	cfg.Token = "fedcba9876543210" // 网关不认识的令牌 → 读 serverMsg 时 EOF
	_, _, err := DialControl(context.Background(), cfg)
	if !errors.Is(err, ErrHandshakeRejected) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(err.Error(), "真实 TLS") {
		t.Fatalf("missing TLS hint: %v", err)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	cfg := baseCfg(l.Addr().String(), nil)
	cfg.HandshakeTimeout = 200 * time.Millisecond
	_, _, err := DialControl(context.Background(), cfg)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestHandshakeContextCancel(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, _, err := DialControl(ctx, baseCfg(l.Addr().String(), nil))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

func TestEncodeToken(t *testing.T) {
	if b, err := EncodeToken(testToken, "ascii"); err != nil || string(b[:]) != testToken {
		t.Fatal(err)
	}
	if b, err := EncodeToken("00112233445566778899aabbccddeeff", "hex"); err != nil || b[1] != 0x11 {
		t.Fatal(err)
	}
	for _, c := range []struct{ tok, enc string }{
		{"short", "ascii"},
		{testToken + "x", "ascii"},
		{testToken, "hex"}, // 16 hex 字符 → 8 字节
		{"zz", "hex"},
	} {
		if _, err := EncodeToken(c.tok, c.enc); !errors.Is(err, ErrTokenLength) || vpnerr.ExitCode(err) != 4 {
			t.Errorf("%q/%s: got %v", c.tok, c.enc, err)
		}
	}
}

func dialPair(t *testing.T, cfg Config) (*FrameWriter, *FrameReader, func()) {
	t.Helper()
	ctl, _, err := DialControl(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	arg := binary.BigEndian.Uint32(testserver.DefaultSendIP.TapIP.AsSlice())
	up, err := DialData(context.Background(), cfg, 6, arg, wire.AckDataUp)
	if err != nil {
		t.Fatal(err)
	}
	down, err := DialData(context.Background(), cfg, 5, arg, wire.AckDataDown)
	if err != nil {
		t.Fatal(err)
	}
	return NewFrameWriter(up, 0, nil, cfg.Log), NewFrameReader(down, nil, 1400, cfg.Log), func() {
		up.Close()
		down.Close()
		ctl.Close()
	}
}

func TestDataChannelsEcho(t *testing.T) {
	ts, addr := startServer(t, "happy", nil)
	log, buf := debugLogger()
	fw, fr, done := dialPair(t, baseCfg(addr, log))
	defer done()
	if tr, _ := ts.DataTrailer(6); tr != 0x0a080002 {
		t.Fatalf("up trailer %#x", tr)
	}
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.0.0.1")
	for seq := uint16(1); seq <= 3; seq++ {
		if err := fw.WritePacket(testserver.BuildEchoRequest(src, dst, 7, seq, []byte("ping"))); err != nil {
			t.Fatal(err)
		}
		pkt := make([]byte, 1500)
		n, err := fr.ReadPacket(pkt)
		if err != nil {
			t.Fatal(err)
		}
		s, ok := wire.SummarizeIPv4(pkt[:n])
		if !ok || s.Src != dst || s.Dst != src || pkt[20] != 0 || binary.BigEndian.Uint16(pkt[26:]) != seq {
			t.Fatalf("bad reply %+v", s)
		}
	}
	out := buf.String()
	for _, want := range []string{"assumption=data_opcode", "assumption=data_endian", "level=TRACE msg=ip dir=tx src=10.8.0.2 dst=10.0.0.1 proto=1", `msg="tx frame" hdr=00000000`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q", want)
		}
	}
	if strings.Contains(out, "70696e67") { // "ping" 负载
		t.Error("payload must not be logged")
	}
}

func TestRC4ContinuousState(t *testing.T) {
	key := []byte("vpnkit-test-key")
	pkt1, pkt2 := []byte("first packet payload"), []byte("second packet!")
	st, _ := rc4.NewCipher(key)
	a, b := append([]byte(nil), pkt1...), append([]byte(nil), pkt2...)
	st.XORKeyStream(a, a)
	st.XORKeyStream(b, b)
	st2, _ := rc4.NewCipher(key)
	combined := append(append([]byte(nil), pkt1...), pkt2...)
	st2.XORKeyStream(combined, combined)
	if !bytes.Equal(append(a, b...), combined) {
		t.Fatal("continuous state mismatch")
	}
	// 每包重置是错误实现，必须能被识别出来
	r1, _ := rc4.NewCipher(key)
	r2, _ := rc4.NewCipher(key)
	ra, rb := append([]byte(nil), pkt1...), append([]byte(nil), pkt2...)
	r1.XORKeyStream(ra, ra)
	r2.XORKeyStream(rb, rb)
	if bytes.Equal(append(ra, rb...), combined) {
		t.Fatal("per-packet reset should differ from continuous stream")
	}
}

func TestFrameWriterKeepsRC4State(t *testing.T) {
	key := []byte("k")
	c, _ := rc4.NewCipher(key)
	var out bytes.Buffer
	fw := NewFrameWriter(&out, 0, c, nil)
	p1, p2 := bytes.Repeat([]byte{1}, 30), bytes.Repeat([]byte{2}, 50)
	fw.WritePacket(p1)
	fw.WritePacket(p2)
	ref, _ := rc4.NewCipher(key)
	want := append(append([]byte(nil), p1...), p2...)
	ref.XORKeyStream(want, want)
	raw := out.Bytes()
	if !bytes.Equal(raw[:12], wire.BuildDataFrame(0, p1)[:12]) {
		t.Fatal("header must not be encrypted")
	}
	got := append(append([]byte(nil), raw[12:42]...), raw[54:]...)
	if !bytes.Equal(got, want) {
		t.Fatal("frame writer must keep RC4 state across packets")
	}
	// 读端用独立实例解回原文
	d, _ := rc4.NewCipher(key)
	fr := NewFrameReader(bytes.NewReader(raw), d, 1400, nil)
	buf := make([]byte, 1500)
	n, _ := fr.ReadPacket(buf)
	if !bytes.Equal(buf[:n], p1) {
		t.Fatal("decrypt p1")
	}
	n, _ = fr.ReadPacket(buf)
	if !bytes.Equal(buf[:n], p2) {
		t.Fatal("decrypt p2")
	}
}

func TestFrameReaderBadLength(t *testing.T) {
	bad := wire.BuildDataFrame(0, []byte{1, 2, 3})
	// 把长度字段写成大端，模拟字节序猜错
	binary.BigEndian.PutUint32(bad[4:8], uint32(len(bad)))
	fr := NewFrameReader(bytes.NewReader(bad), nil, 1400, nil)
	_, err := fr.ReadPacket(make([]byte, 1500))
	if !errors.Is(err, wire.ErrFrameLength) || !strings.Contains(err.Error(), "字节序") {
		t.Fatalf("got %v", err)
	}
}

func TestEncryptedEndToEnd(t *testing.T) {
	key := []byte("experimental-key")
	_, addr := startServer(t, "enc-required", func(c *testserver.TunnelConfig) { c.RC4Key = key })
	cfg := baseCfg(addr, nil)
	ctl, first, err := DialControl(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	sip, _ := wire.ParseSendIP(first, wire.SendIPLayoutV1)
	if sip.Enc != 1 {
		t.Fatal("enc")
	}
	if _, _, err := NewCiphers(sip.Enc, StaticKey(""), nil); !errors.Is(err, ErrEncryptionUnsupported) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
	upC, downC, err := NewCiphers(sip.Enc, StaticKey("6578706572696d656e74616c2d6b6579"), nil)
	if err != nil {
		t.Fatal(err)
	}
	up, _ := DialData(context.Background(), cfg, 6, 0, wire.AckDataUp)
	down, _ := DialData(context.Background(), cfg, 5, 0, wire.AckDataDown)
	defer up.Close()
	defer down.Close()
	fw, fr := NewFrameWriter(up, 0, upC, nil), NewFrameReader(down, downC, 1400, nil)
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.0.0.9")
	for i := uint16(0); i < 3; i++ {
		fw.WritePacket(testserver.BuildEchoRequest(src, dst, 1, i, []byte("enc")))
		buf := make([]byte, 1500)
		n, err := fr.ReadPacket(buf)
		if err != nil {
			t.Fatal(err)
		}
		if s, ok := wire.SummarizeIPv4(buf[:n]); !ok || s.Src != dst {
			t.Fatalf("decrypt failed %+v", s)
		}
	}
	if _, _, err := NewCiphers(0, StaticKey(""), nil); err != nil {
		t.Fatal("enc=0 needs no key")
	}
}
