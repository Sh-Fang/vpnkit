package tunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// serverHelloRecord 拼一条只含 ServerHello 的 TLS 握手记录，用于测试 session id 解析。
func serverHelloRecord(sid []byte) []byte {
	body := make([]byte, 0, 35+len(sid))
	body = append(body, 0x03, 0x01)                     // version
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, byte(len(sid)))                 // session_id_len
	body = append(body, sid...)
	body = append(body, 0x00, 0x2f, 0x01) // cipher + compression
	hs := append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{22, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestServerHelloSessionID(t *testing.T) {
	sid := bytes.Repeat([]byte{0xAB}, 32)
	got, err := ServerHelloSessionID(serverHelloRecord(sid))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sid) {
		t.Fatalf("got %x want %x", got, sid)
	}

	// 前面还有别的记录时要能跳过。
	other := []byte{20, 0x03, 0x01, 0x00, 0x01, 0x01} // CCS
	got, err = ServerHelloSessionID(append(other, serverHelloRecord(sid)...))
	if err != nil || !bytes.Equal(got, sid) {
		t.Fatalf("跳记录失败：%v %x", err, got)
	}

	// TLS 1.3 那种空回显：拿不到会话，必须显式报错而不是返回空切片。
	if _, err := ServerHelloSessionID(serverHelloRecord(nil)); !errors.Is(err, ErrNoSessionID) {
		t.Fatalf("got %v", err)
	}
	// 只有半条记录。
	if _, err := ServerHelloSessionID(serverHelloRecord(sid)[:20]); err == nil {
		t.Fatal("截断的记录应当报错")
	}
}

func TestDeriveAgentToken(t *testing.T) {
	sid := bytes.Repeat([]byte{0xCD}, 32)
	tok, err := DeriveAgentToken(sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != AgentTokenLen {
		t.Fatalf("长度 %d", len(tok))
	}
	want := hex.EncodeToString(sid)[:AgentTokenLen-1]
	if string(tok[:AgentTokenLen-1]) != want {
		t.Fatalf("got %q want %q", tok[:AgentTokenLen-1], want)
	}
	// 末位是 C 字符串结束符，不是第 32 个 hex 字符。
	if tok[AgentTokenLen-1] != 0 {
		t.Fatalf("末字节应为 0，实际 %02X", tok[AgentTokenLen-1])
	}
	if _, err := DeriveAgentToken(nil); !errors.Is(err, ErrNoSessionID) {
		t.Fatalf("空 session id 应报错，got %v", err)
	}
}

func TestBuildL3Layout(t *testing.T) {
	agent := [AgentTokenLen]byte{}
	for i := range agent {
		agent[i] = byte(0xA0 + i)
	}
	var tok [wire.TokenLen]byte
	copy(tok[:], "0123456789abcdef")
	ip := [4]byte{10, 8, 0, 7}

	b := BuildL3(L3OpRecv, agent, tok, ip)
	if len(b) != L3MsgLen {
		t.Fatalf("长度 %d", len(b))
	}
	if got := binary.LittleEndian.Uint32(b[0:4]); got != L3OpRecv {
		t.Errorf("opcode %d", got)
	}
	if !bytes.Equal(b[4:36], agent[:]) {
		t.Errorf("agentToken 段不对")
	}
	if string(b[36:52]) != "0123456789abcdef" {
		t.Errorf("令牌段 %q", b[36:52])
	}
	if !bytes.Equal(b[52:60], make([]byte, 8)) {
		t.Errorf("保留区应为零：%x", b[52:60])
	}
	if !bytes.Equal(b[60:64], ip[:]) {
		t.Errorf("IP 段 %x", b[60:64])
	}
}

// TestBuildL3WrappedMatchesBare 钉住 docs/03 §4.4 的结论：
// 76 字节消息 = 12 字节前缀 + 64 字节裸消息，字段逐一对齐。
func TestBuildL3WrappedMatchesBare(t *testing.T) {
	var agent [AgentTokenLen]byte
	for i := range agent {
		agent[i] = byte(i)
	}
	var tok [wire.TokenLen]byte
	copy(tok[:], "fedcba9876543210")
	ip := [4]byte{172, 16, 3, 9}

	w := BuildL3Wrapped(L3OpSend, agent, tok, ip)
	b := BuildL3(L3OpSend, agent, tok, ip)
	if len(w) != wire.ClientMsgLen {
		t.Fatalf("长度 %d", len(w))
	}
	p := wire.DefaultClientMsgPrefix()
	if !bytes.Equal(w[0:8], p[:]) {
		t.Errorf("前缀 %x", w[0:8])
	}
	if string(w[8:12]) != wire.ClientMagic {
		t.Errorf("魔数 %q", w[8:12])
	}
	if !bytes.Equal(w[12:], b) {
		t.Errorf("主体与裸消息不一致\n got %x\nwant %x", w[12:], b)
	}
}

func TestReverseIP(t *testing.T) {
	if got := ReverseIP([4]byte{10, 8, 0, 7}); got != [4]byte{7, 0, 8, 10} {
		t.Fatalf("got %v", got)
	}
}
