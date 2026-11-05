package tunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

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

func newTestCreds() (agent [AgentTokenLen]byte, tok [wire.TokenLen]byte) {
	for i := range agent {
		agent[i] = byte(0xA0 + i)
	}
	copy(tok[:], testToken)
	return agent, tok
}

// TestBuildL3MsgLayout 钉住实测确认的字段位置（docs/03 §4.4）。
func TestBuildL3MsgLayout(t *testing.T) {
	agent, tok := newTestCreds()
	b, err := BuildL3Msg(CtStreamDownA, agent, tok, 0xC0A80A07)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != wire.ClientMsgLen {
		t.Fatalf("长度 %d", len(b))
	}
	p := wire.DefaultClientMsgPrefix()
	if !bytes.Equal(b[0:8], p[:]) {
		t.Errorf("前缀 %x", b[0:8])
	}
	if string(b[8:12]) != wire.ClientMagic {
		t.Errorf("魔数 %q", b[8:12])
	}
	if got := binary.LittleEndian.Uint32(b[12:16]); got != CtStreamDownA {
		t.Errorf("conn_type %d", got)
	}
	// 这一段是最容易填错的地方：旧记录当成"保留 32 字节零"。
	if !bytes.Equal(b[16:48], agent[:]) {
		t.Errorf("凭据前段没填进 [16:48]")
	}
	if !bytes.Equal(b[48:64], tok[:]) {
		t.Errorf("令牌段 %x", b[48:64])
	}
	if !bytes.Equal(b[64:72], make([]byte, 8)) {
		t.Errorf("保留区应为零：%x", b[64:72])
	}
	if got := binary.BigEndian.Uint32(b[72:76]); got != 0xC0A80A07 {
		t.Errorf("尾部 %08X", got)
	}
}

// TestQueryIP 用内存连接模拟网关回执：AABB + 状态 0 + 载荷里是地址。
func TestQueryIP(t *testing.T) {
	agent, tok := newTestCreds()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// 收下 76 字节查询消息，回一条 40 字节回执。
		req := make([]byte, wire.ClientMsgLen)
		if _, err := readFullForTest(server, req); err != nil {
			return
		}
		if got := binary.LittleEndian.Uint32(req[12:16]); got != CtSendIP {
			t.Errorf("conn_type %d，期望 %d", got, CtSendIP)
		}
		if got := binary.BigEndian.Uint32(req[72:76]); got != ArgSendIP {
			t.Errorf("arg 应为 0xFFFFFFFF，实际 %08X", got)
		}
		reply := make([]byte, wire.ServerMsgLen)
		copy(reply[0:4], wire.ServerMagic)
		binary.LittleEndian.PutUint32(reply[4:8], uint32(wire.CmdSendIP))
		reply[8], reply[9], reply[10], reply[11] = 172, 16, 14, 203
		server.Write(reply)
	}()

	ip, msg, err := QueryIP(client, agent, tok, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != [4]byte{172, 16, 14, 203} {
		t.Fatalf("地址 %v", ip)
	}
	if msg.Status != wire.CmdSendIP {
		t.Fatalf("状态 %d", msg.Status)
	}
}

// TestOpenStreamArgIsReversedIP 钉住"倒序四字节"这个坑：
// 按网络序 u32 填，网关不回执也不报错。
func TestOpenStreamArgIsReversedIP(t *testing.T) {
	agent, tok := newTestCreds()
	ip := [4]byte{172, 16, 14, 203}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		req := make([]byte, wire.ClientMsgLen)
		if _, err := readFullForTest(server, req); err != nil {
			return
		}
		if !bytes.Equal(req[72:76], []byte{203, 14, 16, 172}) {
			t.Errorf("尾部应为倒序地址，实际 %x", req[72:76])
		}
		reply := make([]byte, wire.ServerMsgLen)
		copy(reply[0:4], wire.ServerMagic)
		binary.LittleEndian.PutUint32(reply[4:8], 2)
		server.Write(reply)
	}()

	if _, err := OpenStream(client, CtStreamDownA, agent, tok, ip, 2, 3*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestReadServerMsgRejectsBadMagic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		server.Write(bytes.Repeat([]byte{0}, wire.ServerMsgLen))
	}()
	if _, err := ReadServerMsg(client, 3*time.Second); !errors.Is(err, ErrL3Reply) {
		t.Fatalf("got %v", err)
	}
}

func readFullForTest(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
