package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// 文档原文（docs/03 §2.1、§2.2），逐字节比对；改模板必须让这里失败（AGENTS.md §2）。
const (
	docClientHello = `16 03 01 00 4d 01 00 00 49 03 01 46 83 74 24 01
43 16 29 1f 95 3e c9 63 b9 fc b6 16 00 aa 20 15
eb 75 07 59 40 8b 8d 0c e1 60 43 20 b1 65 f6 7f
5a 6d 2c 54 d2 71 69 97 72 58 65 c3 40 9a 8a 0f
cd 81 d8 2e db 7b 8f f7 1b c1 80 c6 00 02 00 39
01 00`
	docCCSFinished = `14 03 01 00 01 01 16 03 01 00 20 2b d1 df 0e e2
4c da 7a 36 0e de 24 81 b9 79 32 67 8f f2 88 8c
ef a3 7e 50 1c 09 6b 09 9c 5a 0d`
)

func docHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFrozenConstants(t *testing.T) {
	cases := []struct {
		name      string
		got, want int
	}{
		{"ClientHelloLen", ClientHelloLen, 82},
		{"ServerHelloLen", ServerHelloLen, 122},
		{"CCSFinishedLen", CCSFinishedLen, 43},
		{"ClientMsgLen", ClientMsgLen, 76},
		{"ServerMsgLen", ServerMsgLen, 40},
		{"FrameHeaderLen", FrameHeaderLen, 12},
		{"TokenLen", TokenLen, 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s=%d want %d", c.name, c.got, c.want)
		}
	}
	codes := map[string][2]int32{
		"SEND_IP": {CmdSendIP, 0}, "SERVER_RESET": {CmdServerReset, 3}, "RECOVERED": {CmdRecovered, 4},
		"IPISBUSY": {CmdBusyIPInUse, 5}, "MEMORYPOOL": {CmdBusyMemoryPool, 6}, "SYSTEMISBUSY": {CmdBusySystem, 7},
		"SHUTDOWN": {CmdShutdown, 8}, "CONFLICT": {CmdBusyConflict, 9}, "IPVALID": {CmdIPValid, 10},
		"GROUPIDVALID": {CmdGroupIDValid, 11}, "IPKICK": {CmdIPKick, 14}, "HEARTBEAT": {CmdHeartbeat, 15},
	}
	for n, c := range codes {
		if c[0] != c[1] {
			t.Errorf("%s=%d want %d", n, c[0], c[1])
		}
	}
	if ClientMagic != "JJYY" || ServerMagic != "AABB" {
		t.Error("magic changed")
	}
}

func TestTemplates(t *testing.T) {
	ch := BuildClientHello()
	if !bytes.Equal(ch, docHex(t, docClientHello)) {
		t.Fatal("ClientHello differs from docs/03 §2.1")
	}
	if len(ch) != 82 || !bytes.Equal(ch[:5], []byte{0x16, 0x03, 0x01, 0x00, 0x4d}) {
		t.Fatal("ClientHello header")
	}
	// 自洽：5 + 77 == 82 且 9 + 73 == 82
	if 5+int(binary.BigEndian.Uint16(ch[3:5])) != 82 || 9+(int(ch[6])<<16|int(ch[7])<<8|int(ch[8])) != 82 {
		t.Fatal("ClientHello self-consistency")
	}
	cf := BuildCCSFinished()
	if !bytes.Equal(cf, docHex(t, docCCSFinished)) {
		t.Fatal("CCS+Finished differs from docs/03 §2.2")
	}
	if len(cf) != 43 || !bytes.Equal(cf[:6], []byte{0x14, 0x03, 0x01, 0x00, 0x01, 0x01}) {
		t.Fatal("CCS header")
	}
	// 返回副本：修改不影响下一次
	ch[0], cf[0] = 0, 0
	if BuildClientHello()[0] != 0x16 || BuildCCSFinished()[0] != 0x14 {
		t.Fatal("templates must return copies")
	}
}

func TestBuildClientMsg(t *testing.T) {
	var tok [TokenLen]byte
	copy(tok[:], "0123456789abcdef")
	cases := []struct {
		connType, arg uint32
		trailer       uint32
	}{
		{0, 7, 0xFFFFFFFF}, // conn_type<2 合法（docs/03 §4.1 更正）
		{1, 7, 0xFFFFFFFF},
		{2, 7, 0},
		{4, 7, 0},
		{5, 0x0a080002, 0x0a080002},
		{6, 1, 1},
		{7, 2, 2},
		{8, 3, 3},
		{9, 7, 0},
	}
	for _, c := range cases {
		b, err := BuildClientMsg(c.connType, tok, c.arg)
		if err != nil {
			t.Fatalf("connType %d: %v", c.connType, err)
		}
		if len(b) != 76 {
			t.Fatalf("len %d", len(b))
		}
		if !bytes.Equal(b[:8], []byte{0x17, 0x03, 0x01, 0x00, 0x3c, 0, 0, 0}) {
			t.Errorf("prefix %x", b[:8])
		}
		if string(b[8:12]) != "JJYY" {
			t.Errorf("magic %q", b[8:12])
		}
		if binary.LittleEndian.Uint32(b[12:16]) != c.connType {
			t.Errorf("conn_type")
		}
		if !bytes.Equal(b[16:48], make([]byte, 32)) || !bytes.Equal(b[64:72], make([]byte, 8)) {
			t.Errorf("zero regions")
		}
		if !bytes.Equal(b[48:64], tok[:]) {
			t.Errorf("token")
		}
		if got := binary.BigEndian.Uint32(b[72:76]); got != c.trailer {
			t.Errorf("connType %d trailer %#x want %#x", c.connType, got, c.trailer)
		}
		ct, tk, tr, err := ParseClientMsg(b)
		if err != nil || ct != c.connType || tk != tok || tr != c.trailer {
			t.Errorf("roundtrip %v", err)
		}
	}
	var p [8]byte
	copy(p[:], []byte{0x17, 0x03, 0x01, 0x00, 0x47})
	b, _ := BuildClientMsgWithPrefix(p, 1, tok, 0)
	if b[4] != 0x47 {
		t.Error("prefix override")
	}
}

func TestParseServerMsg(t *testing.T) {
	m := BuildServerMsg(CmdIPKick, []byte{1, 2, 3})
	if len(m) != 40 {
		t.Fatal(len(m))
	}
	st, payload, err := ParseServerMsg(m)
	if err != nil || st != 14 || len(payload) != 32 || payload[0] != 1 {
		t.Fatalf("%d %v %v", st, payload, err)
	}
	payload[0] = 99
	if m[8] != 1 {
		t.Fatal("payload must be a copy")
	}
	bad := append([]byte("XXXX"), make([]byte, 36)...)
	if _, _, err := ParseServerMsg(bad); !errors.Is(err, ErrBadServerMsg) {
		t.Fatal(err)
	}
	if _, _, err := ParseServerMsg([]byte("AABB")); !errors.Is(err, ErrShortServerMsg) {
		t.Fatal(err)
	}
	neg := BuildServerMsg(-1, nil)
	if st, _, _ := ParseServerMsg(neg); st != -1 {
		t.Fatal("status is signed int32")
	}
}

func TestDataFrame(t *testing.T) {
	for _, n := range []int{0, 1, 20, 1400} {
		pkt := bytes.Repeat([]byte{0xab}, n)
		f := BuildDataFrame(7, pkt)
		if len(f) != 12+n {
			t.Fatalf("len %d", len(f))
		}
		if binary.LittleEndian.Uint32(f[4:8]) != uint32(len(f)) {
			t.Fatal("total length field")
		}
		if binary.LittleEndian.Uint32(f[0:4]) != 7 || binary.LittleEndian.Uint32(f[8:12]) != 0 {
			t.Fatal("opcode/reserved")
		}
		op, ip, err := ParseDataFrame(f)
		if err != nil || op != 7 || !bytes.Equal(ip, pkt) {
			t.Fatalf("roundtrip %v", err)
		}
	}
	f := BuildDataFrame(0, []byte{1, 2, 3})
	if _, _, err := ParseDataFrame(f[:14]); !errors.Is(err, ErrFrameLength) {
		t.Fatal("truncated frame should fail")
	}
	if _, _, err := ParseDataFrame(f[:5]); !errors.Is(err, ErrFrameLength) {
		t.Fatal("short frame should fail")
	}
}

func TestSendIP(t *testing.T) {
	good := SendIP{
		TapIP: netip.MustParseAddr("10.8.0.2"), LanIP: netip.MustParseAddr("10.8.0.1"),
		Enc: 0, Zip: 0, UDPPort: 4433,
	}
	msg := EncodeSendIP(good, SendIPLayoutV1)
	// 候选布局的字节位置（docs/04 §3.0）
	if !bytes.Equal(msg[8:12], []byte{10, 8, 0, 2}) || !bytes.Equal(msg[12:16], []byte{10, 8, 0, 1}) ||
		binary.LittleEndian.Uint32(msg[24:28]) != 4433 {
		t.Fatalf("layout %x", msg)
	}
	got, err := ParseSendIP(msg, SendIPLayoutV1)
	if err != nil || got != good {
		t.Fatalf("%+v %v", got, err)
	}
	bad := []SendIP{
		{TapIP: netip.MustParseAddr("0.0.0.0")},
		{TapIP: netip.MustParseAddr("255.255.255.255")},
		{TapIP: netip.MustParseAddr("224.0.0.1")},
		{TapIP: netip.MustParseAddr("10.8.0.2"), Enc: 2},
		{TapIP: netip.MustParseAddr("10.8.0.2"), Zip: 5},
		{TapIP: netip.MustParseAddr("10.8.0.2"), UDPPort: 70000},
	}
	for _, s := range bad {
		if _, err := ParseSendIP(EncodeSendIP(s, SendIPLayoutV1), SendIPLayoutV1); !errors.Is(err, ErrSendIPLayout) {
			t.Errorf("%+v should fail, got %v", s, err)
		}
	}
	if _, err := ParseSendIP(msg[:20], SendIPLayoutV1); !errors.Is(err, ErrSendIPLayout) {
		t.Error("short msg")
	}
}

func TestSummarizeIPv4(t *testing.T) {
	p := make([]byte, 28)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 28)
	p[9] = 1
	copy(p[12:], []byte{10, 8, 0, 2, 10, 0, 0, 1})
	s, ok := SummarizeIPv4(p)
	if !ok || s.Src.String() != "10.8.0.2" || s.Dst.String() != "10.0.0.1" || s.Proto != 1 || s.Len != 28 {
		t.Fatalf("%+v", s)
	}
	if _, ok := SummarizeIPv4([]byte{0x60, 0}); ok {
		t.Fatal("ipv6/short")
	}
	// 合法头部的校验和再算一遍应为 0
	binary.BigEndian.PutUint16(p[10:], IPv4Checksum(p[:20]))
	if IPv4Checksum(p[:20]) != 0 {
		t.Fatal("checksum")
	}
}
