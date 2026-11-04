package testserver

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	p := BuildUDP(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.53"), len(q))
	binary.BigEndian.PutUint16(p[20:], 50000)
	binary.BigEndian.PutUint16(p[22:], 53)
	copy(p[28:], q)
	return p
}

func TestDNSReplyA(t *testing.T) {
	r, name := DNSReply(dnsQuery("git.corp.example.com", 1))
	if r == nil || name != "git.corp.example.com" {
		t.Fatalf("reply %v name %q", r, name)
	}
	if wire.IPv4Checksum(r[:20]) != 0 {
		t.Fatal("bad ip checksum")
	}
	if binary.BigEndian.Uint16(r[20:]) != 53 || binary.BigEndian.Uint16(r[22:]) != 50000 {
		t.Fatal("ports not swapped")
	}
	msg := r[28:]
	if binary.BigEndian.Uint16(msg[0:]) != 0x1234 || binary.BigEndian.Uint16(msg[6:]) != 1 {
		t.Fatalf("header % x", msg[:12])
	}
	if got := netip.AddrFrom4([4]byte(msg[len(msg)-4:])); got != DNSAnswerIP {
		t.Fatalf("answer %v", got)
	}
}

func TestDNSReplyAAAAEmptyAndNonDNSIgnored(t *testing.T) {
	r, _ := DNSReply(dnsQuery("git.corp.example.com", 28))
	if r == nil || binary.BigEndian.Uint16(r[28+6:]) != 0 {
		t.Fatal("AAAA must get empty NOERROR")
	}
	if r, _ := DNSReply(BuildUDP(netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.8.0.53"), 20)); r != nil {
		t.Fatal("non-53 udp must be ignored")
	}
}
