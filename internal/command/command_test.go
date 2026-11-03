package command

import (
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		code   int32
		action Action
		policy string
	}{
		{0, ActConfigure, ""},
		{3, ActReconnectNow, "reset"},
		{4, ActLog, ""},
		{5, ActBackoff, "busy"},
		{6, ActBackoff, "busy"},
		{7, ActBackoff, "busy"},
		{8, ActStop, ""},
		{9, ActBackoff, "conflict"},
		{10, ActLog, ""},
		{11, ActLog, ""},
		{14, ActStop, ""},
		{15, ActHeartbeat, ""},
		{1, ActUnknown, ""},
		{2, ActUnknown, ""},
		{12, ActUnknown, ""},
		{13, ActUnknown, ""},
		{99, ActUnknown, ""},
	}
	for _, c := range cases {
		d := Classify(c.code)
		if d.Action != c.action || d.Policy.Name != c.policy {
			t.Errorf("code %d: %v/%s want %v/%s", c.code, d.Action, d.Policy.Name, c.action, c.policy)
		}
	}
	if Name(14) != "IPKICK" || Name(99) != "UNKNOWN(99)" {
		t.Error("names")
	}
}

func TestPolicyDelay(t *testing.T) {
	mid := func() float64 { return 0.5 } // 抖动系数 1.0
	busy := []time.Duration{5, 10, 20, 40, 60, 60}
	for i, want := range busy {
		if got := PolicyBusy.Delay(i+1, mid); got != want*time.Second {
			t.Errorf("busy #%d: %v want %vs", i+1, got, want)
		}
	}
	conflict := []time.Duration{30, 60, 120, 240}
	for i, want := range conflict {
		if got := PolicyConflict.Delay(i+1, mid); got != want*time.Second {
			t.Errorf("conflict #%d: %v", i+1, got)
		}
	}
	network := []time.Duration{2, 4, 8, 16, 30, 30}
	for i, want := range network {
		if got := PolicyNetwork.Delay(i+1, mid); got != want*time.Second {
			t.Errorf("network #%d: %v", i+1, got)
		}
	}
	if PolicyReset.Delay(1, mid) != 0 {
		t.Error("reset is immediate")
	}
	// ±20% 抖动边界
	lo := PolicyBusy.Delay(1, func() float64 { return 0 })
	hi := PolicyBusy.Delay(1, func() float64 { return 0.9999 })
	if lo != 4*time.Second || hi < 5900*time.Millisecond || hi > 6*time.Second {
		t.Errorf("jitter %v %v", lo, hi)
	}
}

func TestExhausted(t *testing.T) {
	if PolicyBusy.Exhausted(6) || !PolicyBusy.Exhausted(7) {
		t.Error("busy max 6")
	}
	if PolicyConflict.Exhausted(4) || !PolicyConflict.Exhausted(5) {
		t.Error("conflict max 4")
	}
	if PolicyNetwork.Exhausted(1000) {
		t.Error("network unlimited")
	}
}

func TestKickReason(t *testing.T) {
	m := wire.BuildServerMsg(14, []byte{0, 0, 0, 0})
	if k := ParseKickReason(m); k.Kind != "normal" || k.Message() != "账号已在其他位置登录" {
		t.Error(k)
	}
	m = wire.BuildServerMsg(14, []byte{1, 0, 0, 0})
	if k := ParseKickReason(m); k.Kind != "session_switch" {
		t.Error(k)
	}
	m = wire.BuildServerMsg(14, []byte{7, 0, 0, 0})
	if k := ParseKickReason(m); k.Kind != "generic" || k.Code != 7 {
		t.Error(k)
	}
}
