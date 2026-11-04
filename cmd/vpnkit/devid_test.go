package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sh-Fang/vpnkit/testserver"
)

func TestDevidCLI(t *testing.T) {
	home := isolate(t)
	const v = "3F2A9C14B7E08D5612AB44CD990E7F31"
	if code, _, e := runCLI(t, "devid", "pin", v); code != 0 {
		t.Fatalf("pin: %d %s", code, e)
	}
	code, out, _ := runCLI(t, "devid", "show")
	if code != 0 || !strings.Contains(out, "hid      = "+v) || !strings.Contains(out, "已固化") {
		t.Fatalf("show: %d %q", code, out)
	}
	// 只给第一段时，另两段用本机现值补齐并一起落盘。
	b, err := os.ReadFile(filepath.Join(home, "device-id"))
	if err != nil || len(strings.Split(strings.TrimSpace(string(b)), "|")) != 3 {
		t.Fatalf("固化文件 = %q, %v", b, err)
	}
	if code, _, _ := runCLI(t, "devid", "pin", "abc"); code != 2 {
		t.Fatalf("bad pin exit %d", code)
	}
	if code, _, _ := runCLI(t, "devid"); code != 2 {
		t.Fatalf("no sub exit %d", code)
	}
}

func TestDevidShowComputed(t *testing.T) {
	isolate(t)
	code, out, errOut := runCLI(t, "devid", "show")
	if code != 0 {
		t.Skipf("本机无指纹来源: %s", errOut)
	}
	if !regexp.MustCompile(`(?m)^hid      = [0-9A-F]{32}$`).MatchString(out) {
		t.Fatalf("%q", out)
	}
}

func TestLoginSendsPinnedDeviceID(t *testing.T) {
	home := isolate(t)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "pw"}})
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "pw")
	const v = "3F2A9C14B7E08D5612AB44CD990E7F31"
	runCLI(t, "devid", "pin", v)
	cfg := filepath.Join(home, "config.toml")
	os.WriteFile(cfg, []byte("[auth]\nsend_device_id = \"always\"\n"), 0o600)
	if code, _, e := runCLI(t, "login", "--config", cfg, "--server", addr, "--ca-file", ca, "--user", "alice"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if got := as.LastLoginForm().Get("devid"); got != v {
		t.Fatalf("devid field %q", got)
	}
	// auto + 未知 isHidUser → 不上报
	os.WriteFile(cfg, []byte("[auth]\nsend_device_id = \"auto\"\n"), 0o600)
	runCLI(t, "logout", "--server", addr)
	runCLI(t, "login", "--config", cfg, "--server", addr, "--ca-file", ca, "--user", "alice")
	if as.LastLoginForm().Has("devid") {
		t.Fatal("auto without isHidUser=1 must not send devid")
	}
}

// TestLoginHIDSendsThreeSegments 锁死线上字段映射（docs/06 §3.1、docs/02 §4.1）：
// 固化值里 `hid|macAddress|hostName` 三段必须原样落到三个表单字段上。
func TestLoginHIDSendsThreeSegments(t *testing.T) {
	const (
		hid  = "8D82BE5469AA53CA87DBB47D97826956"
		mac  = "54-ee-75-e0-3f-c5"
		host = "b2FzaXMtTGVub3Zv"
	)
	isolate(t)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{
		Users:          map[string]string{"alice": "pw-2"},
		NextAuth:       "4",
		NextService:    "auth/hid",
		HIDExpectDevID: hid,
	})
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "pw-2")

	if code, _, e := runCLI(t, "devid", "pin", hid+"|"+mac+"|"+host); code != 0 {
		t.Fatalf("pin: %d %s", code, e)
	}
	if code, out, errOut := runCLI(t, "login", "--server", addr, "--ca-file", ca, "--user", "alice", "--register-device"); code != 0 {
		t.Fatalf("login exit %d: %s %s", code, out, errOut)
	}
	form := as.LastHIDForm()
	for field, want := range map[string]string{"hid": hid, "macaddress": mac, "hostname": host} {
		if got := form.Get(field); got != want {
			t.Errorf("字段 %s = %q，期望 %q", field, got, want)
		}
	}
	if got := form.Get("ignore"); got != "0" {
		t.Errorf("ignore = %q", got)
	}
}
