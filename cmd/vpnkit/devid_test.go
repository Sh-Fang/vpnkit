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
	isolate(t)
	const v = "3F2A9C14B7E08D5612AB44CD990E7F31"
	if code, _, e := runCLI(t, "devid", "pin", v); code != 0 {
		t.Fatalf("pin: %d %s", code, e)
	}
	code, out, _ := runCLI(t, "devid", "show")
	if code != 0 || !strings.HasPrefix(out, v) || !strings.Contains(out, "已固化") {
		t.Fatalf("show: %d %q", code, out)
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
	if !regexp.MustCompile(`^[0-9A-F]{32}\t`).MatchString(out) {
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
