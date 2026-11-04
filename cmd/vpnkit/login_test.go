package main

import (
	"bytes"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/devid"
	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/testserver"
)

// gateway 启动假网关认证端，返回 --server 值与 CA 文件路径。
func gateway(t *testing.T, as *testserver.AuthServer) (string, string) {
	t.Helper()
	srv := httptest.NewTLSServer(as.Handler())
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return srv.Listener.Addr().String(), ca
}

func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("VPNKIT_HOME", home)
	t.Setenv("VPNKIT_CONFIG", "")
	t.Setenv("VPNKIT_SERVER", "")
	t.Setenv("VPNKIT_USER", "")
	return home
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestLoginLogoutCLI(t *testing.T) {
	home := isolate(t)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "pw-Секрет-1"}})
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "pw-Секрет-1")

	code, out, errOut := runCLI(t, "--verbose", "login", "--server", addr, "--ca-file", ca, "--user", "alice")
	if code != 0 {
		t.Fatalf("login exit %d: %s %s", code, out, errOut)
	}
	host := strings.Split(addr, ":")[0]
	p := auth.SessionPath(home, host)
	if ok, err := fsutil.Private(p); err != nil || !ok {
		t.Fatalf("session file not private: %v", err)
	}
	s, _ := auth.LoadSession(home, host)
	if !as.ValidToken(s.TwfID) {
		t.Fatal("saved token not valid on gateway")
	}
	// 密码不得出现在输出、日志文件、会话文件中（docs/00 §5 P1）
	logs, _ := filepath.Glob(filepath.Join(home, "logs", "*.log"))
	if len(logs) != 1 {
		t.Fatalf("verbose should write a log file, got %v", logs)
	}
	for _, f := range append(logs, p) {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, []byte("pw-Секрет-1")) {
			t.Fatalf("password leaked into %s", f)
		}
		if f != p && bytes.Contains(b, []byte(s.TwfID)) {
			t.Fatalf("full token leaked into %s", f)
		}
	}
	if strings.Contains(out+errOut, "pw-Секрет-1") || strings.Contains(out+errOut, s.TwfID) {
		t.Fatal("secret leaked to stdout/stderr")
	}

	code, _, errOut = runCLI(t, "logout", "--server", addr)
	if code != 0 {
		t.Fatalf("logout exit %d: %s", code, errOut)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("session file not removed")
	}
}

func TestLoginWrongPasswordExit3(t *testing.T) {
	isolate(t)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "right"}})
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "wrong")
	code, _, errOut := runCLI(t, "login", "--server", addr, "--ca-file", ca, "--user", "alice")
	if code != 3 || !strings.Contains(errOut, "密码错误") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestLoginUntrustedCertFails(t *testing.T) {
	isolate(t)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "right"}})
	addr, _ := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "right")
	code, _, errOut := runCLI(t, "login", "--server", addr, "--user", "alice")
	if code == 0 || !strings.Contains(errOut, "certificate") {
		t.Fatalf("should reject unknown CA: %d %s", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	isolate(t)
	if code, _, _ := runCLI(t); code != 2 {
		t.Fatalf("no args exit %d", code)
	}
	if code, _, _ := runCLI(t, "bogus"); code != 2 {
		t.Fatalf("unknown cmd exit %d", code)
	}
	if code, _, _ := runCLI(t, "login", "--nope"); code != 2 {
		t.Fatalf("bad flag exit %d", code)
	}
	if code, _, _ := runCLI(t, "login"); code != 2 {
		t.Fatalf("missing server exit %d", code)
	}
	if code, out, _ := runCLI(t, "--version"); code != 0 || strings.Count(out, "\n") != 3 {
		t.Fatalf("version: %d %q", code, out)
	}
}

func TestHoistCommand(t *testing.T) {
	got := strings.Join(hoistCommand([]string{"--config", "x.toml", "--verbose", "up", "--dry-run"}), " ")
	if got != "up --config x.toml --verbose --dry-run" {
		t.Fatal(got)
	}
}

// TestLoginRegisterDevicePinsDevID 验证：开启设备提交并走完特征码这步后，特征码立刻被固化。
// 不固化的话，网卡列表一变（换 Wi-Fi、起 docker）算出来的值就变，网关又当成新设备重新要审批。
func TestLoginRegisterDevicePinsDevID(t *testing.T) {
	home := isolate(t)
	// 假网关要求 hid 这步，且认这一个特征码。
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{
		Users:          map[string]string{"alice": "pw-1"},
		NextAuth:       "4",
		NextService:    "auth/hid",
		HIDExpectDevID: currentHID(t),
	})
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "pw-1")

	if code, out, errOut := runCLI(t, "login", "--server", addr, "--ca-file", ca, "--user", "alice", "--register-device"); code != 0 {
		t.Fatalf("login exit %d: %s %s", code, out, errOut)
	}
	id, err := os.ReadFile(filepath.Join(home, "device-id"))
	if err != nil {
		t.Fatalf("特征码未固化: %v", err)
	}
	if got := strings.TrimSpace(string(id)); got != currentDeviceID(t) {
		t.Errorf("固化值 = %q，期望 %q", got, currentDeviceID(t))
	}
}

// currentHID 返回本机当前算出的第一段（网关只认这一段）。
func currentHID(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	id, _, err := devid.Load(home, devid.SystemSource{})
	if err != nil {
		t.Skipf("本机取不到特征码要素: %v", err)
	}
	return id.HID
}

// currentDeviceID 返回本机当前算出的完整三段值（测试机固定，故可直接当期望值用）。
func currentDeviceID(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	id, _, err := devid.Load(home, devid.SystemSource{})
	if err != nil {
		t.Skipf("本机取不到特征码要素: %v", err)
	}
	return id.String()
}
