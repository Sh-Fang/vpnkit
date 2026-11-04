package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/route"
	"github.com/Sh-Fang/vpnkit/testserver"
)

// fullGateway 启动认证端 + 隧道端，并完成 login，返回 --server 与 --ca-file。
func fullGateway(t *testing.T, script string) (*testserver.AuthServer, *testserver.TunnelServer, string, string) {
	t.Helper()
	tl, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { tl.Close() })
	_, ps, _ := net.SplitHostPort(tl.Addr().String())
	port, _ := strconv.Atoi(ps)
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{
		Users:   map[string]string{"alice": "pw"},
		ConfXML: testserver.ConfXML(port),
		RCList:  testserver.RCListXML("10.0.0.0/8;172.16.0.0/12", "corp.example.com"),
	})
	ts, _ := testserver.NewTunnelServer(testserver.TunnelConfig{Auth: as, Script: script, HeartbeatEvery: 100 * time.Millisecond})
	go ts.Serve(tl)
	addr, ca := gateway(t, as)
	t.Setenv("VPNKIT_PASSWORD", "pw")
	if code, _, e := runCLI(t, "login", "--server", addr, "--ca-file", ca, "--user", "alice"); code != 0 {
		t.Fatalf("login: %s", e)
	}
	return as, ts, addr, ca
}

func TestUpDryRunSendsNoTunnelTraffic(t *testing.T) {
	home := isolate(t)
	_, ts, addr, ca := fullGateway(t, "happy")
	code, out, errOut := runCLI(t, "up", "--dry-run", "--server", addr, "--ca-file", ca)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, w := range []string{"--dry-run", "10.0.0.0/8", "172.16.0.0/12", "<tapip>", "默认路由不变"} {
		if !strings.Contains(out, w) {
			t.Errorf("dry-run output missing %q\n%s", w, out)
		}
	}
	if strings.Contains(out, "0.0.0.0/0") || strings.Contains(out, " default") {
		t.Fatal("must not touch default route")
	}
	if ts.CtrlConns.Load() != 0 {
		t.Fatal("dry-run must not send tunnel traffic")
	}
	if st, _ := route.LoadState(home); st != nil {
		t.Fatal("dry-run must not write state.json")
	}
}

func TestUpFakeTunKickExit7(t *testing.T) {
	home := isolate(t)
	_, ts, addr, ca := fullGateway(t, "kick")
	cfg := filepath.Join(home, "config.toml")
	os.WriteFile(cfg, []byte("[tunnel]\nheartbeat_interval = \"100ms\"\nheartbeat_timeout = \"5s\"\n"), 0o600)
	code, _, errOut := runCLI(t, "--trace", "up", "--config", cfg, "--fake-tun", "--server", addr, "--ca-file", ca)
	if code != 7 || !strings.Contains(errOut, "账号已在其他位置登录") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if ts.CtrlConns.Load() != 1 {
		t.Fatal("must not reconnect after kick")
	}
	for _, w := range []string{"stage=1", "bytes=82", "bytes=122", "bytes=43", "bytes=76", "bytes=40", "to=running", "assumption=sendip_layout",
		"+ " + route.ShellQuote(route.RouteAddCmd(runtime.GOOS, netip.MustParsePrefix("10.0.0.0/8"), "memtun0"))} {
		if !strings.Contains(errOut, w) {
			t.Errorf("missing %q in output", w)
		}
	}
	// status 反映最后一次运行
	code, out, _ := runCLI(t, "status", "--json")
	var st map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil {
		t.Fatalf("status: %d %s", code, out)
	}
	sess := st["session"].(map[string]any)
	if st["running"] != false || sess["tap_ip"] != "10.8.0.2" || !strings.Contains(sess["stop_reason"].(string), "其他位置") {
		t.Fatalf("status %s", out)
	}
	if strings.Contains(out, "device_id") {
		t.Fatal("device id must be hidden by default")
	}
	// 完整令牌不得出现在日志文件与 status 中
	s, _ := auth.LoadSession(home, strings.Split(addr, ":")[0])
	logs, _ := filepath.Glob(filepath.Join(home, "logs", "*.log"))
	for _, f := range append(logs, statusPath(home)) {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), s.TwfID) {
			t.Fatalf("token leaked into %s", f)
		}
	}
}

func TestUpBadMagicExit4(t *testing.T) {
	isolate(t)
	_, _, addr, ca := fullGateway(t, "bad-magic")
	if code, _, e := runCLI(t, "up", "--fake-tun", "--server", addr, "--ca-file", ca); code != 4 {
		t.Fatalf("exit %d: %s", code, e)
	}
}

func TestUpExpiredTokenExit3(t *testing.T) {
	home := isolate(t)
	as, _, addr, ca := fullGateway(t, "happy")
	host := strings.Split(addr, ":")[0]
	s, _ := auth.LoadSession(home, host)
	as.Revoke(s.TwfID)
	code, _, errOut := runCLI(t, "up", "--fake-tun", "--server", addr, "--ca-file", ca)
	if code != 3 || !strings.Contains(errOut, "重新") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if _, err := os.Stat(auth.SessionPath(home, host)); !os.IsNotExist(err) {
		t.Fatal("expired session file must be deleted")
	}
}

func TestUpWithoutLoginExit3(t *testing.T) {
	isolate(t)
	if code, _, _ := runCLI(t, "up", "--server", "127.0.0.1:1"); code != 3 {
		t.Fatalf("exit %d", code)
	}
}

func TestUpNeedsPrivilege(t *testing.T) {
	if platform.Privileged() {
		t.Skip("running privileged")
	}
	isolate(t)
	_, _, addr, ca := fullGateway(t, "happy")
	if code, _, e := runCLI(t, "up", "--server", addr, "--ca-file", ca); code != 5 || !strings.Contains(e, "sudo") {
		t.Fatalf("exit %d: %s", code, e)
	}
}

func TestDownAndStatusIdle(t *testing.T) {
	isolate(t)
	if code, out, _ := runCLI(t, "down"); code != 0 || !strings.Contains(out, "没有运行中的") {
		t.Fatalf("%d %s", code, out)
	}
	if code, out, _ := runCLI(t, "status"); code != 0 || !strings.Contains(out, "idle") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestDoctorJSON(t *testing.T) {
	isolate(t)
	code, out, _ := runCLI(t, "doctor", "--json")
	var r struct {
		OK     bool `json:"ok"`
		Checks []struct{ Name, Level string }
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Checks) < 3 {
		t.Fatalf("%d %s %v", code, out, err)
	}
	if (code == 0) != r.OK {
		t.Fatalf("exit %d vs ok=%v", code, r.OK)
	}
}
