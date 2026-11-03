package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/auth"
	"github.com/Sh-Fang/vpnkit/internal/command"
	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/platform"
	"github.com/Sh-Fang/vpnkit/internal/tunnel"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
	"github.com/Sh-Fang/vpnkit/testserver"
)

const token = "0123456789abcdef"

type fakeAuth struct {
	port int
	res  auth.Resources
	err  error
}

func (f *fakeAuth) FetchConf(context.Context, string) (auth.Conf, []string, error) {
	if f.err != nil {
		return auth.Conf{}, nil, f.err
	}
	return auth.Conf{Port: f.port, MTU: 1400, TunDNS: []string{"10.8.0.53"}, IsHidUserSet: true}, nil, nil
}

func (f *fakeAuth) FetchResources(context.Context, string) (auth.Resources, error) {
	return f.res, nil
}

type fakeNet struct {
	mu        sync.Mutex
	applies   []NetPlan
	teardowns int
	failApply bool
}

func (f *fakeNet) Apply(_ context.Context, p NetPlan) (NetResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failApply {
		return NetResult{}, errors.New("route add failed")
	}
	f.applies = append(f.applies, p)
	return NetResult{RoutesOK: p.Routes, DNSEnabled: len(p.DNSSuffixes) > 0}, nil
}

func (f *fakeNet) Teardown(context.Context) error {
	f.mu.Lock()
	f.teardowns++
	f.mu.Unlock()
	return nil
}

func (f *fakeNet) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applies), f.teardowns
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type harness struct {
	ts   *testserver.TunnelServer
	sess *Session
	dev  *platform.MemDevice
	net  *fakeNet
	logs *syncBuf
	opts Options
}

// fast 把 docs/04 §5 的退避缩短 1000 倍，保留次数上限。
// patient 放宽心跳超时，避免剧本里的停顿被看门狗当成掉线。
func patient(o *Options) { o.Tunnel.HeartbeatTimeout = 3 * time.Second }

func fast(p command.Policy) command.Policy {
	p.Base /= 1000
	p.Max /= 1000
	return p
}

func newHarness(t *testing.T, script string, mod func(*Options)) *harness {
	t.Helper()
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{})
	as.AddSession(token, "alice")
	ts, err := testserver.NewTunnelServer(testserver.TunnelConfig{Auth: as, Script: script, HeartbeatEvery: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
	go ts.Serve(l)
	_, ps, _ := net.SplitHostPort(l.Addr().String())
	port, _ := strconv.Atoi(ps)

	h := &harness{ts: ts, net: &fakeNet{}, logs: &syncBuf{}}
	log, _, _ := logx.Setup(logx.Options{Level: slog.LevelDebug, Stderr: h.logs})
	h.dev = platform.NewMemDevice("memtun0", 1400)
	h.opts = Options{
		Server: "127.0.0.1",
		Port:   443,
		Token:  token,
		Auth: &fakeAuth{port: port, res: auth.Resources{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			Suffixes: []string{"corp.example.com"},
		}},
		Tunnel: TunnelParams{
			MTU: 1400, HeartbeatInterval: 50 * time.Millisecond, HeartbeatTimeout: 400 * time.Millisecond,
			HandshakeTimeout: 2 * time.Second, ConnectTimeout: time.Second, ValidWait: 200 * time.Millisecond,
			CtrlConnType: 1, TokenEncoding: "ascii", DataConnUp: 6, DataConnDown: 5, Templates: tunnel.DefaultTemplates(),
		},
		OpenDevice: func(int) (platform.Device, error) { return h.dev, nil },
		Network:    h.net,
		Log:        log,
		PolicyFor:  fast,
	}
	if mod != nil {
		mod(&h.opts)
	}
	h.sess = New(h.opts)
	return h
}

func (h *harness) run(t *testing.T, timeout time.Duration) (error, context.CancelFunc, chan error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	done := make(chan error, 1)
	go func() { done <- h.sess.Run(ctx) }()
	return nil, cancel, done
}

func (h *harness) waitState(t *testing.T, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.sess.Status().State == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state %s, want %s\n%s", h.sess.Status().State, want, h.logs.String())
}

func runToEnd(t *testing.T, h *harness, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return h.sess.Run(ctx)
}

func TestHappyPingAndDown(t *testing.T) {
	h := newHarness(t, "happy", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	start := time.Now()
	h.waitState(t, Running, 10*time.Second)
	if time.Since(start) > 10*time.Second {
		t.Fatal("docs/00 P2：10 秒内进入 RUNNING")
	}
	st := h.sess.Status()
	if st.TapIP != "10.8.0.2" || st.Device != "memtun0" || len(st.Routes) != 1 || !st.DNSEnabled {
		t.Fatalf("status %+v", st)
	}
	plan := h.net.applies[0]
	if plan.TapIP.String() != "10.8.0.2" || plan.Bypass[0].String() != "127.0.0.1" || plan.DNSServers[0].String() != "10.8.0.53" {
		t.Fatalf("plan %+v", plan)
	}
	src, dst := netip.MustParseAddr("10.8.0.2"), netip.MustParseAddr("10.1.2.3")
	for i := uint16(0); i < 5; i++ {
		h.dev.Inject(testserver.BuildEchoRequest(src, dst, 1, i, []byte("hello")))
		select {
		case p := <-h.dev.Outbound:
			if s, _ := wire.SummarizeIPv4(p); s.Src != dst || s.Dst != src {
				t.Fatalf("reply %+v", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no echo reply\n%s", h.logs.String())
		}
	}
	time.Sleep(150 * time.Millisecond) // 让心跳往返几次
	if h.ts.ClientHeartbeat.Load() == 0 {
		t.Error("client heartbeat not sent")
	}
	if s := h.sess.Status().Stats; s.TxPackets != 5 || s.RxPackets != 5 {
		t.Errorf("stats %+v", s)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("down should return nil: %v", err)
	}
	if _, td := h.net.counts(); td != 1 {
		t.Fatalf("teardown %d", td)
	}
	if h.sess.Status().State != Idle {
		t.Fatal("final state")
	}
	if _, err := h.dev.Write([]byte{1}); err == nil {
		t.Fatal("device should be closed")
	}
	logs := h.logs.String()
	for _, k := range []string{"sendip_layout", "data_conn", "rc4_key", "is_hid_user", "data_opcode", "data_endian"} {
		if !strings.Contains(logs, "assumption="+k) {
			t.Errorf("missing assumption %s", k)
		}
	}
	if strings.Contains(logs, "valid_10_11") && strings.Contains(logs, "仍未收到") {
		t.Error("10/11 were sent; should not warn")
	}
}

func TestBadMagicExit4(t *testing.T) {
	h := newHarness(t, "bad-magic", nil)
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, wire.ErrBadServerMsg) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
	if a, _ := h.net.counts(); a != 0 {
		t.Fatal("no network change expected")
	}
}

func TestKickExit7NoReconnect(t *testing.T) {
	h := newHarness(t, "kick", patient)
	start := time.Now()
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, ErrStopped) || vpnerr.ExitCode(err) != 7 {
		t.Fatalf("got %v", err)
	}
	// docs/00 P5：被踢后 3 秒内 STOPPED
	if time.Since(start) > 3*time.Second+testserver.KickDelay {
		t.Fatal("too slow")
	}
	if h.ts.CtrlConns.Load() != 1 {
		t.Fatalf("must not reconnect after kick, conns=%d", h.ts.CtrlConns.Load())
	}
	if !strings.Contains(err.Error(), "账号已在其他位置登录") || h.sess.Status().StopReason == "" {
		t.Fatalf("reason: %v", err)
	}
	if _, td := h.net.counts(); td != 1 {
		t.Fatal("must roll back")
	}
}

func TestShutdownExit7(t *testing.T) {
	h := newHarness(t, "shutdown", patient)
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, ErrStopped) || vpnerr.ExitCode(err) != 7 || h.ts.CtrlConns.Load() != 1 {
		t.Fatalf("got %v conns=%d", err, h.ts.CtrlConns.Load())
	}
}

func TestBusyThenOK(t *testing.T) {
	h := newHarness(t, "busy-then-ok", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	h.waitState(t, Running, 5*time.Second)
	if n := h.ts.CtrlConns.Load(); n != 4 {
		t.Fatalf("ctrl conns %d want 4", n)
	}
	if st := h.sess.Status(); st.Reconnects != 3 {
		t.Fatalf("reconnects %d", st.Reconnects)
	}
	cancel()
	<-done
}

func TestBusyExhausted(t *testing.T) {
	// 剧本前 3 次繁忙；把上限降到 2 次，应在第 3 次繁忙时放弃
	h := newHarness(t, "busy-then-ok", func(o *Options) {
		o.PolicyFor = func(p command.Policy) command.Policy { p = fast(p); p.MaxRetries = 2; return p }
	})
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, ErrRetriesExhausted) || vpnerr.ExitCode(err) != 7 {
		t.Fatalf("got %v", err)
	}
}

func TestResetReconnectsImmediately(t *testing.T) {
	h := newHarness(t, "reset", patient)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for h.ts.CtrlConns.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.waitState(t, Running, 3*time.Second)
	if h.ts.CtrlConns.Load() != 2 {
		t.Fatalf("conns %d", h.ts.CtrlConns.Load())
	}
	if a, _ := h.net.counts(); a != 1 {
		t.Fatalf("same tapip must not re-apply network, applies=%d", a)
	}
	if strings.Contains(h.logs.String(), "to=backoff") {
		t.Fatal("SERVER_RESET must not back off")
	}
	cancel()
	<-done
}

func TestDropBacksOffAndRecovers(t *testing.T) {
	h := newHarness(t, "drop", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for h.ts.CtrlConns.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.waitState(t, Running, 3*time.Second)
	if !strings.Contains(h.logs.String(), "to=backoff") {
		t.Fatal("network drop should go through backoff")
	}
	cancel()
	<-done
}

func TestSilentWatchdog(t *testing.T) {
	h := newHarness(t, "silent", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(5 * time.Second)
	for h.ts.CtrlConns.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.ts.CtrlConns.Load() < 2 || !strings.Contains(h.logs.String(), "心跳超时") {
		t.Fatalf("watchdog should trigger reconnect\n%s", h.logs.String())
	}
	cancel()
	<-done
}

func TestBadSendIPExit4(t *testing.T) {
	h := newHarness(t, "bad-sendip", nil)
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, wire.ErrSendIPLayout) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(h.logs.String(), "level=ERROR") || !strings.Contains(h.logs.String(), "hex=41414242") {
		t.Fatal("error log must include raw hex")
	}
}

func TestEncRequiredExit4(t *testing.T) {
	h := newHarness(t, "enc-required", nil)
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, tunnel.ErrEncryptionUnsupported) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
}

func TestNoValidWarnsButRuns(t *testing.T) {
	h := newHarness(t, "no-valid", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	h.waitState(t, Running, 5*time.Second)
	time.Sleep(350 * time.Millisecond)
	if h.sess.Status().State != Running || !strings.Contains(h.logs.String(), "IPVALID/GROUPIDVALID") {
		t.Fatalf("should warn and keep running\n%s", h.logs.String())
	}
	if !strings.Contains(h.logs.String(), "assumption=valid_10_11") {
		t.Fatal("assumption log")
	}
	cancel()
	<-done
}

func TestUnknownCommandKeepsRunning(t *testing.T) {
	h := newHarness(t, "unknown-cmd", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	h.waitState(t, Running, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if h.sess.Status().State != Running || !strings.Contains(h.logs.String(), "未知命令") || h.ts.CtrlConns.Load() != 1 {
		t.Fatal("unknown command must be ignored")
	}
	cancel()
	<-done
}

func TestApplyFailureExit6(t *testing.T) {
	h := newHarness(t, "happy", nil)
	h.net.failApply = true
	err := runToEnd(t, h, 5*time.Second)
	if vpnerr.ExitCode(err) != 6 {
		t.Fatalf("got %v", err)
	}
	if _, td := h.net.counts(); td != 1 {
		t.Fatal("teardown after failed apply")
	}
}

func TestSessionExpiredExit3(t *testing.T) {
	h := newHarness(t, "happy", func(o *Options) {
		o.Auth = &fakeAuth{err: errors.Join(vpnerr.ErrAuth, auth.ErrSessionExpired)}
	})
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, auth.ErrSessionExpired) || vpnerr.ExitCode(err) != 3 {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceLostExit6(t *testing.T) {
	h := newHarness(t, "happy", nil)
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	h.waitState(t, Running, 5*time.Second)
	h.dev.Close() // 模拟 TUN 被外部删除
	select {
	case err := <-done:
		if !errors.Is(err, ErrDeviceLost) || vpnerr.ExitCode(err) != 6 {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("device loss not detected")
	}
}

func TestNoRoutesExit6AndDefaultRouteIgnored(t *testing.T) {
	h := newHarness(t, "happy", func(o *Options) {
		o.Auth = &fakeAuth{res: auth.Resources{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}}
	})
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, ErrNoRoutes) || vpnerr.ExitCode(err) != 6 {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(h.logs.String(), "不接管默认路由") {
		t.Fatal("must warn about 0.0.0.0/0")
	}
}

func TestExtraRoutesAndDNSFallback(t *testing.T) {
	h := newHarness(t, "happy", func(o *Options) {
		o.ExtraRoutes = []string{"192.168.50.0/24", "10.9.0.0/16", "172.16.1.1", "bogus"}
		o.DNSServers = []string{"10.0.0.53"}
	})
	_, cancel, done := h.run(t, 10*time.Second)
	defer cancel()
	h.waitState(t, Running, 5*time.Second)
	p := h.net.applies[0]
	var rs []string
	for _, r := range p.Routes {
		rs = append(rs, r.String())
	}
	if strings.Join(rs, ",") != "10.0.0.0/8,192.168.50.0/24,172.16.1.1/32" || p.DNSServers[0].String() != "10.0.0.53" {
		t.Fatalf("routes %v dns %v", rs, p.DNSServers)
	}
	cancel()
	<-done
}

func TestHandshakeRejectedFirstAttemptExit4(t *testing.T) {
	h := newHarness(t, "happy", func(o *Options) { o.Token = "ffffffffffffffff" })
	err := runToEnd(t, h, 5*time.Second)
	if !errors.Is(err, tunnel.ErrHandshakeRejected) || vpnerr.ExitCode(err) != 4 {
		t.Fatalf("got %v", err)
	}
}
