package route

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestRouteCommands(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/8")
	cases := []struct {
		goos string
		add  string
		del  string
	}{
		{"darwin", "route -n add -net 10.0.0.0/8 -interface utun5", "route -n delete -net 10.0.0.0/8 -interface utun5"},
		{"linux", "ip route add 10.0.0.0/8 dev utun5", "ip route del 10.0.0.0/8 dev utun5"},
		{"windows", "netsh interface ipv4 add route 10.0.0.0/8 utun5 0.0.0.0 store=active", "netsh interface ipv4 delete route 10.0.0.0/8 utun5"},
	}
	for _, c := range cases {
		if got := strings.Join(RouteAddCmd(c.goos, p, "utun5"), " "); got != c.add {
			t.Errorf("%s add: %s", c.goos, got)
		}
		if got := strings.Join(RouteDelCmd(c.goos, p, "utun5"), " "); got != c.del {
			t.Errorf("%s del: %s", c.goos, got)
		}
	}
	host := netip.MustParsePrefix("10.1.1.1/32")
	if got := strings.Join(RouteAddCmd("darwin", host, "utun5"), " "); got != "route -n add -host 10.1.1.1 -interface utun5" {
		t.Error(got)
	}
}

func TestAddrCmds(t *testing.T) {
	tap := netip.MustParseAddr("10.8.0.2")
	want := map[string]string{
		"linux":   "ip addr add 10.8.0.2/32 dev tun0 | ip link set tun0 mtu 1400 up",
		"darwin":  "ifconfig tun0 inet 10.8.0.2 10.8.0.2 netmask 255.255.255.255 | ifconfig tun0 mtu 1400 up",
		"windows": "netsh interface ipv4 set address name=tun0 static 10.8.0.2 255.255.255.255 | netsh interface ipv4 set subinterface tun0 mtu=1400 store=active",
	}
	for goos, w := range want {
		var parts []string
		for _, c := range AddrCmds(goos, "tun0", tap, 1400) {
			parts = append(parts, strings.Join(c, " "))
		}
		if got := strings.Join(parts, " | "); got != w {
			t.Errorf("%s: %s", goos, got)
		}
	}
	if !strings.Contains(strings.Join(AddrCmds("linux", "tun0", netip.Addr{}, 1400)[0], " "), "<tapip>") {
		t.Error("dry-run placeholder")
	}
}

func TestParseGateway(t *testing.T) {
	cases := []struct {
		goos, out string
		want      Gateway
		err       bool
	}{
		{"linux", "203.0.113.9 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 1000 \n    cache", Gateway{Via: "192.168.1.1", Dev: "eth0"}, false},
		{"linux", "192.168.1.7 dev wlan0 src 192.168.1.5 uid 1000", Gateway{Dev: "wlan0"}, false},
		{"linux", "local 127.0.0.1 dev lo src 127.0.0.1", Gateway{Dev: "lo", Local: true}, false},
		{"linux", "garbage", Gateway{}, true},
		{"darwin", "   route to: 203.0.113.9\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>", Gateway{Via: "192.168.1.1", Dev: "en0"}, false},
		{"windows", "12 192.168.1.1\r\n", Gateway{Via: "192.168.1.1", Dev: "12"}, false},
		{"windows", "", Gateway{}, true},
	}
	for _, c := range cases {
		g, err := ParseGateway(c.goos, c.out)
		if (err != nil) != c.err || (!c.err && g != c.want) {
			t.Errorf("%s %q: %+v %v", c.goos, c.out, g, err)
		}
	}
	ip := netip.MustParseAddr("203.0.113.9")
	if got := strings.Join(BypassAddCmd("linux", ip, Gateway{Via: "192.168.1.1", Dev: "eth0"}), " "); got != "ip route add 203.0.113.9/32 via 192.168.1.1 dev eth0" {
		t.Error(got)
	}
	if got := strings.Join(BypassAddCmd("darwin", ip, Gateway{Dev: "en0"}), " "); got != "route -n add -host 203.0.113.9 -interface en0" {
		t.Error(got)
	}
}

func TestDNSCommands(t *testing.T) {
	sv := []netip.Addr{netip.MustParseAddr("10.0.0.53")}
	c := LinuxDNSCmds("tun0", sv, []string{"corp.example.com", "internal.example.com"})
	if strings.Join(c[0], " ") != "resolvectl dns tun0 10.0.0.53" || strings.Join(c[1], " ") != "resolvectl domain tun0 ~corp.example.com ~internal.example.com" {
		t.Error(c)
	}
	n := WindowsNRPTAddCmd(sv, []string{"corp.example.com"})
	if !strings.Contains(n[len(n)-1], `-Namespace ".corp.example.com" -NameServers "10.0.0.53" -Comment "vpnkit"`) {
		t.Error(n)
	}
	path, content := ResolverFile("corp.example.com", sv)
	if path != "/etc/resolver/corp.example.com" || !strings.Contains(content, "nameserver 10.0.0.53\n") {
		t.Error(path, content)
	}
}

// fakeRunner 记录变更命令，可按前缀注入失败。
type fakeRunner struct {
	mu       sync.Mutex
	cmds     []string
	failOn   map[string]string // 命令前缀 → 输出
	query    map[string]string // 命令前缀 → 输出
	files    map[string]string
	noResolv bool
}

func newFake() *fakeRunner {
	return &fakeRunner{failOn: map[string]string{}, query: map[string]string{}, files: map[string]string{}}
}

func (f *fakeRunner) Run(_ context.Context, argv []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := strings.Join(argv, " ")
	f.cmds = append(f.cmds, c)
	for p, out := range f.failOn {
		if strings.HasPrefix(c, p) {
			return []byte(out), errors.New("exit status 2")
		}
	}
	return nil, nil
}

func (f *fakeRunner) Query(_ context.Context, argv []string) ([]byte, error) {
	c := strings.Join(argv, " ")
	for p, out := range f.query {
		if strings.HasPrefix(c, p) {
			return []byte(out), nil
		}
	}
	return nil, errors.New("query failed")
}

func (f *fakeRunner) WriteFile(p, c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = c
	f.cmds = append(f.cmds, "write "+p)
	return nil
}

func (f *fakeRunner) RemoveFile(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, p)
	f.cmds = append(f.cmds, "rm "+p)
	return nil
}

func (f *fakeRunner) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(c), nil
}

func (f *fakeRunner) LookPath(string) bool { return !f.noResolv }

func (f *fakeRunner) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.cmds, "\n")
}

func plan() Plan {
	return Plan{
		Device: "tun0", TapIP: netip.MustParseAddr("10.8.0.2"), MTU: 1400,
		Routes:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12")},
		Bypass:      []netip.Addr{netip.MustParseAddr("203.0.113.9")},
		DNSServers:  []netip.Addr{netip.MustParseAddr("10.0.0.53")},
		DNSSuffixes: []string{"corp.example.com"},
	}
}

func TestManagerApplyTeardownLinux(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	f.query["ip -4 route get 203.0.113.9"] = "203.0.113.9 via 192.168.1.1 dev eth0 src 192.168.1.5"
	m := &Manager{GOOS: "linux", R: f, Dir: dir}
	res, err := m.Apply(context.Background(), plan())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RoutesOK) != 2 || !res.DNSEnabled {
		t.Fatalf("%+v", res)
	}
	want := `ip route add 203.0.113.9/32 via 192.168.1.1 dev eth0
ip addr add 10.8.0.2/32 dev tun0
ip link set tun0 mtu 1400 up
ip route add 10.0.0.0/8 dev tun0
ip route add 172.16.0.0/12 dev tun0
resolvectl dns tun0 10.0.0.53
resolvectl domain tun0 ~corp.example.com`
	if f.all() != want {
		t.Fatalf("commands:\n%s", f.all())
	}
	// 默认路由神圣不可侵犯
	if strings.Contains(f.all(), "default") || strings.Contains(f.all(), "0.0.0.0/0") {
		t.Fatal("must never touch default route")
	}
	st, _ := LoadState(dir)
	if st == nil || len(st.RoutesAdded) != 2 || len(st.BypassAdded) != 1 || st.ResolvectlLink != "tun0" || st.PID != os.Getpid() {
		t.Fatalf("state %+v", st)
	}
	f.cmds = nil
	if err := m.Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantDown := `resolvectl revert tun0
ip route del 172.16.0.0/12 dev tun0
ip route del 10.0.0.0/8 dev tun0
ip route del 203.0.113.9/32`
	if f.all() != wantDown {
		t.Fatalf("teardown:\n%s", f.all())
	}
	if st, _ := LoadState(dir); st != nil {
		t.Fatal("state.json must be removed")
	}
	if err := m.Teardown(context.Background()); err != nil {
		t.Fatal("teardown must be idempotent")
	}
}

func TestPartialRouteFailure(t *testing.T) {
	f := newFake()
	f.failOn["ip route add 172.16.0.0/12"] = "RTNETLINK answers: File exists"
	m := &Manager{GOOS: "linux", R: f, Dir: t.TempDir()}
	res, err := m.Apply(context.Background(), plan())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.RoutesOK) != 1 || len(res.RoutesFailed) != 1 || !strings.Contains(res.RoutesFailed[0], "冲突") {
		t.Fatalf("%+v", res)
	}
	if len(res.Warnings) == 0 { // bypass 查询失败但不在网段内 → 告警
		t.Fatal("expected bypass warning")
	}
	f.cmds = nil
	m.Teardown(context.Background())
	if strings.Contains(f.all(), "172.16.0.0/12") {
		t.Fatal("must not delete a route we did not add")
	}
}

func TestAllRoutesFailRollsBack(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	f.failOn["ip route add 1"] = "Error: Nexthop has invalid gateway."
	m := &Manager{GOOS: "linux", R: f, Dir: dir}
	_, err := m.Apply(context.Background(), plan())
	if !errors.Is(err, ErrAllRoutesFailed) {
		t.Fatalf("got %v", err)
	}
	if st, _ := LoadState(dir); st != nil {
		t.Fatal("rollback must clear state")
	}
}

func TestBypassRequiredWhenServerInsideRoutes(t *testing.T) {
	f := newFake() // 查询全部失败
	p := plan()
	p.Bypass = []netip.Addr{netip.MustParseAddr("10.20.30.40")}
	m := &Manager{GOOS: "linux", R: f, Dir: t.TempDir()}
	if _, err := m.Apply(context.Background(), p); !errors.Is(err, ErrBypassRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestDarwinResolverFiles(t *testing.T) {
	f := newFake()
	f.query["route -n get 203.0.113.9"] = "gateway: 192.168.1.1\ninterface: en0\n"
	f.files["/etc/resolver/other.example.com"] = "nameserver 1.1.1.1\n"
	p := plan()
	p.Device = "utun5"
	p.DNSSuffixes = []string{"corp.example.com", "other.example.com"}
	m := &Manager{GOOS: "darwin", R: f, Dir: t.TempDir()}
	res, err := m.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.DNSEnabled || !strings.HasPrefix(f.files["/etc/resolver/corp.example.com"], "# managed by vpnkit") {
		t.Fatalf("resolver %+v", f.files)
	}
	if f.files["/etc/resolver/other.example.com"] != "nameserver 1.1.1.1\n" || len(res.Warnings) != 1 {
		t.Fatal("must not overwrite foreign resolver file")
	}
	if !strings.Contains(f.all(), "route -n add -host 203.0.113.9 192.168.1.1") {
		t.Fatal(f.all())
	}
	m.Teardown(context.Background())
	if _, ok := f.files["/etc/resolver/corp.example.com"]; ok {
		t.Fatal("resolver file must be removed")
	}
	if _, ok := f.files["/etc/resolver/other.example.com"]; !ok {
		t.Fatal("foreign file must survive")
	}
}

func TestLinuxWithoutResolved(t *testing.T) {
	f := newFake()
	f.noResolv = true
	m := &Manager{GOOS: "linux", R: f, Dir: t.TempDir()}
	res, err := m.Apply(context.Background(), plan())
	if err != nil || res.DNSEnabled {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "/etc/resolv.conf") || strings.Contains(f.all(), "resolv") {
		t.Fatalf("%v\n%s", res.Warnings, f.all())
	}
}

func TestWindowsNRPT(t *testing.T) {
	f := newFake()
	f.query["powershell"] = "12 192.168.1.1"
	p := plan()
	p.Device = WindowsAdapter
	m := &Manager{GOOS: "windows", R: f, Dir: t.TempDir()}
	res, err := m.Apply(context.Background(), p)
	if err != nil || !res.DNSEnabled {
		t.Fatal(err)
	}
	if !strings.Contains(f.all(), "route add 203.0.113.9 mask 255.255.255.255 192.168.1.1 if 12") {
		t.Fatal(f.all())
	}
	f.cmds = nil
	m.Teardown(context.Background())
	if !strings.Contains(f.all(), `Where-Object {$_.Comment -eq "vpnkit"} | Remove-DnsClientNrptRule -Force`) {
		t.Fatal(f.all())
	}
}

func TestRecover(t *testing.T) {
	dir := t.TempDir()
	saveState(dir, &State{PID: 999999, GOOS: "linux", Tun: "tun0", RoutesAdded: []string{"10.0.0.0/8"}, BypassAdded: []string{"203.0.113.9"}})
	f := newFake()
	f.failOn["ip route del 10.0.0.0/8"] = "Cannot find device \"tun0\"" // TUN 已随进程消失：视为已清理
	ok, err := Recover(context.Background(), dir, f, nil, func(int) bool { return false })
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if !strings.Contains(f.all(), "ip route del 203.0.113.9/32") {
		t.Fatal(f.all())
	}
	if st, _ := LoadState(dir); st != nil {
		t.Fatal("state must be removed")
	}
	if ok, err := Recover(context.Background(), dir, f, nil, func(int) bool { return false }); ok || err != nil {
		t.Fatal("no state → nothing to do")
	}
	saveState(dir, &State{PID: 4242, GOOS: "linux"})
	if _, err := Recover(context.Background(), dir, f, nil, func(int) bool { return true }); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("alive pid: %v", err)
	}
}

func TestCleanupFailureKeepsState(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	m := &Manager{GOOS: "linux", R: f, Dir: dir}
	f.query["ip -4 route get"] = "x via 192.168.1.1 dev eth0"
	m.Apply(context.Background(), plan())
	f.failOn["ip route del 10.0.0.0/8"] = "Operation not permitted"
	if err := m.Teardown(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	st, _ := LoadState(dir)
	if st == nil || len(st.RoutesAdded) != 1 || st.RoutesAdded[0] != "10.0.0.0/8" {
		t.Fatalf("remaining state %+v", st)
	}
}

func TestDryRunner(t *testing.T) {
	var out bytes.Buffer
	f := newFake()
	f.query["ip -4 route get"] = "203.0.113.9 via 192.168.1.1 dev eth0"
	d := &DryRunner{Out: &out, Reader: f}
	p := plan()
	p.Device, p.TapIP = "<tun>", netip.Addr{}
	m := &Manager{GOOS: "linux", R: d, Dir: ""}
	if _, err := m.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, w := range []string{"+ ip route add 203.0.113.9/32 via 192.168.1.1 dev eth0", "+ ip addr add '<tapip>/32' dev '<tun>'", "+ ip route add 10.0.0.0/8 dev '<tun>'", "+ resolvectl domain '<tun>' '~corp.example.com'"} {
		if !strings.Contains(s, w) {
			t.Errorf("dry-run missing %q\n%s", w, s)
		}
	}
	if len(f.cmds) != 0 {
		t.Fatal("dry-run must not execute mutating commands")
	}
}
