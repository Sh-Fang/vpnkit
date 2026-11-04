package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/testserver"
)

func newGateway(t *testing.T, cfg testserver.AuthConfig, opts ...func(*Options)) (*testserver.AuthServer, *Client) {
	t.Helper()
	if cfg.Users == nil {
		cfg.Users = map[string]string{"alice": "s3cret"}
	}
	as, err := testserver.NewAuthServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(as.Handler())
	t.Cleanup(srv.Close)
	host, portS, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)
	o := Options{Server: host, Port: port, HTTPClient: srv.Client(), Timeout: 5 * time.Second}
	for _, f := range opts {
		f(&o)
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return as, c
}

func TestLoginHappy(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{
		RCList: testserver.RCListXML("10.0.0.0/8", "corp.example.com", "192.168.1.10"),
	})
	ctx := context.Background()
	tok, err := c.Login(ctx, LoginRequest{User: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if !as.ValidToken(tok) {
		t.Fatalf("token %q not registered", tok)
	}
	f := as.LastLoginForm()
	if f.Get("mitm_result") != "1" || f.Get("svpn_rand_code") != "" || f.Has("devid") {
		t.Errorf("form %v", f)
	}
	if strings.Contains(f.Encode(), "s3cret") {
		t.Fatal("plaintext password leaked into form")
	}
	conf, _, err := c.FetchConf(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if conf.MTU != 1400 || !conf.IsHidUserSet || len(conf.TunDNS) != 1 {
		t.Errorf("conf %+v", conf)
	}
	r, err := c.FetchResources(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Prefixes) != 2 || r.Prefixes[0].String() != "10.0.0.0/8" || r.Prefixes[1].String() != "192.168.1.10/32" {
		t.Errorf("prefixes %v", r.Prefixes)
	}
	if len(r.Suffixes) != 1 || r.Suffixes[0] != "corp.example.com" {
		t.Errorf("suffixes %v", r.Suffixes)
	}
}

func TestLoginPswConfigKeyWins(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{PswConfigDifferentKey: true})
	if _, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("should use psw_config key: %v", err)
	}
}

func TestLoginNoPswConfig(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{NoPswConfig: true})
	if _, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"}); err != nil {
		t.Fatal(err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "nope"})
	var re *RejectError
	if !errors.As(err, &re) || !strings.Contains(re.Message, "密码错误") {
		t.Fatalf("want RejectError with message, got %v", err)
	}
	if vpnerr.ExitCode(err) != 3 || !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("exit code %d", vpnerr.ExitCode(err))
	}
}

func TestLoginMissingTwfID(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{OmitTwfID: true})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrBadResponse) || vpnerr.ExitCode(err) != 3 {
		t.Fatalf("want ErrBadResponse, got %v", err)
	}
}

func TestLoginCaptchaRequired(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{Captcha: true})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestLoginPasswordTooLong(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: strings.Repeat("x", 200)})
	if err == nil || vpnerr.ExitCode(err) != 3 || !strings.Contains(err.Error(), "过长") {
		t.Fatalf("got %v", err)
	}
}

func TestLoginSendsDeviceID(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{})
	if _, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret", DeviceID: "3F2A9C14B7E08D5612AB44CD990E7F31"}); err != nil {
		t.Fatal(err)
	}
	if as.LastLoginForm().Get("devid") != "3F2A9C14B7E08D5612AB44CD990E7F31" {
		t.Fatal("devid not sent")
	}
}

func TestExpiredToken401(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{})
	tok, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	as.Revoke(tok)
	_, _, err = c.FetchConf(context.Background(), tok)
	if !errors.Is(err, ErrSessionExpired) || vpnerr.ExitCode(err) != 3 {
		t.Fatalf("got %v", err)
	}
}

func TestExtractFields(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`{"TwfID":"abc123","x":1}`, "abc123"},
		{`{"data":{"twfid":"nested"}}`, "nested"},
		{`<Auth><TwfID>xml1</TwfID></Auth>`, "xml1"},
		{`<Auth><TwfID><![CDATA[cdata1]]></TwfID></Auth>`, "cdata1"},
		{`var TwfID = "js1";`, "js1"},
		{`TwfID=qs1&foo=bar`, "qs1"},
	}
	for _, c := range cases {
		f := extractFields([]byte(c.body), "TwfID")
		if f["TwfID"] != c.want {
			t.Errorf("%s → %q want %q", c.body, f["TwfID"], c.want)
		}
	}
	if _, ok := extractFields([]byte("<html>nothing</html>"), "TwfID")["TwfID"]; ok {
		t.Error("should be missing")
	}
}

func TestTagNames(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?><Auth><ErrorCode>1</ErrorCode>` +
		`<Message>ok</Message><NextAuth>4</NextAuth><NextService>auth/hid</NextService>` +
		`<NextAuth>dup</NextAuth><Field name="x"/></Auth>`
	got := tagNames([]byte(body))
	want := []string{"Auth", "ErrorCode", "Message", "NextAuth", "NextService", "Field"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tagNames = %v, want %v", got, want)
	}
}

func TestParseConfTolerant(t *testing.T) {
	c, w := ParseConf([]byte(`<Conf><Unknown a="1"/><Htp mtu="1350" port="4433"/><Mline enable="1" list="10.0.0.1:443;bad;10.0.0.2:443;"/></Conf>`))
	if c.MTU != 1350 || c.Port != 4433 || len(c.Lines) != 2 || !c.MlineEnabled || c.IsHidUserSet {
		t.Errorf("%+v", c)
	}
	if len(w) != 1 {
		t.Errorf("warnings %v", w)
	}
	_, w = ParseConf([]byte("not xml"))
	if len(w) != 1 {
		t.Errorf("warnings %v", w)
	}
}

func TestNormalizeResources(t *testing.T) {
	_, entries := ParseResources([]byte(testserver.RCListXML(
		"10.0.0.0/8;10.1.2.0/24", "172.16.0.0/255.240.0.0", "192.168.1.1~192.168.1.6",
		"https://wiki.corp.example.com:8443/path", "*.internal.example.com", "10.2.3.4:80",
		"fe80::1", "???", "CORP.example.com")))
	r := Normalize(entries)
	var got []string
	for _, p := range r.Prefixes {
		got = append(got, p.String())
	}
	want := "10.0.0.0/8,172.16.0.0/12,192.168.1.2/31,192.168.1.4/31,192.168.1.1/32,192.168.1.6/32"
	if strings.Join(got, ",") != want {
		t.Errorf("prefixes\n got %s\nwant %s", strings.Join(got, ","), want)
	}
	if strings.Join(r.Suffixes, ",") != "wiki.corp.example.com,internal.example.com,corp.example.com" {
		t.Errorf("suffixes %v", r.Suffixes)
	}
	if len(r.Skipped) != 2 {
		t.Errorf("skipped %v", r.Skipped)
	}
	format, plain := ParseResources([]byte("10.0.0.0/8\n# c\nfoo.example.com\n"))
	if format != "plain-lines" || len(plain) != 2 {
		t.Errorf("%s %v", format, plain)
	}
}

func TestRangeToPrefixes(t *testing.T) {
	ps, err := RangeToPrefixes(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.255.255.255"))
	if err != nil || len(ps) != 1 || ps[0].String() != "10.0.0.0/8" {
		t.Fatalf("%v %v", ps, err)
	}
	ps, _ = RangeToPrefixes(netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"))
	if len(ps) != 1 || ps[0].Bits() != 0 {
		t.Fatalf("%v", ps)
	}
	if _, err := RangeToPrefixes(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Fatal("want error")
	}
}

func TestSessionStore(t *testing.T) {
	d := t.TempDir()
	if _, err := LoadSession(d, "vpn.example.com"); !errors.Is(err, ErrNoSession) || vpnerr.ExitCode(err) != 3 {
		t.Fatalf("got %v", err)
	}
	s := &Session{Server: "vpn.example.com", User: "alice", TwfID: "0123456789abcdef", ObtainedAt: time.Now()}
	if err := SaveSession(d, s); err != nil {
		t.Fatal(err)
	}
	if ok, err := fsutil.Private(SessionPath(d, "vpn.example.com")); err != nil || !ok {
		t.Fatalf("session file not private: %v", err)
	}
	got, err := LoadSession(d, "vpn.example.com")
	if err != nil || got.TwfID != s.TwfID {
		t.Fatalf("%+v %v", got, err)
	}
	if l := ListSessions(d); len(l) != 1 || l[0] != "vpn.example.com" {
		t.Fatalf("%v", l)
	}
	if filepath.Dir(SessionPath(d, "a/../../b")) != d || filepath.Dir(SessionPath(d, `a\..\b`)) != d {
		t.Fatal("unsafe path")
	}
	if err := DeleteSession(d, "vpn.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSession(d, "vpn.example.com"); err != nil {
		t.Fatal("delete should be idempotent")
	}
}

func TestCertSHA256Pinning(t *testing.T) {
	as, err := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "s3cret"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(as.Handler())
	t.Cleanup(srv.Close)
	host, portS, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])
	login := func(pin string) error {
		c, err := New(Options{Server: host, Port: port, CertSHA256: pin, Timeout: 5 * time.Second})
		if err != nil {
			return err
		}
		_, err = c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
		return err
	}
	colon := strings.ToUpper(fp[:2])
	for i := 2; i < len(fp); i += 2 {
		colon += ":" + strings.ToUpper(fp[i:i+2])
	}
	for _, pin := range []string{fp, colon} {
		if err := login(pin); err != nil {
			t.Fatalf("pin %s: %v", pin, err)
		}
	}
	if err := login(strings.Repeat("00", 32)); !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("wrong pin: %v", err)
	}
	if err := login("abcd"); !errors.Is(err, vpnerr.ErrUsage) {
		t.Fatalf("bad pin: %v", err)
	}
}

func TestLoginKeepsTwfIDOnSuccessCode(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{KeepTwfID: true})
	tok, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if !as.ValidToken(tok) {
		t.Fatalf("token %q not registered", tok)
	}
	if _, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "wrong"}); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestLoginSecondFactorRequired(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{NextAuth: "2"})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrSecondFactor) || !errors.Is(err, vpnerr.ErrAuth) {
		t.Fatalf("got %v", err)
	}
}

const testDevID = "3F2A9C14B7E08D5612AB44CD990E7F31"

func TestLoginHIDRegisterSuccess(t *testing.T) {
	// 已绑定的机器：login_hid.csp 认下 hid 即完成二次认证（docs/02 §4.1）。
	as, c := newGateway(t, testserver.AuthConfig{NextAuth: "4", NextService: "auth/hid", HIDExpectDevID: testDevID},
		func(o *Options) { o.RegisterDevice = true })
	tok, err := c.Login(context.Background(), LoginRequest{
		User: "alice", Password: "s3cret", DeviceID: testDevID,
		MACAddress: "AA:BB:CC:DD:EE:01", Hostname: "test-host",
	})
	if err != nil {
		t.Fatalf("hid login: %v", err)
	}
	if !as.ValidToken(tok) {
		t.Fatalf("token %q not registered after hid", tok)
	}
	f := as.LastHIDForm()
	// 四个字段缺一不可，形状取自 Web 端 SDK 的 loginHid（docs/02 §4.1）。
	if f.Get("hid") != testDevID {
		t.Errorf("hid = %q，期望 %q", f.Get("hid"), testDevID)
	}
	if got := f.Get("hostname"); got != "test-host" {
		t.Errorf("hostname = %q", got)
	}
	if got := f.Get("macaddress"); got != "AA:BB:CC:DD:EE:01" {
		t.Errorf("macaddress = %q", got)
	}
	if got := f.Get("ignore"); got != "0" {
		t.Errorf("ignore = %q，期望 0", got)
	}
	// 反重放：回显 login_psw 那步拿到的 CSRF。
	if f.Get("svpn_req_randcode") == "" {
		t.Errorf("hid 表单应带 CSRF: %v", f)
	}
	// 已绑定的机器不需要再提交绑定申请。
	if got := as.LastSubmitHID(); got != nil {
		t.Errorf("不该提交绑定申请: %v", got)
	}
}

func TestLoginHIDParamError(t *testing.T) {
	// 认证这步被拒（20210）时，按网关特征码页的提示改走绑定申请；
	// 这里网关要管理员审批，于是停在「等待审批」。
	as, c := newGateway(t, testserver.AuthConfig{NextAuth: "4", NextService: "auth/hid", HIDField: "svpn_inputhid"},
		func(o *Options) { o.RegisterDevice = true })
	_, err := c.Login(context.Background(), LoginRequest{
		User: "alice", Password: "s3cret", DeviceID: testDevID,
		MACAddress: "AA:BB:CC:DD:EE:01", Hostname: "test-host",
	})
	if !errors.Is(err, ErrDevicePending) {
		t.Fatalf("got %v", err)
	}
	if as.LastSubmitHID() == nil {
		t.Error("认证被拒后应尝试提交绑定申请")
	}
}

func TestLoginHIDWithoutRegisterDevice(t *testing.T) {
	// 没开 register_device 时，hid 这步仍报 ErrSecondFactor，不静默登记。
	_, c := newGateway(t, testserver.AuthConfig{NextAuth: "4", NextService: "auth/hid"})
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret", DeviceID: testDevID})
	if !errors.Is(err, ErrSecondFactor) {
		t.Fatalf("got %v", err)
	}
}

func TestLoginHIDNeedsDeviceID(t *testing.T) {
	_, c := newGateway(t, testserver.AuthConfig{NextAuth: "4", NextService: "auth/hid"},
		func(o *Options) { o.RegisterDevice = true })
	_, err := c.Login(context.Background(), LoginRequest{User: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrNeedDeviceID) {
		t.Fatalf("got %v", err)
	}
}

func TestLoginHIDPendingApproval(t *testing.T) {
	// 网关期望另一台机器 → login_hid 认证不过 → 改走 submithid.csp 提交绑定申请 → 停在待审批。
	as, c := newGateway(t, testserver.AuthConfig{NextAuth: "4", NextService: "auth/hid", HIDExpectDevID: "00000000000000000000000000000000"},
		func(o *Options) { o.RegisterDevice = true })
	_, err := c.Login(context.Background(), LoginRequest{
		User: "alice", Password: "s3cret", DeviceID: testDevID,
		MACAddress: "AA:BB:CC:DD:EE:01", Hostname: "test-host",
	})
	if !errors.Is(err, ErrDevicePending) {
		t.Fatalf("got %v", err)
	}
	q := as.LastSubmitHID()
	if q == nil {
		t.Fatal("未提交绑定申请")
	}
	// 绑定申请的参数走表单体，三个字段（docs/02 §4.2）。
	for _, k := range []string{"hid", "hostname", "macaddress"} {
		if q.Get(k) == "" {
			t.Errorf("绑定申请缺参数 %s: %v", k, q)
		}
	}
	if q.Get("hid") != testDevID {
		t.Errorf("绑定申请的特征码不对: %v", q)
	}
	if q.Get("hostname") != "test-host" || q.Get("macaddress") != "AA:BB:CC:DD:EE:01" {
		t.Errorf("绑定申请没带上主机名/MAC: %v", q)
	}
}

// TestCertVerifyFailureHints 验证证书校验失败时给出可操作提示与实际指纹，
// 而不是把 Go 的原始 x509 报错直接甩给用户。
func TestCertVerifyFailureHints(t *testing.T) {
	// 假网关用的是自签证书；客户端不带 ca_file/cert_sha256，校验必然失败。
	as, _ := testserver.NewAuthServer(testserver.AuthConfig{Users: map[string]string{"alice": "pw"}})
	srv := httptest.NewTLSServer(as.Handler())
	defer srv.Close()
	host, portS, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)
	c, err := New(Options{Server: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Login(context.Background(), LoginRequest{User: "alice", Password: "pw"})
	if err == nil {
		t.Fatal("期望证书校验失败")
	}
	msg := err.Error()
	for _, want := range []string{"--cert-sha256", "--insecure", "SHA-256"} {
		if !strings.Contains(msg, want) {
			t.Errorf("提示里缺少 %q: %v", want, err)
		}
	}
}

// TestLoginHIDCSRFRetry 验证反重放握手：网关第一次回 20210 并换发 CSRF，
// 客户端带上新 CSRF 重试一次即通过（docs/02 §4.1）。
func TestLoginHIDCSRFRetry(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{
		NextAuth: "4", NextService: "auth/hid",
		HIDExpectDevID: testDevID, HIDRejectFirstCSRF: true,
	}, func(o *Options) { o.RegisterDevice = true })
	tok, err := c.Login(context.Background(), LoginRequest{
		User: "alice", Password: "s3cret", DeviceID: testDevID,
		MACAddress: "AA:BB:CC:DD:EE:01", Hostname: "test-host",
	})
	if err != nil {
		t.Fatalf("hid retry login: %v", err)
	}
	if !as.ValidToken(tok) {
		t.Fatalf("token %q 未登记", tok)
	}
}

// TestLoginHIDAutoApprove 覆盖网关「提交即自动审核」的形态（docs/02 §4.2）：
// 特征码认证不过 → 提交绑定申请成功 → 重跑一次登录，这回不再要特征码。
func TestLoginHIDAutoApprove(t *testing.T) {
	as, c := newGateway(t, testserver.AuthConfig{
		NextAuth: "4", NextService: "auth/hid", AutoApproveHID: true,
		HIDExpectDevID: "00000000000000000000000000000000", // 认证必失败，逼出「提交→自动审核」
	}, func(o *Options) { o.RegisterDevice = true })
	tok, err := c.Login(context.Background(), LoginRequest{
		User: "alice", Password: "s3cret", DeviceID: testDevID,
		MACAddress: "AA:BB:CC:DD:EE:01", Hostname: "test-host",
	})
	if err != nil {
		t.Fatalf("自动审核流程登录失败: %v", err)
	}
	if !as.ValidToken(tok) {
		t.Fatalf("token %q 未登记", tok)
	}
	if as.LastSubmitHID() == nil {
		t.Error("应当提交过绑定申请")
	}
}
