package auth

import (
	"context"
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

func newGateway(t *testing.T, cfg testserver.AuthConfig) (*testserver.AuthServer, *Client) {
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
	c, err := New(Options{Server: host, Port: port, HTTPClient: srv.Client(), Timeout: 5 * time.Second})
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
