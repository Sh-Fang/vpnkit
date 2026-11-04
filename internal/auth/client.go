// Package auth 实现认证协议（docs/02）：HTTPS + RSA PKCS#1 v1.5。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

var (
	ErrBadResponse     = errors.New("网关响应格式不符")
	ErrLoginRejected   = errors.New("网关拒绝登录")
	ErrSessionExpired  = errors.New("会话已失效，请重新 vpnkit login")
	ErrCaptchaRequired = errors.New("网关要求图形验证码")
	ErrCertMismatch    = errors.New("网关证书指纹与 cert_sha256 不符")
	ErrSecondFactor    = errors.New("网关要求二次认证（短信、令牌等），当前版本不支持")
)

// RejectError 携带网关返回的可读消息，透传给用户便于自助排查（docs/02 §4）。
type RejectError struct {
	Code    string
	Message string
}

func (e *RejectError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "（网关未给出原因）"
	}
	if e.Code != "" {
		return fmt.Sprintf("网关拒绝登录: %s (code=%s)", msg, e.Code)
	}
	return "网关拒绝登录: " + msg
}

func (e *RejectError) Unwrap() []error { return []error{ErrLoginRejected, vpnerr.ErrAuth} }

type Options struct {
	Server        string
	Port          int
	Insecure      bool
	CAFile        string
	CertSHA256    string // 十六进制，大小写与冒号分隔均可
	Timeout       time.Duration
	MitmField     string
	SendRandCode  bool
	DeviceIDField string
	Logger        *slog.Logger
	// HTTPClient 非空时覆盖默认客户端（测试用）。
	HTTPClient *http.Client
}

type Client struct {
	base *url.URL
	http *http.Client
	o    Options
	log  *slog.Logger
}

func New(o Options) (*Client, error) {
	if o.Server == "" {
		return nil, fmt.Errorf("%w: 未指定网关", vpnerr.ErrUsage)
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MitmField == "" {
		o.MitmField = "mitm_result"
	}
	c := &Client{o: o, log: logx.Or(o.Logger)}
	c.base = &url.URL{Scheme: "https", Host: net.JoinHostPort(o.Server, strconv.Itoa(o.Port))}
	if o.HTTPClient != nil {
		c.http = o.HTTPClient
		return c, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS10}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%w: 读取 ca_file: %w", vpnerr.ErrUsage, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: ca_file 中没有可用证书", vpnerr.ErrUsage)
		}
		tc.RootCAs = pool
	}
	if o.CertSHA256 != "" {
		want, err := parseFingerprint(o.CertSHA256)
		if err != nil {
			return nil, err
		}
		// 出厂证书的名字与网关域名对不上，标准校验必然失败；改为只比对叶子证书指纹。
		tc.InsecureSkipVerify = true
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: 网关没有出示证书", ErrCertMismatch)
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got != want {
				return fmt.Errorf("%w: 实际为 %s", ErrCertMismatch, strings.ToUpper(hex.EncodeToString(got[:])))
			}
			return nil
		}
	} else if o.Insecure {
		c.log.Warn("已关闭网关证书校验（server.insecure=true），仅在确认网络可信时使用")
		tc.InsecureSkipVerify = true
	}
	c.http = &http.Client{
		Timeout:   o.Timeout,
		Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil},
		// 会话失效时网关常重定向回登录页；不跟随，便于识别为失效。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

func parseFingerprint(s string) ([32]byte, error) {
	var fp [32]byte
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != len(fp) {
		return fp, fmt.Errorf("%w: cert_sha256 应为 64 位十六进制（可带冒号）", vpnerr.ErrUsage)
	}
	copy(fp[:], b)
	return fp, nil
}

// LoginRequest 是一次登录的输入。Password 只在内存中停留，不落盘、不进日志。
type LoginRequest struct {
	User     string
	Password string
	Captcha  string
	DeviceID string // 非空时按 DeviceIDField 上报
}

// Login 执行 docs/02 §1 的第 1–3 步，返回登录后的会话令牌。
func (c *Client) Login(ctx context.Context, req LoginRequest) (string, error) {
	body, _, err := c.get(ctx, "/por/login_auth.csp", "")
	if err != nil {
		return "", err
	}
	f := extractFields(body, "TwfID", "RSA_ENCRYPT_KEY", "RSA_ENCRYPT_EXP", "CSRF_RAND_CODE", "RndImg")
	initial := f["TwfID"]
	if initial == "" {
		return "", fmt.Errorf("%w: %w: login_auth.csp 缺少 TwfID", vpnerr.ErrAuth, ErrBadResponse)
	}
	key, exp, csrf := f["RSA_ENCRYPT_KEY"], f["RSA_ENCRYPT_EXP"], f["CSRF_RAND_CODE"]

	// 部分网关两处返回不一致，以最后一次拿到的为准（docs/02 §1.1）。
	if b2, status, err := c.get(ctx, "/public/psw_config", initial); err == nil && status == http.StatusOK {
		f2 := extractFields(b2, "RSA_ENCRYPT_KEY", "RSA_ENCRYPT_EXP", "CSRF_RAND_CODE")
		if v := f2["RSA_ENCRYPT_KEY"]; v != "" {
			if v != key {
				c.log.Debug("psw_config 公钥与 login_auth 不同，以 psw_config 为准")
			}
			key = v
		}
		if v := f2["RSA_ENCRYPT_EXP"]; v != "" {
			exp = v
		}
		if v := f2["CSRF_RAND_CODE"]; v != "" {
			csrf = v
		}
	} else if err != nil {
		c.log.Debug("psw_config 不可用，沿用 login_auth 的公钥", "err", err)
	}
	if key == "" || csrf == "" {
		return "", fmt.Errorf("%w: %w: 缺少 RSA_ENCRYPT_KEY 或 CSRF_RAND_CODE", vpnerr.ErrAuth, ErrBadResponse)
	}
	if exp == "" {
		exp = "65537"
	}
	logx.Assumption(c.log, "rsa_exp", exp)
	if f["RndImg"] == "1" && req.Captcha == "" {
		return "", fmt.Errorf("%w: %w（当前版本不支持获取验证码图片）", vpnerr.ErrAuth, ErrCaptchaRequired)
	}

	cipher, err := wire.EncryptPassword(rand.Reader, req.Password, csrf, key, exp)
	if err != nil {
		return "", fmt.Errorf("%w: %w", vpnerr.ErrAuth, err)
	}
	form := url.Values{}
	form.Set("svpn_name", req.User)
	form.Set("svpn_password", cipher)
	form.Set("svpn_req_randcode", csrf)
	randCode := ""
	if c.o.SendRandCode && req.Captcha != "" {
		randCode = wire.MD5Lower(req.Captcha)
	}
	form.Set("svpn_rand_code", randCode)
	form.Set(c.o.MitmField, "1")
	if req.DeviceID != "" {
		field := c.o.DeviceIDField
		if field == "" {
			field = "devid"
		}
		logx.Assumption(c.log, "device_id_field", field, "devid", logx.Mask(req.DeviceID))
		form.Set(field, req.DeviceID)
	}

	resp, err := c.do(ctx, http.MethodPost, "/por/login_psw.csp?anti_replay=1&encrypt=1", initial,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", &RejectError{Code: strconv.Itoa(resp.StatusCode), Message: "HTTP " + resp.Status}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: %w: login_psw.csp HTTP %d", vpnerr.ErrAuth, ErrBadResponse, resp.StatusCode)
	}
	rf := extractFields(rb, "TwfID", "Result", "ErrorCode", "Message", "Note", "NextAuth", "NextService")
	newID := rf["TwfID"]
	for _, ck := range resp.Cookies() {
		if strings.EqualFold(ck.Name, "TWFID") && ck.Value != "" {
			newID = ck.Value
		}
	}
	msg := firstNonEmpty(rf["Message"], rf["Note"])
	code := firstNonEmpty(rf["ErrorCode"], rf["Result"])
	ok := rf["Result"] == "1" || rf["ErrorCode"] == "1"
	logx.Assumption(c.log, "login_next_auth", rf["NextAuth"], "next_service", rf["NextService"], "twfid_in_response", newID != "")
	if ok && rf["NextAuth"] != "" && rf["NextAuth"] != "-1" {
		return "", fmt.Errorf("%w: %w（NextAuth=%s NextService=%s）", vpnerr.ErrAuth, ErrSecondFactor, rf["NextAuth"], rf["NextService"])
	}
	switch {
	case newID != "" && newID != initial:
		return newID, nil
	case ok:
		// docs/02 §4 要求新旧令牌不同；实测 M7.6.8R2 成功后响应里不带 TwfID，沿用 login_auth 的令牌。
		logx.Assumption(c.log, "login_same_twfid", true)
		c.log.Warn("登录响应沿用了原令牌，依据成功码判定为成功", "result", rf["Result"], "error_code", rf["ErrorCode"])
		return initial, nil
	default:
		return "", &RejectError{Code: code, Message: msg}
	}
}

// FetchConf 拉取 conf.csp（docs/09 §3）。
func (c *Client) FetchConf(ctx context.Context, token string) (Conf, []string, error) {
	b, err := c.authedGet(ctx, "/por/conf.csp", token)
	if err != nil {
		return Conf{}, nil, err
	}
	conf, warns := ParseConf(b)
	return conf, warns, nil
}

// FetchResources 拉取 rclist.csp，内网网段与域名后缀的唯一服务端来源（docs/09 §4）。
func (c *Client) FetchResources(ctx context.Context, token string) (Resources, error) {
	b, err := c.authedGet(ctx, "/por/rclist.csp", token)
	if err != nil {
		return Resources{}, err
	}
	format, entries := ParseResources(b)
	logx.Assumption(c.log, "rclist_format", format, "entries", len(entries))
	r := Normalize(entries)
	if len(r.Skipped) > 0 {
		c.log.Warn("资源列表中有无法识别的条目，已跳过", "count", len(r.Skipped), "entries", r.Skipped)
	}
	return r, nil
}

func (c *Client) authedGet(ctx context.Context, path, token string) ([]byte, error) {
	b, status, err := c.get(ctx, path, token)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden || (status >= 300 && status < 400):
		return nil, fmt.Errorf("%w: %w (%s HTTP %d)", vpnerr.ErrAuth, ErrSessionExpired, path, status)
	case status != http.StatusOK:
		return nil, fmt.Errorf("%w: %s HTTP %d", ErrBadResponse, path, status)
	}
	return b, nil
}

func (c *Client) get(ctx context.Context, path, token string) ([]byte, int, error) {
	resp, err := c.do(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, err
}

func (c *Client) do(ctx context.Context, method, path, token string, body io.Reader) (*http.Response, error) {
	u := c.base.String() + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		// docs/02 §1 规定 TWFID 请求头；常见网关实际读 Cookie，两者都带，互不冲突。
		req.Header.Set("TWFID", token)
		req.AddCookie(&http.Cookie{Name: "TWFID", Value: token})
	}
	req.Header.Set("User-Agent", "vpnkit")
	c.log.Debug("HTTP 请求", "method", method, "path", strings.SplitN(path, "?", 2)[0])
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	c.log.Debug("HTTP 响应", "path", strings.SplitN(path, "?", 2)[0], "status", resp.StatusCode)
	return resp, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
