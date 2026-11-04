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
	ErrNeedDeviceID    = errors.New("网关要求特征码登记，但未能取得本机特征码")
	ErrDevicePending   = errors.New("特征码已提交，等待网关管理员审批后再登录")
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
	// auth/hid 二次认证（特征码登记）参数，线格式待联调（docs/02 §4）。
	RegisterDevice bool
	HIDEndpoint    string
	HIDQuery       string
	HIDField       string
	Logger         *slog.Logger
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
	if o.HIDEndpoint == "" {
		o.HIDEndpoint = "/por/login_hid.csp"
	}
	if o.HIDQuery == "" {
		o.HIDQuery = "apiversion=1"
	}
	if o.HIDField == "" {
		o.HIDField = "svpn_inputhid"
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
	// auth/hid 登记时与特征码并列上报的本机信息（官方模板变量 macaddress/hostname）。
	MACAddress string
	Hostname   string
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
	rf := extractFields(rb, "TwfID", "Result", "ErrorCode", "Message", "Note", "NextAuth", "NextService", "CSRF_RAND_CODE")
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
		// 还不知道 auth/hid 这一步要提交哪些字段。先把响应体里声明的标签名全部记下来，
		// 再记几个描述性字段的值（CSRF 只记有无、不记原值），联调时据此确定提交协议（docs/02 §4）。
		logx.Assumption(c.log, "hid_response_tags", strings.Join(tagNames(rb), ","))
		hf := extractFields(rb, "CurAuth", "NextServiceSubType", "ChallengeMsg", "AuthInfo", "IsFirstAuth", "EnableMAM", "LBEnabled")
		logx.Assumption(c.log, "hid_probe", hf["NextServiceSubType"],
			"cur_auth", hf["CurAuth"], "challenge", hf["ChallengeMsg"], "auth_info", hf["AuthInfo"],
			"is_first_auth", hf["IsFirstAuth"], "enable_mam", hf["EnableMAM"],
			"lb_enabled", hf["LBEnabled"], "csrf_present", rf["CSRF_RAND_CODE"] != "")
		// auth/hid 是硬件特征码登记（docs/06）。仅在用户显式开启 register_device 时提交本机特征码，
		// 否则沿用原行为报错——避免普通登录静默把机器登记进网关的设备绑定队列。
		if isHIDService(rf["NextService"]) && c.o.RegisterDevice {
			return c.submitHID(ctx, initial, rf["CSRF_RAND_CODE"], req)
		}
		hint := ""
		if isHIDService(rf["NextService"]) {
			hint = "；这是特征码设备登记，加 --register-device 可提交本机特征码"
		}
		return "", fmt.Errorf("%w: %w（NextAuth=%s NextService=%s）%s", vpnerr.ErrAuth, ErrSecondFactor, rf["NextAuth"], rf["NextService"], hint)
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

// isHIDService 判断二次认证是否为硬件特征码登记（NextService=auth/hid）。
func isHIDService(s string) bool {
	return strings.Contains(strings.ToLower(s), "hid")
}

// hidParamErrCode 是深信服 "submit param error"，表示提交字段不对（而非拒绝登记），换候选字段再试。
const hidParamErrCode = "20210"

// submitHID 提交本机特征码完成 auth/hid 登记（docs/02 §4、docs/06）。
// 字段名线格式无处可查：先用配置值，网关报 param error 时按命名规律 svpn_input<service> 依次换候选，
// 一次运行内定位正确字段，避免反复真机联调。每次尝试的请求/响应结构都打日志（令牌掩码）。
func (c *Client) submitHID(ctx context.Context, token, csrf string, req LoginRequest) (string, error) {
	if req.DeviceID == "" {
		return "", fmt.Errorf("%w: %w", vpnerr.ErrAuth, ErrNeedDeviceID)
	}
	var last error
	for _, field := range dedupStrings(c.o.HIDField, "svpn_inputhid", "svpn_hid", "svpn_hardid", "hid", "hardid") {
		tok, retry, err := c.tryHID(ctx, token, csrf, field, req)
		if err == nil {
			return tok, nil
		}
		last = err
		if !retry {
			return "", err
		}
		c.log.Debug("hid 字段名被网关拒为 param error，换下一候选", "field", field)
	}
	return "", fmt.Errorf("%w: hid 登记失败，候选字段名都被网关拒为 param error，真实字段名需进一步联调：%w", vpnerr.ErrAuth, last)
}

// tryHID 用字段名 field 提交一次特征码。retry=true 表示网关报 param error（字段名可能不对），可换候选再试。
func (c *Client) tryHID(ctx context.Context, token, pswCSRF, field string, req LoginRequest) (tok string, retry bool, err error) {
	// hid 请求对齐 sms 流程带 ?apiversion=1 查询串（docs/02 §4）。
	hidPath := c.o.HIDEndpoint
	if c.o.HIDQuery != "" {
		hidPath += "?" + c.o.HIDQuery
	}
	// 深信服每一步认证页发自己的 CSRF，POST 要回显这一步的 CSRF，不能用上一步 login_psw 的。
	// 顺带取 AuthInfo/Note 找字段名线索。GET 只读、不写入。
	getCSRF := ""
	if b, status, gerr := c.get(ctx, hidPath, token); gerr == nil {
		gf := extractFields(b, "CSRF_RAND_CODE", "AuthInfo", "Note", "Message")
		getCSRF = gf["CSRF_RAND_CODE"]
		logx.Assumption(c.log, "hid_get", hidPath, "status", status,
			"csrf_present", getCSRF != "", "auth_info", gf["AuthInfo"], "note", gf["Note"],
			"message", gf["Message"], "tags", strings.Join(tagNames(b), ","))
		// --trace 时打完整 XML（含属性），CSRF 掩码；联调看清 hid 页到底要什么参数。
		logx.Trace(c.log, "hid_get_body", "body", maskCSRFBody(b))
	} else {
		c.log.Debug("hid 端点只读探测失败，直接提交", "err", gerr)
	}
	csrfToSend := firstNonEmpty(getCSRF, pswCSRF)

	form := url.Values{}
	form.Set(field, req.DeviceID)
	// 官方模板变量 macaddress/hostname 与 hid 并列，网关可能要三个一起带（docs/06 §6）。
	if req.MACAddress != "" {
		form.Set("macaddress", req.MACAddress)
	}
	if req.Hostname != "" {
		form.Set("hostname", req.Hostname)
	}
	if csrfToSend != "" {
		form.Set("svpn_req_randcode", csrfToSend)
	}
	// body 提交此前一律被判 20210，故把同一组参数也拼进 URL 查询串（部分 .csp 只从 query 读参数）。
	// body 不变，若此次成功即可归因于 query（docs/02 §4）。
	postPath := hidPath
	sep := "?"
	if strings.Contains(postPath, "?") {
		sep = "&"
	}
	postPath += sep + form.Encode()
	// 注意：postPath 的查询串含明文特征码/MAC，绝不入日志；只打不含参数的 hidPath。
	logx.Assumption(c.log, "hid_submit", hidPath,
		"field", field, "devid", logx.Mask(req.DeviceID), "mac", logx.Mask(req.MACAddress),
		"hostname", req.Hostname, "csrf_sent", csrfToSend != "", "csrf_from_get", getCSRF != "", "params_in", "query+body")

	resp, err := c.do(ctx, http.MethodPost, postPath, token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("%w: %w: %s HTTP %d", vpnerr.ErrAuth, ErrBadResponse, c.o.HIDEndpoint, resp.StatusCode)
	}
	rf := extractFields(rb, "TwfID", "Result", "ErrorCode", "Message", "Note", "NextAuth", "NextService")
	newID := rf["TwfID"]
	for _, ck := range resp.Cookies() {
		if strings.EqualFold(ck.Name, "TWFID") && ck.Value != "" {
			newID = ck.Value
		}
	}
	ok := rf["Result"] == "1" || rf["ErrorCode"] == "1"
	logx.Assumption(c.log, "hid_result", rf["Result"],
		"field", field, "error_code", rf["ErrorCode"], "next_auth", rf["NextAuth"], "message", rf["Message"],
		"twfid_in_response", newID != "", "tags", strings.Join(tagNames(rb), ","))
	switch {
	case ok && (rf["NextAuth"] == "" || rf["NextAuth"] == "-1"):
		if newID != "" {
			return newID, false, nil
		}
		return token, false, nil // 多数场景沿用原令牌（docs/02 §4）
	case ok:
		return "", false, fmt.Errorf("%w: %w（hid 后仍需 NextAuth=%s NextService=%s）", vpnerr.ErrAuth, ErrSecondFactor, rf["NextAuth"], rf["NextService"])
	case rf["ErrorCode"] == hidParamErrCode:
		return "", true, fmt.Errorf("%w: hid 字段 %q 被网关拒为 param error", vpnerr.ErrAuth, field)
	default:
		// 失败且非 param error：多为进入管理员审批队列。把网关可读消息透传给用户。
		return "", false, fmt.Errorf("%w: %w（网关消息：%s）", vpnerr.ErrAuth, ErrDevicePending, firstNonEmpty(rf["Message"], rf["Note"], "无"))
	}
}

// dedupStrings 去空、去重，保持首次出现顺序。
func dedupStrings(ss ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
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
