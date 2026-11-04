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

// 特征码二次认证的线格式常量（docs/02 §4）。官方客户端把 type/language/encrypt 三个
// 公共参数挂在每个认证请求的查询串上，`login_hid.csp` 的 body 只放特征码本身。
const (
	DefaultHIDQuery = "manual_submit=1"
	DefaultHIDField = "hid"
)

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
	// auth/hid 二次认证（特征码登记）参数，线格式取自官方客户端（docs/02 §4）。
	RegisterDevice bool
	HIDEndpoint    string // 认证这步：POST body 只带特征码
	HIDQuery       string // 上面的固定查询串，官方客户端每个认证请求都带
	HIDField       string // 特征码表单字段名
	// 提交设备绑定申请（进管理员审批队列）的端点，参数走查询串（docs/02 §4.3）。
	SubmitHIDEndpoint string
	// 特征码页端点，只在诊断时只读 GET（docs/02 §4.1）。
	HardIDEndpoint string
	HIDLanguage    string
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
		o.HIDQuery = DefaultHIDQuery
	}
	if o.HIDField == "" {
		o.HIDField = DefaultHIDField
	}
	if o.SubmitHIDEndpoint == "" {
		o.SubmitHIDEndpoint = "/por/submithid.csp"
	}
	if o.HardIDEndpoint == "" {
		o.HardIDEndpoint = "/por/hardid.csp"
	}
	if o.HIDLanguage == "" {
		o.HIDLanguage = "zh_CN"
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
	return c.login(ctx, req, 0)
}

// login 是 Login 的实现；depth 限制「提交设备绑定后重跑登录」的递归深度，最多重跑一次。
func (c *Client) login(ctx context.Context, req LoginRequest, depth int) (string, error) {
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
		// auth/hid 是硬件特征码二次认证（docs/02 §4、docs/06）。仅在用户显式开启 register_device
		// 时提交本机特征码，否则报错——避免普通登录静默把机器登记进网关的设备绑定队列。
		if isHIDStep(rf["NextAuth"], rf["NextService"]) && c.o.RegisterDevice {
			return c.completeHID(ctx, initial, rf["CSRF_RAND_CODE"], req, depth)
		}
		hint := ""
		if isHIDStep(rf["NextAuth"], rf["NextService"]) {
			hint = "；这是特征码二次认证，加 --register-device 可提交本机特征码"
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

// isHIDStep 判断二次认证是否为硬件特征码这步（docs/02 §4）。
// 官方客户端按数字 NextAuth 选处理器，4 就是特征码；部分网关同时下发 NextService=auth/hid。
func isHIDStep(nextAuth, nextService string) bool {
	if strings.Contains(strings.ToLower(nextService), "hid") {
		return true
	}
	return nextAuth == "4"
}

// hidParamErrCode 是网关的 "submit param error"，表示这次提交的内容不被接受（docs/02 §4）。
const hidParamErrCode = "20210"

// hidPath 返回特征码认证请求的完整路径（固定查询串 + 端点，不含任何秘密）。
func (c *Client) hidPath() string {
	if c.o.HIDQuery == "" {
		return c.o.HIDEndpoint
	}
	sep := "?"
	if strings.Contains(c.o.HIDEndpoint, "?") {
		sep = "&"
	}
	return c.o.HIDEndpoint + sep + c.o.HIDQuery
}

func (c *Client) hidLanguage() string {
	if c.o.HIDLanguage != "" {
		return c.o.HIDLanguage
	}
	return "zh_CN"
}

// submitHID 提交本机特征码，完成 auth/hid 这步二次认证（docs/02 §4.1、docs/06）。
//
// 请求形状取自 Web 端 SDK 的 loginHid：POST {endpoint}?manual_submit=1，
// 表单体四个字段 hid / hostname / macaddress / ignore。
//
// 网关判 20210（submit param error）时会在响应里回一个新的 CSRF_RAND_CODE——
// 这是反重放握手的重试信号，带上它再试一次即可，不能无限重试。
func (c *Client) submitHID(ctx context.Context, token, csrf string, req LoginRequest) (string, error) {
	if req.DeviceID == "" {
		return "", fmt.Errorf("%w: %w", vpnerr.ErrAuth, ErrNeedDeviceID)
	}
	var res authResult
	for attempt := 0; ; attempt++ {
		var err error
		res, err = c.postHID(ctx, token, csrf, req)
		if err != nil {
			return "", err
		}
		if res.code != hidParamErrCode {
			break
		}
		fresh := res.fields["CSRF_RAND_CODE"]
		if attempt >= 1 || fresh == "" || fresh == csrf {
			break
		}
		c.log.Debug("特征码这步被判 param error，带上网关刚发的 CSRF 重试一次")
		csrf = fresh
	}
	logx.Assumption(c.log, "hid_result", res.fields["Result"],
		"error_code", res.code, "next_auth", res.fields["NextAuth"], "message", res.message,
		"twfid_in_response", res.token != "")
	if !res.ok {
		if res.code == hidParamErrCode {
			// 请求本身不合法：把网关那张特征码页读回来（只读 GET），它的回执最权威。
			c.dumpHIDPage(ctx, token)
			return "", fmt.Errorf("%w: %w（网关判 param error：字段 %q 或取值不被接受；"+
				"确认 auth.hid_field 与 auth.hid_query，特征码须为 32 位大写十六进制）",
				vpnerr.ErrAuth, ErrDevicePending, c.o.HIDField)
		}
		return "", fmt.Errorf("%w: %w（网关消息：%s）",
			vpnerr.ErrAuth, ErrDevicePending, firstNonEmpty(res.message, "无"))
	}
	if res.fields["NextAuth"] != "" && res.fields["NextAuth"] != "-1" {
		return "", fmt.Errorf("%w: %w（特征码通过后仍需 NextAuth=%s NextService=%s）",
			vpnerr.ErrAuth, ErrSecondFactor, res.fields["NextAuth"], res.fields["NextService"])
	}
	return firstNonEmpty(res.token, token), nil
}

// completeHID 走完特征码这步：先认证，认证不过再提交设备绑定，绑定成功后重跑一次登录。
//
// 为什么要重跑：网关的特征码页明确写着「直接点击下方提交即可，会自动审核」——
// 即设备绑定是独立的一步，认证通过与否取决于「这台机器在不在册」。提交成功之后
// 重新走一遍密码登录，这一回网关就不再要特征码了（docs/02 §4.2）。
func (c *Client) completeHID(ctx context.Context, token, csrf string, req LoginRequest, depth int) (string, error) {
	tok, authErr := c.submitHID(ctx, token, csrf, req)
	if authErr == nil {
		return tok, nil
	}
	if depth >= 1 || req.DeviceID == "" {
		return "", authErr
	}
	if _, regErr := c.submitHIDRegistration(ctx, token, req); regErr != nil {
		if errors.Is(regErr, ErrDevicePending) {
			return "", regErr
		}
		c.log.Warn("提交设备绑定申请失败", "err", regErr)
		return "", authErr
	}
	c.log.Info("设备已提交绑定，重试一次登录")
	return c.login(ctx, req, depth+1)
}

// dumpHIDPage 取一次特征码页（GET /por/hardid.csp?manual_submit=1）。
// 这是只读请求，用来在 --trace 下看清网关实际要求的字段，避免继续猜。
func (c *Client) dumpHIDPage(ctx context.Context, token string) {
	if c.o.HardIDEndpoint == "" {
		return
	}
	path := c.o.HardIDEndpoint + "?manual_submit=1"
	b, status, err := c.get(ctx, path, token)
	if err != nil {
		c.log.Debug("读取特征码页失败", "err", err)
		return
	}
	logx.Assumption(c.log, "hardid_page", status, "bytes", len(b), "tags", strings.Join(tagNames(b), ","))
	logx.Trace(c.log, "hardid_page_body", "body", maskCSRFBody(b))
}

// postHID 发一次特征码认证请求。csrf 非空时一并回显（反重放握手）。
func (c *Client) postHID(ctx context.Context, token, csrf string, req LoginRequest) (authResult, error) {
	form := url.Values{}
	form.Set(c.o.HIDField, req.DeviceID)
	form.Set("hostname", req.Hostname)
	form.Set("macaddress", req.MACAddress)
	form.Set("ignore", "0")
	if csrf != "" {
		form.Set("svpn_req_randcode", csrf)
	}
	logx.Assumption(c.log, "hid_submit", c.hidPath(),
		"field", c.o.HIDField, "devid", logx.Mask(req.DeviceID),
		"hostname", req.Hostname, "mac", logx.Mask(req.MACAddress), "csrf_sent", csrf != "")
	return c.postAuthForm(ctx, c.hidPath(), token, form)
}

// submitHIDRegistration 提交设备绑定申请，让这台机器进管理员审批队列（docs/02 §4.3、docs/06 §6）。
//
// 请求形状取自官方客户端二进制：参数全部走查询串，
// /por/submithid.csp?type=cs&language=%s&hid=%s&hostname=%s&macaddress=%s&rnd=%u
// 其中 rnd 是毫秒级计数值，没有校验意义。返回的令牌与 hid 认证一样处理。
func (c *Client) submitHIDRegistration(ctx context.Context, token string, req LoginRequest) (string, error) {
	if req.DeviceID == "" {
		return "", fmt.Errorf("%w: %w", vpnerr.ErrAuth, ErrNeedDeviceID)
	}
	form := url.Values{}
	form.Set("hid", req.DeviceID)
	form.Set("hostname", req.Hostname)
	form.Set("macaddress", req.MACAddress)
	// 查询串里没有秘密，但特征码在表单体里，所以只记录端点名。
	logx.Assumption(c.log, "hid_register", c.o.SubmitHIDEndpoint,
		"devid", logx.Mask(req.DeviceID), "mac", logx.Mask(req.MACAddress), "hostname", req.Hostname)
	res, err := c.postAuthForm(ctx, c.o.SubmitHIDEndpoint, token, form)
	if err != nil {
		return "", err
	}
	if res.ok {
		c.log.Info("已提交设备绑定申请，等待网关管理员审批")
		return firstNonEmpty(res.token, token), nil
	}
	return "", fmt.Errorf("%w: %w（网关消息：%s）", vpnerr.ErrAuth, ErrDevicePending, firstNonEmpty(res.message, "无"))
}

// authResult 是一次认证请求响应的投影（docs/02 §4 各步共用的响应字段）。
type authResult struct {
	token   string // 网关换发的令牌；没有换发时为空
	ok      bool
	code    string
	message string
	fields  map[string]string
}

// postAuthForm 提交一个认证表单并解析响应。path 可含查询串。
func (c *Client) postAuthForm(ctx context.Context, path, token string, form url.Values, extra ...*http.Cookie) (authResult, error) {
	var res authResult
	resp, err := c.do(ctx, http.MethodPost, path, token, strings.NewReader(form.Encode()), extra...)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return res, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return res, fmt.Errorf("%w: %w", vpnerr.ErrAuth, ErrSessionExpired)
	}
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("%w: %w: %s HTTP %d", vpnerr.ErrAuth, ErrBadResponse,
			strings.SplitN(path, "?", 2)[0], resp.StatusCode)
	}
	res.fields = extractFields(rb, "TwfID", "Result", "ErrorCode", "Message", "Note",
		"NextAuth", "NextService", "CSRF_RAND_CODE")
	res.token = res.fields["TwfID"]
	for _, ck := range resp.Cookies() {
		if strings.EqualFold(ck.Name, "TWFID") && ck.Value != "" {
			res.token = ck.Value
		}
	}
	res.code = firstNonEmpty(res.fields["ErrorCode"], res.fields["Result"])
	res.message = firstNonEmpty(res.fields["Message"], res.fields["Note"])
	res.ok = res.fields["Result"] == "1" || res.fields["ErrorCode"] == "1"
	logx.Trace(c.log, "auth_response", "path", strings.SplitN(path, "?", 2)[0],
		"status", resp.StatusCode, "body", maskCSRFBody(rb))
	return res, nil
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

func (c *Client) do(ctx context.Context, method, path, token string, body io.Reader, extra ...*http.Cookie) (*http.Response, error) {
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
	for _, ck := range extra {
		req.AddCookie(ck)
	}
	req.Header.Set("User-Agent", "vpnkit")
	c.log.Debug("HTTP 请求", "method", method, "path", strings.SplitN(path, "?", 2)[0])
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s: %w%s", strings.SplitN(path, "?", 2)[0], err, certHint(err))
	}
	c.log.Debug("HTTP 响应", "path", strings.SplitN(path, "?", 2)[0], "status", resp.StatusCode)
	return resp, nil
}

// certHint 在证书校验失败时补一句可操作的提示，并打出服务端实际出示的指纹。
// 这类网关的出厂证书自签、只有 CN 没有 SAN，标准校验必然失败；用户拿到指纹后钉住即可，
// 比一律 --insecure 更安全（docs/02 §4 证书一节）。
func certHint(err error) string {
	var cve *tls.CertificateVerificationError
	if !errors.As(err, &cve) || len(cve.UnverifiedCertificates) == 0 {
		return ""
	}
	fp := sha256.Sum256(cve.UnverifiedCertificates[0].Raw)
	s := colonHex(fp[:])
	return fmt.Sprintf("；网关证书校验失败（自签或名字不匹配属常见情况）。"+
		"实际 SHA-256 指纹 %s，加 --cert-sha256 %s 只信任这一张证书；"+
		"确认网络可信时才用 --insecure 跳过校验", s, s)
}

// colonHex 把字节串格式化成大写、冒号分隔的十六进制。
func colonHex(b []byte) string {
	var sb strings.Builder
	for i, x := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
