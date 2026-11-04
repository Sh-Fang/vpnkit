// Package testserver 是实现同样线格式的假网关（docs/11 §2），覆盖 P1–P4 全部离线测试。
package testserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// AuthConfig 控制假网关认证端的行为。
type AuthConfig struct {
	Users map[string]string // 账号 → 密码
	// PswConfigDifferentKey 让 /public/psw_config 返回另一把公钥，测试"以最后一次为准"（docs/02 §6）。
	PswConfigDifferentKey bool
	// NoPswConfig 让 /public/psw_config 返回 404。
	NoPswConfig bool
	// OmitTwfID 让 login_auth.csp 不返回 TwfID，测试格式错误分支。
	OmitTwfID bool
	// KeepTwfID 模拟 M7.6.8R2：登录成功只回 ErrorCode=1，不发新令牌，沿用 login_auth 的 TwfID。
	KeepTwfID bool
	// NextAuth 非空时登录成功响应带 <NextAuth>，测试二次认证分支。
	NextAuth string
	// NextService 非空时随 NextAuth 一起下发；含 "hid" 时进入特征码登记流程（需后续提交 hid）。
	NextService string
	// HIDField 是特征码提交字段名，默认 svpn_inputhid；HIDExpectDevID 非空时校验提交的特征码。
	HIDField       string
	HIDExpectDevID string
	Captcha        bool
	ConfXML        string
	RCList         string
}

type hidState struct {
	csrf string
	user string
}

type pending struct {
	csrf string
	key  *rsa.PrivateKey
}

// AuthServer 实现 docs/11 §2.2 的认证端点。
type AuthServer struct {
	cfg        AuthConfig
	keyA, keyB *rsa.PrivateKey

	mu         sync.Mutex
	pending    map[string]pending
	hidPending map[string]hidState // twf → 等待 hid 提交的会话
	sessions   map[string]string   // token → user
	lastForm   url.Values
	lastHID    url.Values
}

func NewAuthServer(cfg AuthConfig) (*AuthServer, error) {
	a, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	b, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	if cfg.ConfXML == "" {
		cfg.ConfXML = ConfXML(443)
	}
	if cfg.HIDField == "" {
		cfg.HIDField = "svpn_inputhid"
	}
	return &AuthServer{cfg: cfg, keyA: a, keyB: b, pending: map[string]pending{}, hidPending: map[string]hidState{}, sessions: map[string]string{}}, nil
}

// ConfXML 返回 docs/09 §3 形态的 conf.csp，隧道端口指向 tunnelPort。
func ConfXML(tunnelPort int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<Conf>
  <Mline  enable="0" number="0" list="" interval="5" timeout="10"/>
  <Htp    enable="0" auto="1" param="7|0|1|200|100" port="%d" mtu="1400"/>
  <Bandwidth recvlimit="0" sendlimit="0"/>
  <TcpApplication userMode="1" compress="0" maxthread="50" maxsession="2"/>
  <L3VPN  iptunDns="10.8.0.53" iptunDnsBak="0.0.0.0"/>
  <Other  login_name="test" sddn_enable="0" enableAutoRelogin="0" isHidUser="0"/>
</Conf>`, tunnelPort)
}

// RCListXML 把条目拼成 <Rc host="..."> 形态的资源列表。
func RCListXML(entries ...string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="utf-8"?><Resource><Rcs>`)
	for i, e := range entries {
		fmt.Fprintf(&sb, `<Rc id="%d" name="r%d" type="2" proto="-1" svc="" host="%s" port="0" />`, i+1, i+1, e)
	}
	sb.WriteString(`</Rcs></Resource>`)
	return sb.String()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidToken 供隧道端校验 clientMsg 中的会话令牌。
func (s *AuthServer) ValidToken(t string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[t]
	return ok
}

// AddSession 直接登记一个有效令牌（隧道测试跳过 HTTP 登录时用）。
func (s *AuthServer) AddSession(token, user string) {
	s.mu.Lock()
	s.sessions[token] = user
	s.mu.Unlock()
}

// Revoke 使令牌失效，测试过期分支。
func (s *AuthServer) Revoke(t string) {
	s.mu.Lock()
	delete(s.sessions, t)
	s.mu.Unlock()
}

// LastLoginForm 返回最近一次 login_psw.csp 的表单（密码字段为密文）。
func (s *AuthServer) LastLoginForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastForm
}

func (s *AuthServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/por/login_auth.csp", s.loginAuth)
	mux.HandleFunc("/public/psw_config", s.pswConfig)
	mux.HandleFunc("/por/login_psw.csp", s.loginPsw)
	mux.HandleFunc("/por/login_hid.csp", s.loginHID)
	mux.HandleFunc("/por/conf.csp", s.authed(func(w http.ResponseWriter) { fmt.Fprint(w, s.cfg.ConfXML) }))
	mux.HandleFunc("/por/rclist.csp", s.authed(func(w http.ResponseWriter) { fmt.Fprint(w, s.cfg.RCList) }))
	return mux
}

func token(r *http.Request) string {
	if t := r.Header.Get("TWFID"); t != "" {
		return t
	}
	if c, err := r.Cookie("TWFID"); err == nil {
		return c.Value
	}
	return ""
}

func (s *AuthServer) loginAuth(w http.ResponseWriter, r *http.Request) {
	twf := randHex(8) // 16 个 ASCII 字符，正好填满 clientMsg 的令牌字段
	csrf := strings.ToUpper(randHex(8))
	s.mu.Lock()
	s.pending[twf] = pending{csrf: csrf, key: s.keyA}
	s.mu.Unlock()
	rnd := "0"
	if s.cfg.Captcha {
		rnd = "1"
	}
	twfXML := "<TwfID>" + twf + "</TwfID>"
	if s.cfg.OmitTwfID {
		twfXML = ""
	}
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><ErrorCode>1</ErrorCode><Message>auth success</Message>%s<RSA_ENCRYPT_KEY>%X</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>65537</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>%s</CSRF_RAND_CODE><RndImg>%s</RndImg></Auth>`,
		twfXML, s.keyA.N, csrf, rnd)
}

func (s *AuthServer) pswConfig(w http.ResponseWriter, r *http.Request) {
	if s.cfg.NoPswConfig {
		http.NotFound(w, r)
		return
	}
	twf := token(r)
	s.mu.Lock()
	p, ok := s.pending[twf]
	if ok && s.cfg.PswConfigDifferentKey {
		p.key = s.keyB
		s.pending[twf] = p
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	// JS 变量形态，覆盖解析器的正则兜底分支
	fmt.Fprintf(w, "var RSA_ENCRYPT_KEY = \"%X\";\nvar RSA_ENCRYPT_EXP = \"10001\";\nvar CSRF_RAND_CODE = \"%s\";\n", p.key.N, p.csrf)
}

func (s *AuthServer) loginPsw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	twf := token(r)
	s.mu.Lock()
	s.lastForm = r.PostForm
	p, ok := s.pending[twf]
	delete(s.pending, twf)
	s.mu.Unlock()
	fail := func(msg string) {
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>0</Result><ErrorCode>20021</ErrorCode><Message>%s</Message></Auth>`, msg)
	}
	if !ok {
		fail("invalid session")
		return
	}
	user := r.PostForm.Get("svpn_name")
	want, known := s.cfg.Users[user]
	ct, err := hex.DecodeString(r.PostForm.Get("svpn_password"))
	if err != nil || r.PostForm.Get("svpn_password") != strings.ToUpper(r.PostForm.Get("svpn_password")) {
		fail("password must be upper hex")
		return
	}
	// 真 RSA 解密，验证客户端加密是否正确（docs/11 §2.2）
	pt, err := rsa.DecryptPKCS1v15(nil, p.key, ct)
	if err != nil {
		fail("rsa decrypt failed")
		return
	}
	if r.PostForm.Get("svpn_req_randcode") != p.csrf {
		fail("csrf mismatch")
		return
	}
	if !known || string(pt) != want+"_"+p.csrf {
		fail("用户名或密码错误")
		return
	}
	// 特征码登记：成功后不立即发会话，改为下发 NextService=auth/hid + 新 CSRF，等 hid 提交。
	if s.cfg.NextAuth != "" && strings.Contains(s.cfg.NextService, "hid") {
		csrf := strings.ToUpper(randHex(8))
		s.mu.Lock()
		s.hidPending[twf] = hidState{csrf: csrf, user: user}
		s.mu.Unlock()
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><ErrorCode>1</ErrorCode><Message>Auth is success</Message><CurAuth>1</CurAuth><IsFirstAuth>1</IsFirstAuth><NextAuth>%s</NextAuth><NextService>%s</NextService><CSRF_RAND_CODE>%s</CSRF_RAND_CODE></Auth>`,
			s.cfg.NextAuth, s.cfg.NextService, csrf)
		return
	}
	if s.cfg.KeepTwfID || s.cfg.NextAuth != "" {
		s.mu.Lock()
		s.sessions[twf] = user
		s.mu.Unlock()
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><ErrorCode>1</ErrorCode><Message>Auth is success</Message><NextAuth>%s</NextAuth></Auth>`, s.cfg.NextAuth)
		return
	}
	newID := randHex(8)
	s.mu.Lock()
	s.sessions[newID] = user
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: newID})
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>1</Result><Message>login success</Message><TwfID>%s</TwfID></Auth>`, newID)
}

// loginHID 模拟特征码登记端点：GET 回一张声明字段的表单，POST 校验特征码与 CSRF 后发会话。
func (s *AuthServer) loginHID(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><Auth><NextService>auth/hid</NextService><`+s.cfg.HIDField+`/></Auth>`)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	twf := token(r)
	s.mu.Lock()
	s.lastHID = r.PostForm
	st, ok := s.hidPending[twf]
	s.mu.Unlock()
	fail := func(code, msg string) {
		fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>0</Result><ErrorCode>%s</ErrorCode><Message>%s</Message><Note>%s</Note></Auth>`, code, msg, msg)
	}
	if !ok {
		fail("30001", "no hid session")
		return
	}
	// 字段名不对返回 20210 submit param error，且保留待登记会话，让客户端换候选字段再试（镜像真机）。
	devid := r.PostForm.Get(s.cfg.HIDField)
	if devid == "" {
		fail("20210", "submit param error.")
		return
	}
	if r.PostForm.Get("svpn_req_randcode") != st.csrf {
		fail("20210", "submit param error.")
		return
	}
	s.mu.Lock()
	delete(s.hidPending, twf)
	s.mu.Unlock()
	if s.cfg.HIDExpectDevID != "" && devid != s.cfg.HIDExpectDevID {
		// 未登记的机器：进审批队列（非 param error，用别的错误码）。
		fail("30005", "设备未登记，已提交管理员审批")
		return
	}
	s.mu.Lock()
	s.sessions[twf] = st.user
	s.mu.Unlock()
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>1</Result><Message>hid auth success</Message></Auth>`)
}

// LastHIDForm 返回最近一次 hid 提交的表单。
func (s *AuthServer) LastHIDForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHID
}

func (s *AuthServer) authed(write func(http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.ValidToken(token(r)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		write(w)
	}
}
