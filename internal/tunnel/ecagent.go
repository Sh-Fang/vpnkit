package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// AgentTokenLen 是隧道凭据前段的长度（docs/03 §4.4）。
const AgentTokenLen = 32

// ErrNoSessionID 表示网关的 ServerHello 里没有 session id，取不到 agentToken。
var ErrNoSessionID = errors.New("网关 ServerHello 没有 session id，无法取得隧道凭据前段")

// serverHelloRequest 是取 agentToken 时要发的请求，逐字节照抄可用实现的做法：
// 一条连接上流水线发两个 GET，只读回前几字节确认服务端已受理。
const serverHelloRequest = "GET /por/conf.csp HTTP/1.1\r\nHost: %s\r\nCookie: TWFID=%s\r\n\r\n" +
	"GET /por/rclist.csp HTTP/1.1\r\nHost: %s\r\nCookie: TWFID=%s\r\n\r\n"

// AgentToken 推导隧道凭据的前 32 字节（docs/03 §4.4）。
//
// 网关把隧道凭据拆成两段：前段是"这条 TLS 会话"的标识，后段才是登录拿到的令牌。
// 前段的来源很反直觉——在一条**真实** TLS 连接上带 TWFID 请求 conf/rclist，
// 然后读 ServerHello 里的 session id，转成十六进制取前 31 个字符，末尾留一个 0x00。
//
// 末位恒为 0 而不是第 32 个 hex 字符：那 32 字节在网关侧是 C 字符串缓冲区，
// 最后一个字节留给结束符。照抄整数个 hex 字符会得到 32 个字符，看起来只差一位，
// 实际整个凭据都不对。
//
// 必须把 TLS 上限压到 1.2：TLS 1.3 的 ServerHello 里那个字段只是客户端随机数的回显，
// 服务端不分配会话，取出来的值没有意义。
func AgentToken(ctx context.Context, addr, twfID string, dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) ([AgentTokenLen]byte, error) {
	var out [AgentTokenLen]byte
	if twfID == "" {
		return out, fmt.Errorf("%w: 没有登录令牌", ErrNoSessionID)
	}
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dial(dctx, "tcp", addr)
	if err != nil {
		return out, fmt.Errorf("连接 %s: %w", addr, err)
	}
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	tap := &tapConn{Conn: raw}
	tc := tls.Client(tap, &tls.Config{
		InsecureSkipVerify: true, // 这一步只要 session id，不承载任何机密数据
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	})
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.HandshakeContext(dctx); err != nil {
		return out, fmt.Errorf("TLS 握手: %w", err)
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	req := fmt.Sprintf(serverHelloRequest, host, twfID, host, twfID)
	if _, err := io.WriteString(tc, req); err != nil {
		return out, fmt.Errorf("发送 conf/rclist 请求: %w", err)
	}
	// 必须读到东西再取 session id：服务端要先受理请求，绑定才会落到这条会话上。
	// 顺带校验状态行——令牌已失效时网关照样做完 TLS 握手，不查就会把"令牌过期"
	// 拖到隧道建连阶段才暴露成一条无关的握手错误。
	br := bufio.NewReader(tc)
	line, err := br.ReadString('\n')
	if err != nil {
		return out, fmt.Errorf("读取 conf/rclist 响应: %w", err)
	}
	if !strings.HasPrefix(line, "HTTP/") || !strings.Contains(line, " 200") {
		return out, fmt.Errorf("%w: conf/rclist 返回 %q", ErrNoSessionID, strings.TrimSpace(line))
	}

	sid, err := ServerHelloSessionID(tap.ServerBytes())
	if err != nil {
		return out, err
	}
	return DeriveAgentToken(sid)
}

// DeriveAgentToken 按 docs/03 §4.4 把 session id 转成 32 字节凭据前段。
func DeriveAgentToken(sid []byte) ([AgentTokenLen]byte, error) {
	var out [AgentTokenLen]byte
	if len(sid) == 0 {
		return out, ErrNoSessionID
	}
	h := hex.EncodeToString(sid)
	if len(h) < AgentTokenLen-1 {
		return out, fmt.Errorf("%w: session id 只有 %d 字节，十六进制不足 %d 字符",
			ErrNoSessionID, len(sid), AgentTokenLen-1)
	}
	// 前 31 个字符 + 1 个结束符，正好 32 字节；out[31] 保持 0。
	copy(out[:], h[:AgentTokenLen-1])
	return out, nil
}

// ServerHelloSessionID 从服务端方向的原始字节流里取出 ServerHello 的 session id。
//
// 只做最小解析：按记录头切分，跳过非 handshake 记录，找到 handshake 类型 2
// （ServerHello）后读 session_id_len 及其后的会话 id。Certificate 等后续消息不碰。
func ServerHelloSessionID(raw []byte) ([]byte, error) {
	for i := 0; i+5 <= len(raw); {
		typ := raw[i]
		n := int(binary.BigEndian.Uint16(raw[i+3 : i+5]))
		if i+5+n > len(raw) {
			return nil, fmt.Errorf("记录不完整：声明 %d 字节，只剩 %d", n, len(raw)-i-5)
		}
		if typ == 22 { // handshake
			if sid, ok, err := scanHandshakes(raw[i+5 : i+5+n]); err != nil {
				return nil, err
			} else if ok {
				// TLS 1.3 下服务端不分配会话，这个字段只是客户端随机数的回显。
				if len(sid) == 0 {
					return nil, ErrNoSessionID
				}
				return sid, nil
			}
		}
		i += 5 + n
	}
	return nil, ErrNoSessionID
}

func scanHandshakes(p []byte) ([]byte, bool, error) {
	for len(p) >= 4 {
		typ := p[0]
		n := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
		if len(p) < 4+n {
			return nil, false, nil // 这条记录里只有半条消息，交给上层按记录继续切
		}
		if typ == 2 { // ServerHello
			m := p[4 : 4+n]
			if len(m) < 35 {
				return nil, false, fmt.Errorf("ServerHello 过短：%d 字节", len(m))
			}
			ln := int(m[34])
			if len(m) < 35+ln {
				return nil, false, fmt.Errorf("ServerHello 声明 session id %d 字节，实际只有 %d", ln, len(m)-35)
			}
			return m[35 : 35+ln], true, nil
		}
		p = p[4+n:]
	}
	return nil, false, nil
}

// tapConn 旁路记录服务端方向的原始字节，供解析 ServerHello。
// 只保留头部若干字节：session id 一定出现在第一批记录里，不必留全量。
type tapConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

const tapLimit = 8 << 10

func (t *tapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.mu.Lock()
		if len(t.buf) < tapLimit {
			room := tapLimit - len(t.buf)
			if n < room {
				room = n
			}
			t.buf = append(t.buf, p[:room]...)
		}
		t.mu.Unlock()
	}
	return n, err
}

// ServerBytes 返回旁路记录到的服务端字节副本。
func (t *tapConn) ServerBytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]byte, len(t.buf))
	copy(out, t.buf)
	return out
}
