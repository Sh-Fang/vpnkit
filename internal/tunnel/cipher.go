package tunnel

import (
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/Sh-Fang/vpnkit/internal/logx"
)

// Cipher 是数据面的流变换。RC4 状态跨包连续，上下行各一个实例（docs/05 §3.2）。
// 这是兼容性要求，只提供流量混淆，不提供机密性（docs/05 §4）。
type Cipher interface {
	XORKeyStream(dst, src []byte)
}

// KeySource 抽象 RC4 密钥来源（docs/05 §3.3）。派生算法未知，目前只有配置注入一种实现。
type KeySource interface {
	Key() ([]byte, error)
}

// StaticKey 是 tunnel.rc4_key_hex 注入的实验用密钥；空表示不支持加密。
type StaticKey string

func (k StaticKey) Key() ([]byte, error) {
	if k == "" {
		return nil, ErrEncryptionUnsupported
	}
	b, err := hex.DecodeString(string(k))
	if err != nil || len(b) == 0 || len(b) > 256 {
		return nil, fmt.Errorf("tunnel.rc4_key_hex 非法（需 1–256 字节 hex）")
	}
	return b, nil
}

// NewCiphers 按 SEND_IP 的 enc 字段创建上下行密码器；enc == 0 时返回 nil（不加密）。
func NewCiphers(enc uint32, ks KeySource, log *slog.Logger) (up, down Cipher, err error) {
	if enc == 0 {
		logx.Assumption(log, "rc4_key", "none", "enc", enc)
		return nil, nil, nil
	}
	key, err := ks.Key()
	if err != nil {
		return nil, nil, tunnelErr(err, "SEND_IP enc=%d", enc)
	}
	logx.Assumption(log, "rc4_key", "injected", "enc", enc, "key_len", len(key))
	u, err := rc4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	d, err := rc4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	return u, d, nil
}
