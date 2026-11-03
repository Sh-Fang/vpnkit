package wire

import (
	"crypto/md5"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strings"
)

var (
	ErrBadPublicKey    = errors.New("wire: 网关下发的 RSA 公钥非法")
	ErrPasswordTooLong = errors.New("wire: 密码过长，超出 RSA 明文上限")
)

// EncryptPassword 实现 docs/02 §2 / docs/05 §1：
// hex_upper(RSA_PKCS1v15(password + "_" + csrf))。
// rnd 由调用方注入（生产传 crypto/rand.Reader），保持本包可测。
func EncryptPassword(rnd io.Reader, password, csrf, nHex, eHex string) (string, error) {
	n, ok := new(big.Int).SetString(strings.TrimSpace(nHex), 16)
	if !ok || n.Sign() <= 0 || n.Bit(0) == 0 || n.BitLen() < 512 {
		// 偶数模数或过短模数说明解析错了字段，绝不能静默降级（docs/05 §1）。
		return "", ErrBadPublicKey
	}
	e, ok := new(big.Int).SetString(strings.TrimSpace(eHex), 16)
	if !ok || e.Sign() <= 0 || !e.IsInt64() || e.Int64() > 1<<31-1 || e.Int64() < 3 {
		return "", ErrBadPublicKey
	}
	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	plain := []byte(password + "_" + csrf)
	if len(plain) > pub.Size()-11 {
		return "", ErrPasswordTooLong // 不截断
	}
	ct, err := rsa.EncryptPKCS1v15(rnd, pub, plain)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(ct)), nil
}

// MD5Upper 返回 32 位大写十六进制 MD5（docs/05 §2）。仅用于生成稳定短标识，不是安全摘要。
func MD5Upper(s string) string {
	sum := md5.Sum([]byte(s))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// MD5Lower 用于图形验证码字段（大小写以服务端为准，默认小写）。
func MD5Lower(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
