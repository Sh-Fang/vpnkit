// Package tunnel 实现隧道握手、数据帧收发与 RC4（docs/03、docs/05）。
package tunnel

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// Templates 是可替换的握手模板（docs/03 §2.4）。
// 模板能否被网关接受无法离线判定；集中在这里，联调失效时只换这一处。
type Templates struct {
	ClientHello     []byte
	CCSFinished     []byte
	ClientMsgPrefix [8]byte
}

// DefaultTemplates 返回 docs/03 §2、§4.1 的原样模板。
func DefaultTemplates() Templates {
	return Templates{
		ClientHello:     wire.BuildClientHello(),
		CCSFinished:     wire.BuildCCSFinished(),
		ClientMsgPrefix: wire.DefaultClientMsgPrefix(),
	}
}

// Fingerprint 用于 assumption=handshake_template 日志：一眼看出用的是不是默认模板。
func (t Templates) Fingerprint() string {
	h := sha256.New()
	h.Write(t.ClientHello)
	h.Write(t.CCSFinished)
	sum := h.Sum(nil)
	name := "custom"
	d := DefaultTemplates()
	if string(t.ClientHello) == string(d.ClientHello) && string(t.CCSFinished) == string(d.CCSFinished) {
		name = "docs03-v1"
	}
	return name + ":" + hex.EncodeToString(sum[:6])
}
