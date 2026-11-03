package tunnel

import (
	"encoding/hex"
	"fmt"

	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// EncodeToken 把会话令牌填成 clientMsg 的 16 字节字段（docs/03 §4.1）。
// 默认 ASCII 原文；hex 时解码后填入。长度不符报 ErrTokenLength，不截断、不补零。
func EncodeToken(token, encoding string) ([wire.TokenLen]byte, error) {
	var out [wire.TokenLen]byte
	var raw []byte
	switch encoding {
	case "", "ascii":
		raw = []byte(token)
	case "hex":
		b, err := hex.DecodeString(token)
		if err != nil {
			return out, tunnelErr(ErrTokenLength, "token_encoding=hex 但令牌不是合法 hex")
		}
		raw = b
	default:
		return out, fmt.Errorf("未知 token_encoding %q", encoding)
	}
	if len(raw) != wire.TokenLen {
		return out, tunnelErr(ErrTokenLength, "编码 %s 后长度 %d，需要 %d；可尝试 tunnel.token_encoding", encodingName(encoding), len(raw), wire.TokenLen)
	}
	copy(out[:], raw)
	return out, nil
}

func encodingName(e string) string {
	if e == "" {
		return "ascii"
	}
	return e
}
