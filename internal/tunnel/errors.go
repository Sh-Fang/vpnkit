package tunnel

import (
	"errors"
	"fmt"

	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// 握手失败三分类（docs/00 §5 P2）：拒绝 / 超时 / 格式不符。
var (
	ErrHandshakeRejected     = errors.New("握手被拒绝（连接被对端关闭；疑似模板失效或会话过期）")
	ErrHandshakeTimeout      = errors.New("握手超时")
	ErrBadServerMsg          = wire.ErrBadServerMsg
	ErrTokenLength           = errors.New("会话令牌长度与 clientMsg 的 16 字节字段不符")
	ErrEncryptionUnsupported = errors.New("服务端要求加密，密钥派生未实现（可实验性配置 tunnel.rc4_key_hex）")
	ErrUnexpectedAck         = errors.New("数据通道应答码不符")
)

// tunnelErr 给具体错误挂上隧道类别（退出码 4）。
func tunnelErr(specific error, format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", vpnerr.ErrTunnel, specific, fmt.Sprintf(format, a...))
}
