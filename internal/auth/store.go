package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/internal/vpnerr"
)

// Session 是落盘的会话（docs/02 §5）。
type Session struct {
	Server      string    `json:"server"`
	Port        int       `json:"port,omitempty"`
	User        string    `json:"user"`
	TwfID       string    `json:"twfid"`
	ObtainedAt  time.Time `json:"obtained_at"`
	ExpiresHint int       `json:"expires_hint"`
	// IsHidUser 缓存上次 conf.csp 的 Other.isHidUser，供 send_device_id=auto 在下次登录时决策。
	IsHidUser *int `json:"is_hid_user,omitempty"`
}

var ErrNoSession = errors.New("没有本地会话，请先 vpnkit login")

var reUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// SessionPath 返回 session-<host>.json；不同网关分文件存放（docs/02 §5）。
func SessionPath(dir, server string) string {
	return filepath.Join(dir, "session-"+reUnsafe.ReplaceAllString(server, "_")+".json")
}

func SaveSession(dir string, s *Session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(SessionPath(dir, s.Server), b)
}

// LoadSession 读取会话；不存在时返回挂了 ErrAuth 类别的 ErrNoSession（退出码 3）。
func LoadSession(dir, server string) (*Session, error) {
	b, err := os.ReadFile(SessionPath(dir, server))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", vpnerr.ErrAuth, ErrNoSession)
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil || s.TwfID == "" {
		return nil, fmt.Errorf("%w: 会话文件损坏，请重新 login: %v", vpnerr.ErrAuth, err)
	}
	return &s, nil
}

func DeleteSession(dir, server string) error {
	err := os.Remove(SessionPath(dir, server))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// ListSessions 返回目录下全部会话文件对应的 server 名。
func ListSessions(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "session-*.json"))
	var out []string
	for _, p := range m {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s Session
		if json.Unmarshal(b, &s) == nil && s.Server != "" {
			out = append(out, s.Server)
		}
	}
	return out
}
