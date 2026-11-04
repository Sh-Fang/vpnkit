package route

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
)

// State 是 state.json：运行时变更记录，用于 down 与异常退出后的清理（docs/07 §6）。
type State struct {
	PID            int       `json:"pid"`
	GOOS           string    `json:"goos"`
	Tun            string    `json:"tun"`
	StartedAt      time.Time `json:"started_at"`
	RoutesAdded    []string  `json:"routes_added"`
	BypassAdded    []string  `json:"bypass_added"`
	DNSFiles       []string  `json:"dns_files"`
	ResolvectlLink string    `json:"resolvectl_link,omitempty"`
	NRPTAdded      []string  `json:"nrpt_added"`
	// NRPTPolicyKeyRemoved 表示 up 删除过空的组策略 NRPT 键，清理时要重建。
	NRPTPolicyKeyRemoved bool `json:"nrpt_policy_key_removed,omitempty"`
	// ProxyBypassAdded 是 vpnkit 追加到系统代理例外里的条目；清理时只删这些。
	ProxyBypassAdded []string `json:"proxy_bypass_added,omitempty"`
}

func StatePath(dir string) string { return filepath.Join(dir, "state.json") }

// LoadState 读取 state.json；不存在时返回 nil, nil。
func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(StatePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func saveState(dir string, s *State) error {
	if dir == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(StatePath(dir), b)
}

func removeState(dir string) error {
	if dir == "" {
		return nil
	}
	err := os.Remove(StatePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
