// Package fsutil 负责状态目录定位与 0600 文件落盘。
package fsutil

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// Dir 返回状态目录（docs/09 §2）。
//
// 三平台统一用 ~/.config/vpnkit，而不是 os.UserConfigDir，以便文档里写的路径在任何平台都成立。
// sudo 运行时 HOME 可能被重置为 /root，因此优先取 SUDO_USER 的主目录——
// 否则用户态 login 写下的令牌，提权后的 up 会找不到。
// VPNKIT_HOME 用于测试与多环境隔离。
func Dir() (string, error) {
	if d := os.Getenv("VPNKIT_HOME"); d != "" {
		return d, nil
	}
	home, err := homeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "vpnkit"), nil
}

func homeDir() (string, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
			if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}

// EnsureDir 创建状态目录（0700）。
func EnsureDir() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	if err := MkdirPrivate(d); err != nil {
		return "", fmt.Errorf("创建状态目录: %w", err)
	}
	return d, nil
}

// MkdirPrivate 创建目录并收紧为仅本人可访问（0700）。
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := restrict(dir, true); err != nil {
		return err
	}
	chownToSudoUser(dir)
	return nil
}

// OpenPrivate 以追加方式打开（必要时创建）仅本人可读写的文件（0600）。
func OpenPrivate(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := restrict(path, false); err != nil {
		f.Close()
		return nil, err
	}
	chownToSudoUser(path)
	return f, nil
}

// WriteFile 原子写入 0600 文件：先写临时文件再 rename，避免进程中断留下半截令牌。
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := restrict(name, false); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	chownToSudoUser(path)
	return nil
}
