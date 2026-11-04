//go:build !windows

package fsutil

import "os"

func restrict(path string, isDir bool) error {
	if isDir {
		return os.Chmod(path, 0o700)
	}
	return os.Chmod(path, 0o600)
}

// Private 报告文件是否只有属主可访问（组与其他人无任何权限位）。
func Private(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return st.Mode().Perm()&0o077 == 0, nil
}
