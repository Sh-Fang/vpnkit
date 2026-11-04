//go:build !linux

package devid

// diskSerial 在非 Linux 平台尚未实现（docs/06 §3.2）。
func diskSerial() (string, bool, error) { return "", false, ErrUnsupported }
