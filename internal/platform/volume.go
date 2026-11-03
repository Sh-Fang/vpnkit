//go:build !windows

package platform

// VolumeSerial 返回系统盘卷序列号（docs/06 §2.2）。仅 Windows 有此概念。
func VolumeSerial() (uint32, bool, error) { return 0, false, nil }
