//go:build !windows

package platform

// VolumeSerial 返回系统盘卷序列号。仅 Windows 有此概念。
//
// 特征码改用 ATA 序列号后（docs/06 §3.1），这里当前没有调用方，保留备用。
func VolumeSerial() (uint32, bool, error) { return 0, false, nil }
