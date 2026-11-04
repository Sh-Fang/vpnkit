//go:build linux

package devid

import "os"

// physicalIface 判定一张网卡是否有真实硬件：sysfs 里有 device 链接。
// 这是原客户端的判据（docs/06 §3.3），不要改用名字前缀猜。
func physicalIface(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/device")
	return err == nil
}
