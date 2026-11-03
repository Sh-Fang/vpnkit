//go:build !windows

package fsutil

import (
	"os"
	"strconv"
)

// chownToSudoUser 把 sudo 下创建的文件归还给原用户，
// 否则下一次非提权的 login/status 会因权限读不到自己的文件。
func chownToSudoUser(path string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Lchown(path, uid, gid)
}
