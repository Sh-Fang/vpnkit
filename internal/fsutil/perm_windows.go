package fsutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// restrict 把 DACL 替换为「仅当前用户完全控制」并切断继承，等价于 Unix 的 0600/0700。
// Windows 忽略 Chmod 的权限位，不这样做的话令牌文件会继承用户目录的 ACL。
// 用令牌用户而不是文件属主：提权进程创建的文件属主可能是 Administrators 组，
// 非提权的 login/status 仍需能读到。
func restrict(path string, isDir bool) error {
	sid, err := currentUser()
	if err != nil {
		return err
	}
	// 目录加 OICI，让其下新建的文件和子目录继承同样的限制。
	flags := ""
	if isDir {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;%s;FA;;;%s)", flags, sid))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Private 报告文件的 DACL 是否只放行当前用户、SYSTEM 与 Administrators。
// 后两者本就能绕过任何 ACL，放行它们不扩大暴露面。
func Private(path string) (bool, error) {
	sid, err := currentUser()
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	// 空 DACL 表示所有人完全控制。
	if dacl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		s := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !s.Equals(sid) && !s.IsWellKnown(windows.WinLocalSystemSid) && !s.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return false, nil
		}
	}
	return true, nil
}

func currentUser() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("读取当前用户 SID: %w", err)
	}
	return u.User.Sid, nil
}
