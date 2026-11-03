package platform

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// VolumeSerial 返回系统盘卷序列号（docs/06 §2.2）。
func VolumeSerial() (uint32, bool, error) {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	root, err := windows.UTF16PtrFromString(strings.TrimRight(drive, `\`) + `\`)
	if err != nil {
		return 0, false, err
	}
	var serial uint32
	if err := windows.GetVolumeInformation(root, nil, 0, &serial, nil, nil, nil, 0); err != nil {
		return 0, false, err
	}
	return serial, true, nil
}
