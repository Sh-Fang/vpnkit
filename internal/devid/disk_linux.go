//go:build linux

package devid

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	hdioGetIdentity = 0x030d // 探测设备是否支持 ATA IDENTIFY
	sgIO            = 0x2285 // SCSI 直通
)

// ataIdentifyCDB 是 ATA PASS-THROUGH(16) 封装的 IDENTIFY DEVICE 命令。
// 字节序列与原客户端一致（docs/06 §3.2）：0x85 0x08 0x2e … 0x40 0xec 0x00。
var ataIdentifyCDB = [16]byte{
	0x85, 0x08, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xec, 0x00,
}

// sgIOHdr 对应 struct sg_io_hdr（linux/scsi/sg.h）。
type sgIOHdr struct {
	InterfaceID    int32
	DxferDirection int32
	CmdLen         uint8
	MxSbLen        uint8
	IovecCount     uint16
	DxferLen       uint32
	Dxferp         uintptr
	Cmdp           uintptr
	Sbp            uintptr
	Timeout        uint32
	Flags          uint32
	PackID         int32
	UsrPtr         uintptr
	Status         uint8
	MaskedStatus   uint8
	MsgStatus      uint8
	HostStatus     uint16
	DriverStatus   uint16
	Resid          int32
	Duration       uint32
	Info           uint32
}

// diskSerial 按原客户端的次序找第一块能读到 ATA 序列号的盘（docs/06 §3.2）。
func diskSerial() (string, bool, error) {
	devices := []string{"/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/hda", "/dev/hdb", "/dev/hdc", "/dev/hdd"}
	var firstErr error
	for _, dev := range devices {
		reply, err := identifyDevice(dev)
		if err != nil {
			if firstErr == nil && err != unix.ENOENT {
				firstErr = fmt.Errorf("devid: %s: %w", dev, err)
			}
			continue
		}
		if serial := decodeSerial(reply); serial != "" {
			return serial, true, nil
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("%w: 没有可读的 ATA 磁盘（需要 root 或 CAP_SYS_RAWIO）", ErrUnsupported)
	}
	return "", false, firstErr
}

// identifyDevice 复刻原客户端的取盘流程：先 HDIO_GET_IDENTITY 探测，
// 再用 SG_IO 发 ATA PASS-THROUGH(16) IDENTIFY DEVICE 拿 512 字节应答。
func identifyDevice(dev string) ([]byte, error) {
	fd, err := unix.Open(dev, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	probe := make([]byte, 512)
	if err := ioctlPtr(fd, hdioGetIdentity, unsafe.Pointer(&probe[0])); err != nil {
		return nil, err
	}

	reply := make([]byte, 512)
	sense := make([]byte, 32)
	hdr := sgIOHdr{
		InterfaceID:    'S',
		DxferDirection: -3, // SG_DXFER_FROM_DEV
		CmdLen:         uint8(len(ataIdentifyCDB)),
		MxSbLen:        uint8(len(sense)),
		DxferLen:       uint32(len(reply)),
		Dxferp:         uintptr(unsafe.Pointer(&reply[0])),
		Cmdp:           uintptr(unsafe.Pointer(&ataIdentifyCDB[0])),
		Sbp:            uintptr(unsafe.Pointer(&sense[0])),
		Timeout:        10000,
	}
	if err := ioctlPtr(fd, sgIO, unsafe.Pointer(&hdr)); err != nil {
		return nil, err
	}
	if !(hdr.Status == 0 || hdr.Status == 2) || hdr.HostStatus != 0 || hdr.DriverStatus != 8 {
		return nil, fmt.Errorf("sg_io: status=%d host=%d driver=%d", hdr.Status, hdr.HostStatus, hdr.DriverStatus)
	}
	return reply, nil
}

func ioctlPtr(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// decodeSerial 把 IDENTIFY 应答里第 10–19 个字（字节 20 起）还原成序列号。
//
// 原客户端的行为（docs/06 §3.2）：先跳过“两个字节都是空格”的前导字；
// 若停在一个高字节为空格的字上，就把低字节单独吐出并从下一个字继续；
// 之后逐字按高字节、低字节的顺序输出，丢掉 NUL。
func decodeSerial(reply []byte) string {
	const words = 10
	var w [words]uint16
	for i := 0; i < words; i++ {
		w[i] = uint16(reply[20+2*i]) | uint16(reply[21+2*i])<<8
	}

	out := make([]byte, 0, words*2)
	n := 0
	broke := false
	var c byte
	for {
		if n >= words || byte(w[n]>>8) != ' ' {
			break
		}
		c = byte(w[n])
		if c != ' ' {
			broke = true
			break
		}
		n++
	}
	if broke {
		if c != 0 {
			out = append(out, c)
		}
		n++
	}
	for ; n < words; n++ {
		if hi := byte(w[n] >> 8); hi != 0 {
			out = append(out, hi)
		}
		if lo := byte(w[n]); lo != 0 {
			out = append(out, lo)
		}
	}
	return string(out)
}
