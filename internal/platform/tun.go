package platform

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// tunOffset 是读写缓冲前预留的头部空间：macOS utun 需要 4 字节地址族头，
// Linux 开启 vnet hdr 时需要 10 字节；wireguard-go 自身用 16，这里照用。
const tunOffset = 16

// DefaultTUNName 返回各平台的设备名（docs/08 §2）。macOS 的 utun 由内核分配编号。
func DefaultTUNName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun"
	case "windows":
		return "vpnkit"
	default:
		return "vpnkit0"
	}
}

// wgDevice 把 wireguard/tun 的批量接口适配成逐包的 Device。
type wgDevice struct {
	dev  tun.Device
	name string

	rmu     sync.Mutex
	bufs    [][]byte
	sizes   []int
	pending int // bufs 中尚未交付的包的起始下标
	count   int

	wmu  sync.Mutex
	wbuf []byte
}

// OpenTUN 创建 TUN 设备（需要 root / CAP_NET_ADMIN / 管理员）。
func OpenTUN(name string, mtu int, log *slog.Logger) (Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN %q: %w", name, err)
	}
	real, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	batch := dev.BatchSize()
	w := &wgDevice{dev: dev, name: real, bufs: make([][]byte, batch), sizes: make([]int, batch), wbuf: make([]byte, tunOffset+65535)}
	for i := range w.bufs {
		w.bufs[i] = make([]byte, tunOffset+65535)
	}
	go func() {
		// 必须消费事件通道，否则库内部的通知 goroutine 会阻塞
		for ev := range dev.Events() {
			if ev&tun.EventDown != 0 && log != nil {
				log.Warn("TUN 设备状态变为 down", "dev", real)
			}
		}
	}()
	return w, nil
}

func (w *wgDevice) Read(b []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for w.pending >= w.count {
		n, err := w.dev.Read(w.bufs, w.sizes, tunOffset)
		if err != nil {
			return 0, err
		}
		w.pending, w.count = 0, n
	}
	i := w.pending
	w.pending++
	return copy(b, w.bufs[i][tunOffset:tunOffset+w.sizes[i]]), nil
}

func (w *wgDevice) Write(b []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	buf := w.wbuf[:tunOffset+len(b)]
	copy(buf[tunOffset:], b)
	if _, err := w.dev.Write([][]byte{buf}, tunOffset); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wgDevice) MTU() (int, error)     { return w.dev.MTU() }
func (w *wgDevice) Name() (string, error) { return w.name, nil }
func (w *wgDevice) Close() error          { return w.dev.Close() }
