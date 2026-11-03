package platform

import (
	"errors"
	"io"
	"sync"
)

// MemDevice 是内存 TUN：Inject 模拟操作系统发往隧道的包，Outbound 收集隧道写回系统的包。
// 用于无 root 的测试与 up --fake-tun 联调（docs/11 §5 的 fakeTUN）。
type MemDevice struct {
	name     string
	mtu      int
	in       chan []byte
	Outbound chan []byte
	once     sync.Once
	closed   chan struct{}
}

func NewMemDevice(name string, mtu int) *MemDevice {
	return &MemDevice{name: name, mtu: mtu, in: make(chan []byte, 256), Outbound: make(chan []byte, 1024), closed: make(chan struct{})}
}

var errMemClosed = errors.New("memdev: closed")

// Inject 模拟系统发出一个包（进入 txLoop）。
func (d *MemDevice) Inject(p []byte) error {
	select {
	case d.in <- append([]byte(nil), p...):
		return nil
	case <-d.closed:
		return errMemClosed
	}
}

func (d *MemDevice) Read(b []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(b, p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *MemDevice) Write(b []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, errMemClosed
	default:
	}
	select {
	case d.Outbound <- append([]byte(nil), b...):
	default: // 无人消费时丢弃，模拟系统丢包而不是阻塞隧道
	}
	return len(b), nil
}

func (d *MemDevice) MTU() (int, error)     { return d.mtu, nil }
func (d *MemDevice) Name() (string, error) { return d.name, nil }
func (d *MemDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}
