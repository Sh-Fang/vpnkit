package platform

// Device 是 TUN 设备的最小接口（docs/11 §5）。生产实现包 wireguard/tun，测试实现是内存队列。
// Read/Write 收发的都是裸 IPv4 包，不含任何平台前缀。
type Device interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	MTU() (int, error)
	Name() (string, error)
	Close() error
}
