package tunnel

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/Sh-Fang/vpnkit/internal/logx"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

// FrameWriter 把 IP 包封帧、加密负载后写入上行数据通道（docs/03 §5）。并发安全。
type FrameWriter struct {
	mu     sync.Mutex
	w      io.Writer
	opcode uint32
	c      Cipher
	buf    []byte
	log    *slog.Logger
}

func NewFrameWriter(w io.Writer, opcode uint32, c Cipher, log *slog.Logger) *FrameWriter {
	log = logx.Or(log)
	logx.Assumption(log, "data_opcode", opcode)
	return &FrameWriter{w: w, opcode: opcode, c: c, log: log}
}

// WritePacket 发送一个 IP 包。头不加密，只有 [12:] 经过 RC4，且状态跨包连续。
func (f *FrameWriter) WritePacket(ip []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := wire.FrameHeaderLen + len(ip)
	if cap(f.buf) < n {
		f.buf = make([]byte, n)
	}
	b := f.buf[:n]
	wire.PutFrameHeader(b, f.opcode, uint32(n))
	copy(b[wire.FrameHeaderLen:], ip)
	if f.c != nil {
		f.c.XORKeyStream(b[wire.FrameHeaderLen:], b[wire.FrameHeaderLen:])
	}
	if f.log.Enabled(context.Background(), slog.LevelDebug) {
		f.log.Debug("tx frame", "hdr", hex.EncodeToString(b[:wire.FrameHeaderLen]))
		traceIP(f.log, "tx", ip)
	}
	_, err := f.w.Write(b)
	return err
}

// FrameReader 从下行数据通道读帧、解密并返回裸 IP 包。非并发安全，由单一 rxLoop 使用。
type FrameReader struct {
	r       *bufio.Reader
	c       Cipher
	maxBody int
	hdr     [wire.FrameHeaderLen]byte
	seen    map[uint32]bool
	log     *slog.Logger
}

func NewFrameReader(r io.Reader, c Cipher, mtu int, log *slog.Logger) *FrameReader {
	log = logx.Or(log)
	logx.Assumption(log, "data_endian", "little")
	return &FrameReader{r: bufio.NewReaderSize(r, 64<<10), c: c, maxBody: mtu, seen: map[uint32]bool{}, log: log}
}

// ReadPacket 把下一个 IP 包读入 buf（需 ≥ MTU），返回长度。
func (f *FrameReader) ReadPacket(buf []byte) (int, error) {
	if _, err := io.ReadFull(f.r, f.hdr[:]); err != nil {
		return 0, err
	}
	op, total, _ := wire.ParseFrameHeader(f.hdr[:])
	if total < wire.FrameHeaderLen || int(total) > f.maxBody+wire.FrameHeaderLen {
		return 0, fmt.Errorf("%w: 长度字段 %d 超出 [12, MTU+12=%d]，疑似字节序错误；头部 %s",
			wire.ErrFrameLength, total, f.maxBody+wire.FrameHeaderLen, hex.EncodeToString(f.hdr[:]))
	}
	// 不按 opcode 过滤；未见过的 opcode 只记一次（docs/03 §5）
	if !f.seen[op] {
		f.seen[op] = true
		f.log.Debug("新的数据帧 opcode", "opcode", op)
	}
	n := int(total) - wire.FrameHeaderLen
	if n > len(buf) {
		return 0, fmt.Errorf("%w: 包长 %d 超出缓冲 %d", wire.ErrFrameLength, n, len(buf))
	}
	body := buf[:n]
	if _, err := io.ReadFull(f.r, body); err != nil {
		return 0, err
	}
	if f.c != nil {
		f.c.XORKeyStream(body, body)
	}
	if f.log.Enabled(context.Background(), slog.LevelDebug) {
		f.log.Debug("rx frame", "hdr", hex.EncodeToString(f.hdr[:]))
		traceIP(f.log, "rx", body)
	}
	return n, nil
}

// traceIP 在 trace 级输出 IP 头摘要；不输出负载（docs/11 §8.1）。
func traceIP(log *slog.Logger, dir string, ip []byte) {
	if !log.Enabled(context.Background(), logx.LevelTrace) {
		return
	}
	if s, ok := wire.SummarizeIPv4(ip); ok {
		logx.Trace(log, "ip", "dir", dir, "src", s.Src, "dst", s.Dst, "proto", s.Proto, "len", s.Len)
	} else {
		logx.Trace(log, "ip", "dir", dir, "non_ipv4_len", len(ip))
	}
}
