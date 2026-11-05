package main

import (
	"strings"
	"testing"
)

// TestHexMaskedCred 钉住掩码行为：凭据那一段必须一个字节都别出来。
// 这是安全问题，不是格式问题——probe 的输出会进终端和日志文件。
func TestHexMaskedCred(t *testing.T) {
	b := make([]byte, 76)
	for i := range b {
		b[i] = byte(i + 1)
	}
	out := hexMaskedCred(b, 16, 48)
	toks := strings.Split(out, " ")
	if len(toks) != len(b) {
		t.Fatalf("字段数 %d，期望 %d", len(toks), len(b))
	}
	for i, tok := range toks {
		masked := i >= 16 && i < 64
		if masked && tok != "****" {
			t.Errorf("第 %d 字节应被掩码，实际 %q", i, tok)
		}
		if !masked && tok == "****" {
			t.Errorf("第 %d 字节不该被掩码", i)
		}
	}
}

func TestHexPreview(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	if got := hexPreview(b, 2); got != "0102" {
		t.Fatalf("got %q", got)
	}
	if got := hexPreview(b, 99); got != "0102030405" {
		t.Fatalf("got %q", got)
	}
}
