package logx

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"abcd":             "****",
		"abcdefgh":         "********",
		"abcdefghi":        "abcd…fghi",
		"0123456789abcdef": "0123…cdef",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q)=%q want %q", in, got, want)
		}
	}
}

func TestHexMask(t *testing.T) {
	got := Hex([]byte{1, 2, 3, 4}, Span{1, 2})
	if got != "01****04" {
		t.Fatal(got)
	}
	if Hex([]byte{0xab}) != "ab" {
		t.Fatal("plain")
	}
}

func TestTraceLevelAndAssumption(t *testing.T) {
	var buf bytes.Buffer
	l, closeFn, err := Setup(Options{Level: LevelTrace, Stderr: &buf})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	Trace(l, "pkt")
	Assumption(l, "ctrl_conn_type", 1)
	out := buf.String()
	if !strings.Contains(out, "level=TRACE") {
		t.Errorf("trace level not rendered: %s", out)
	}
	if !strings.Contains(out, "assumption=ctrl_conn_type value=1") {
		t.Errorf("assumption missing: %s", out)
	}
}

func TestInfoFiltersDebug(t *testing.T) {
	var buf bytes.Buffer
	l, _, _ := Setup(Options{Level: slog.LevelInfo, Stderr: &buf})
	l.Debug("hidden")
	if buf.Len() != 0 {
		t.Fatal(buf.String())
	}
}

func TestFileOutputAndRotate(t *testing.T) {
	d := t.TempDir()
	for i := 0; i < 12; i++ {
		os.WriteFile(filepath.Join(d, fmt.Sprintf("vpnkit-20200101-0000%02d.log", i)), nil, 0o600)
	}
	var buf bytes.Buffer
	l, closeFn, err := Setup(Options{Level: slog.LevelDebug, Stderr: &buf, FileDir: d, FileKeep: 10})
	if err != nil {
		t.Fatal(err)
	}
	l.Debug("hello")
	closeFn()
	m, _ := filepath.Glob(filepath.Join(d, "vpnkit-*.log"))
	if len(m) != 10 {
		t.Fatalf("keep 10, got %d", len(m))
	}
	newest := m[len(m)-1]
	b, _ := os.ReadFile(newest)
	if !strings.Contains(string(b), "hello") {
		t.Fatalf("file content: %s", b)
	}
	if st, _ := os.Stat(newest); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", st.Mode().Perm())
	}
}
