package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFilePerm(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "sub", "f.json")
	if err := WriteFile(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if ok, err := Private(p); err != nil || !ok {
		t.Fatalf("not private: %v", err)
	}
	if err := WriteFile(p, []byte("yy")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "yy" {
		t.Fatalf("got %q", b)
	}
}

func TestDirEnvOverride(t *testing.T) {
	t.Setenv("VPNKIT_HOME", "/x/y")
	d, err := Dir()
	if err != nil || d != "/x/y" {
		t.Fatalf("%q %v", d, err)
	}
}
