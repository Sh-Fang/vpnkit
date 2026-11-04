package devid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sh-Fang/vpnkit/internal/fsutil"
	"github.com/Sh-Fang/vpnkit/pkg/wire"
)

type fakeSource struct {
	ifs    []Iface
	serial uint32
	hasSer bool
	calls  int
}

func (f *fakeSource) Interfaces() ([]Iface, error)        { f.calls++; return f.ifs, nil }
func (f *fakeSource) VolumeSerial() (uint32, bool, error) { return f.serial, f.hasSer, nil }

var physical = []Iface{
	{Name: "wlan0", MAC: "aa:bb:cc:dd:ee:02"},
	{Name: "eth0", MAC: "aa:bb:cc:dd:ee:01"},
	{Name: "lo", MAC: "", Loopback: true},
	{Name: "docker0", MAC: "02:42:00:00:00:01"},
	{Name: "utun3", MAC: ""},
	{Name: "vEthernet (WSL)", MAC: "00-15-5D-00-00-01"},
}

func TestBuildPlaintextCases(t *testing.T) {
	cases := []struct {
		name string
		p    FingerprintParts
		want string
		err  error
	}{
		{"mac only", FingerprintParts{MACList: "AABB"}, "AABB", nil},
		{"volume only", FingerprintParts{VolumeSerial: "1a2B3c4d"}, "1a2B3c4d", nil},
		{"both", FingerprintParts{MACList: "AABB", VolumeSerial: "1a2B3c4d"}, "AABB", nil},
		{"none", FingerprintParts{}, "", ErrNoFingerprintSource},
	}
	for _, c := range cases {
		got, err := buildPlaintext(c.p)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: got %q %v", c.name, got, err)
		}
	}
}

func TestComputeMAC(t *testing.T) {
	id, err := Compute(&fakeSource{ifs: physical})
	if err != nil {
		t.Fatal(err)
	}
	// 按接口名排序：eth0 在 wlan0 前；虚拟接口全部排除
	if want := wire.MD5Upper("AABBCCDDEE01AABBCCDDEE02"); id != want {
		t.Fatalf("got %s want %s", id, want)
	}
	if !Valid(id) {
		t.Fatal("format")
	}
}

func TestComputeFallbackVolume(t *testing.T) {
	id, err := Compute(&fakeSource{ifs: physical[2:], serial: 0x1a2b3c4d, hasSer: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := wire.MD5Upper("1a2B3c4d"); id != want {
		t.Fatalf("got %s want %s", id, want)
	}
}

func TestComputeNoSource(t *testing.T) {
	id, err := Compute(&fakeSource{ifs: physical[2:]})
	if !errors.Is(err, ErrNoFingerprintSource) || id != "" {
		t.Fatalf("got %q %v", id, err)
	}
}

func TestFormatVolumeSerial(t *testing.T) {
	if got := FormatVolumeSerial(0x1a2b3c4d); got != "1a2B3c4d" {
		t.Fatal(got)
	}
	if got := FormatVolumeSerial(0x0a0b0c0d); got != "0a0B0c0d" {
		t.Fatal(got)
	}
}

func TestCacheAndPin(t *testing.T) {
	d := t.TempDir()
	src := &fakeSource{ifs: physical}
	id, fromCache, err := Get(d, src)
	if err != nil || fromCache {
		t.Fatal(err, fromCache)
	}
	const pinned = "3F2A9C14B7E08D5612AB44CD990E7F31"
	if err := Pin(d, pinned); err != nil {
		t.Fatal(err)
	}
	if ok, err := fsutil.Private(CachePath(d)); err != nil || !ok {
		t.Fatalf("cache file not private: %v", err)
	}
	src.calls = 0
	got, fromCache, err := Get(d, src)
	if err != nil || got != pinned || !fromCache || src.calls != 0 {
		t.Fatalf("cache should win without enumerating: %s %v %d", got, fromCache, src.calls)
	}
	// 31 字符视为无效，重新计算
	os.WriteFile(filepath.Join(d, "device-id"), []byte(pinned[:31]), 0o600)
	got, fromCache, _ = Get(d, src)
	if got != id || fromCache {
		t.Fatalf("invalid cache should be ignored: %s", got)
	}
	for _, bad := range []string{"", pinned[:31], "3f2a9c14b7e08d5612ab44cd990e7f31", pinned + "0", "G" + pinned[1:]} {
		if err := Pin(d, bad); !errors.Is(err, ErrBadFormat) {
			t.Errorf("Pin(%q) should fail", bad)
		}
	}
}
