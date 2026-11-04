package devid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 下列期望值取自实机比对结果（docs/06 §5.1）：
// 磁盘 WD-WXP1E278DWSN、网卡 54-ee-75-e0-3f-c5、主机名 oasis-Lenovo。
const (
	goldenDisk = "WD-WXP1E278DWSN"
	goldenMAC  = "54-ee-75-e0-3f-c5"
	goldenHost = "oasis-Lenovo"
	goldenHID  = "8D82BE5469AA53CA87DBB47D97826956"
	goldenFull = "8D82BE5469AA53CA87DBB47D97826956|54-ee-75-e0-3f-c5|b2FzaXMtTGVub3Zv"
)

func TestMD5Hex(t *testing.T) {
	if got := MD5Hex(""); got != "D41D8CD98F00B204E9800998ECF8427E" {
		t.Fatalf("MD5Hex(\"\") = %s", got)
	}
	if got := MD5Hex(goldenDisk + "\n"); got != "DD0A972BDC1723886A98315F622A30E0" {
		t.Fatalf("MD5Hex(disk+nl) = %s", got)
	}
	if got := MD5Hex(goldenMAC); got != "D98AB73B269C30DB2F4C83B7C561C906" {
		t.Fatalf("MD5Hex(mac) = %s", got)
	}
}

func TestFold(t *testing.T) {
	// 折叠取字符码点低四位的和，再对大写十六进制表取模（docs/06 §3.2）。
	got, err := Fold(strings.Repeat("0", 32), strings.Repeat("0", 32))
	if err != nil || got != strings.Repeat("0", 32) {
		t.Fatalf("Fold(0,0) = %q, %v", got, err)
	}
	// 'A' = 0x41 → 0x41%16 = 1；'F' = 0x46 → 6。
	got, err = Fold(strings.Repeat("A", 32), strings.Repeat("F", 32))
	if err != nil || got != strings.Repeat("7", 32) {
		t.Fatalf("Fold(A,F) = %q, %v", got, err)
	}
	if _, err := Fold("abc", strings.Repeat("0", 32)); err == nil {
		t.Fatal("长度不足应报错")
	}
}

func TestHostNameField(t *testing.T) {
	if got := HostNameField(goldenHost); got != "b2FzaXMtTGVub3Zv" {
		t.Fatalf("HostNameField = %s", got)
	}
	if got := HostNameField("ab"); got != "YWI=" {
		t.Fatalf("单字节补位应带 =：%s", got)
	}
	if got := HostNameField("abc"); got != "YWJj" {
		t.Fatalf("三字节不应补位：%s", got)
	}
}

func TestBuildGolden(t *testing.T) {
	id, err := Build(goldenDisk, goldenMAC, goldenHost)
	if err != nil {
		t.Fatal(err)
	}
	if id.HID != goldenHID {
		t.Fatalf("HID = %s，期望 %s", id.HID, goldenHID)
	}
	if id.String() != goldenFull {
		t.Fatalf("String() = %s", id.String())
	}
}

func TestBuildOnlyMAC(t *testing.T) {
	// 磁盘取不到时，只把 MAC 的 MD5 当第一段（docs/06 §3.2）。
	id, err := Build("", goldenMAC, goldenHost)
	if err != nil {
		t.Fatal(err)
	}
	if id.HID != MD5Hex(goldenMAC) {
		t.Fatalf("HID = %s", id.HID)
	}
}

func TestBuildNoSource(t *testing.T) {
	if _, err := Build("", "", goldenHost); err == nil {
		t.Fatal("两路都没有时应报错")
	}
}

func TestBuildNoMACPlaceholder(t *testing.T) {
	// 有磁盘没 MAC：第二段补固定值，但第一段仍然只有磁盘参与。
	id, err := Build(goldenDisk, "", goldenHost)
	if err != nil {
		t.Fatal(err)
	}
	if id.MAC != "00-00-00-00-00-00" {
		t.Fatalf("MAC 段 = %s", id.MAC)
	}
	if id.HID != MD5Hex(goldenDisk+"\n") {
		t.Fatalf("HID = %s", id.HID)
	}
}

func TestMACField(t *testing.T) {
	cases := map[string]string{
		"54:EE:75:E0:3F:C5": "54-ee-75-e0-3f-c5",
		"54-ee-75-e0-3f-c5": "54-ee-75-e0-3f-c5",
		"":                  "",
		"00:00:00:00:00:00": "",
		"aa:bb:cc":          "",
	}
	for in, want := range cases {
		if got := MACField(in); got != want {
			t.Errorf("MACField(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestSelectMACOrderAndPhysical(t *testing.T) {
	ifs := []Iface{
		{Name: "wlp2s0", MAC: "bc:a8:a6:f2:63:f4", Physical: true},
		{Name: "docker0", MAC: "02:42:00:00:00:01"},
		{Name: "enp3s0", MAC: "54:ee:75:e0:3f:c5", Physical: true},
		{Name: "lo", MAC: "", Loopback: true},
	}
	got, ok := SelectMAC(ifs)
	if !ok || got != goldenMAC {
		t.Fatalf("SelectMAC = %q, %v（按名字排序后应取 enp3s0）", got, ok)
	}
	if _, ok := SelectMAC([]Iface{{Name: "docker0", MAC: "02:42:00:00:00:01"}}); ok {
		t.Fatal("没有物理网卡时不应选出 MAC")
	}
}

// buildReply 按 IDENTIFY 的存储方式把显示串放进第 10–19 字（每字高字节在前）。
func buildReply(display string) []byte {
	reply := make([]byte, 512)
	for i := 0; i < 10; i++ {
		reply[20+2*i] = display[2*i+1]
		reply[21+2*i] = display[2*i]
	}
	return reply
}

func TestDecodeSerial(t *testing.T) {
	// 实机字段是前导空格右对齐，原客户端会跳过这些空格。
	padded := "     " + goldenDisk
	got := decodeSerial(buildReply(padded))
	if got != goldenDisk {
		t.Fatalf("decodeSerial(前导空格) = %q，期望 %q", got, goldenDisk)
	}
	tooLong := goldenDisk + "AAAAA"
	if got := decodeSerial(buildReply(tooLong)); got != tooLong {
		t.Fatalf("decodeSerial(刚好 20 字节) = %q", got)
	}
}

func TestParseRoundTrip(t *testing.T) {
	id, err := Parse(goldenFull)
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != goldenFull {
		t.Fatalf("往返不一致：%s", id.String())
	}
	if _, err := Parse("不是十六进制"); err == nil {
		t.Fatal("形状不符应报错")
	}
	if _, err := Parse("8D82BE5469AA53CA87DBB47D97826956|a|b|c"); err == nil {
		t.Fatal("段数不对应报错")
	}
	bare, err := Parse(goldenHID)
	if err != nil || bare.HID != goldenHID || bare.MAC != "" {
		t.Fatalf("只给第一段应解析成功：%+v %v", bare, err)
	}
}

type fakeSource struct {
	ifs    []Iface
	serial string
	ok     bool
	err    error
	host   string
}

func (f fakeSource) Interfaces() ([]Iface, error)      { return f.ifs, nil }
func (f fakeSource) DiskSerial() (string, bool, error) { return f.serial, f.ok, f.err }
func (f fakeSource) Hostname() (string, error)         { return f.host, nil }

func TestLoadPinnedWinsAndPins(t *testing.T) {
	dir := t.TempDir()
	src := fakeSource{
		ifs:    []Iface{{Name: "enp3s0", MAC: "54:ee:75:e0:3f:c5", Physical: true}},
		serial: goldenDisk, ok: true, host: goldenHost,
	}
	id, cached, err := Load(dir, src)
	if err != nil || cached {
		t.Fatalf("首轮不应命中缓存: %v %v", cached, err)
	}
	if id.HID != goldenHID {
		t.Fatalf("实时计算 = %s", id.HID)
	}
	if err := Pin(dir, id); err != nil {
		t.Fatal(err)
	}
	again, cached, err := Load(dir, src)
	if err != nil || !cached || again != id {
		t.Fatalf("固化后应原样读回: %v %v %+v", cached, err, again)
	}
	b, err := os.ReadFile(filepath.Join(dir, "device-id"))
	if err != nil || strings.TrimSpace(string(b)) != goldenFull {
		t.Fatalf("固化文件内容 = %q, %v", b, err)
	}
}

func TestLoadFillsBareHID(t *testing.T) {
	// 早期版本只固化了第一段，另外两段要用本机现值补齐。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device-id"), []byte(goldenHID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := fakeSource{
		ifs:  []Iface{{Name: "enp3s0", MAC: "54:ee:75:e0:3f:c5", Physical: true}},
		host: goldenHost,
	}
	id, cached, err := Load(dir, src)
	if err != nil || !cached {
		t.Fatalf("应命中缓存: %v %v", cached, err)
	}
	if id.String() != goldenFull {
		t.Fatalf("补齐结果 = %s", id.String())
	}
}

func TestPinRejectsBadFormat(t *testing.T) {
	if err := Pin(t.TempDir(), HardID{HID: "xyz"}); err == nil {
		t.Fatal("形状不符应拒绝固化")
	}
}
