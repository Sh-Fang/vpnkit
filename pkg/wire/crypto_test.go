package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEncryptPasswordRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	nHex := fmt.Sprintf("%X", priv.N)
	got, err := EncryptPassword(rand.Reader, "s3cret", "ABCD1234", nHex, "10001")
	if err != nil {
		t.Fatal(err)
	}
	// docs/05 §5：1024 位模数 → 128 字节密文 → 256 字符大写 hex
	if len(got) != 256 || got != strings.ToUpper(got) {
		t.Fatalf("len=%d upper=%v", len(got), got == strings.ToUpper(got))
	}
	ct, _ := hex.DecodeString(got)
	pt, err := rsa.DecryptPKCS1v15(nil, priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "s3cret_ABCD1234" {
		t.Fatalf("plaintext %q", pt)
	}
}

func TestEncryptPasswordTooLong(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	nHex := fmt.Sprintf("%x", priv.N)
	// 117 字节恰好可以，118 字节必须报错
	ok := strings.Repeat("a", 117-1-4)
	if _, err := EncryptPassword(rand.Reader, ok, "CSRF", nHex, "10001"); err != nil {
		t.Fatalf("117 bytes should pass: %v", err)
	}
	long := strings.Repeat("a", 118-1-4)
	if _, err := EncryptPassword(rand.Reader, long, "CSRF", nHex, "10001"); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("want ErrPasswordTooLong, got %v", err)
	}
}

func TestEncryptPasswordBadKey(t *testing.T) {
	for _, c := range []struct{ n, e string }{
		{"zz", "10001"},
		{"", "10001"},
		{strings.Repeat("F", 255) + "E", "10001"}, // 偶数
		{"FFFF", "10001"},                         // 过短
		{strings.Repeat("F", 256), "zz"},
		{strings.Repeat("F", 256), "0"},
	} {
		if _, err := EncryptPassword(rand.Reader, "p", "c", c.n, c.e); !errors.Is(err, ErrBadPublicKey) {
			t.Errorf("n=%q e=%q: want ErrBadPublicKey, got %v", c.n, c.e, err)
		}
	}
}

func TestMD5Upper(t *testing.T) {
	if got := MD5Upper("abc"); got != "900150983CD24FB0D6963F7D28E17F72" {
		t.Fatal(got)
	}
	if got := MD5Lower("abc"); got != "900150983cd24fb0d6963f7d28e17f72" {
		t.Fatal(got)
	}
}

func TestParseRSAExp(t *testing.T) {
	for in, want := range map[string]int{"65537": 65537, " 65537 ": 65537, "10001": 65537, "0x10001": 65537, "3": 3, "1001b": 65563} {
		if got, ok := ParseRSAExp(in); !ok || got != want {
			t.Errorf("%q → %d,%v want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "1", "65536", "zz", "99999999999"} {
		if _, ok := ParseRSAExp(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestEncryptPasswordDecimalExp(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	got, err := EncryptPassword(rand.Reader, "s3cret", "1413239678", fmt.Sprintf("%X", priv.N), "65537")
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := hex.DecodeString(got)
	if pt, err := rsa.DecryptPKCS1v15(nil, priv, ct); err != nil || string(pt) != "s3cret_1413239678" {
		t.Fatalf("%q %v", pt, err)
	}
}
