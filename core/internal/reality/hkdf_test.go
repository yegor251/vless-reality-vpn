package reality

import (
	"encoding/hex"
	"testing"
)

// RFC 5869, test vector A.1 (SHA-256).
func TestHKDFSHA256(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString(
		"3cb25f25faacd57a90434f64d0362f2a" +
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
			"34007208d5b887185865")

	got := hkdfSHA256(ikm, salt, info, 42)
	if string(got) != string(want) {
		t.Errorf("okm = %x, want %x", got, want)
	}
}
