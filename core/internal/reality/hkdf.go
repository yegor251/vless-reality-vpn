package reality

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hkdfSHA256 implements RFC 5869 extract-then-expand with SHA-256.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}
