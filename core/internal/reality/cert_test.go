package reality

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"testing"
)

func TestBuildCert(t *testing.T) {
	authKey := bytes.Repeat([]byte{7}, 32)
	der, priv := buildCert(authKey)

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pub, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type %T, want ed25519", parsed.PublicKey)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("certificate key does not match private key")
	}

	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	if !bytes.Equal(der[len(der)-64:], mac.Sum(nil)) {
		t.Error("signature field does not contain the HMAC")
	}

	// the same process must hand out the same key pair (global ed25519 key)
	der2, _ := buildCert(bytes.Repeat([]byte{9}, 32))
	parsed2, _ := x509.ParseCertificate(der2)
	if !parsed2.PublicKey.(ed25519.PublicKey).Equal(pub) {
		t.Error("key pair changed between calls")
	}
}
