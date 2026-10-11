package reality

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"math/big"
	"sync"
)

var (
	certOnce    sync.Once
	ed25519Priv ed25519.PrivateKey
	emptyCert   []byte // DER of a minimal self-signed ed25519 certificate
)

func initCert() {
	certOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		template := x509.Certificate{SerialNumber: big.NewInt(0)}
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
		if err != nil {
			panic(err)
		}
		ed25519Priv, emptyCert = priv, der
	})
}

// buildCert returns the per-connection server certificate: the minimal
// self-signed certificate with HMAC-SHA512(authKey, public key) written over
// its 64-byte signature field. A REALITY client recognizes the server by this
// MAC; everyone else just sees an unremarkable self-signed certificate.
func buildCert(authKey []byte) (certDER []byte, priv ed25519.PrivateKey) {
	initCert()
	der := bytes.Clone(emptyCert)
	mac := hmac.New(sha512.New, authKey)
	mac.Write(ed25519Priv.Public().(ed25519.PublicKey))
	copy(der[len(der)-64:], mac.Sum(nil))
	return der, ed25519Priv
}
