package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// keygen prints an x25519 key pair for REALITY, base64-encoded the same way
// Xray expects it in configs.
func main() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Private key: %s\n", base64.RawURLEncoding.EncodeToString(priv.Bytes()))
	fmt.Printf("Public key:  %s\n", base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()))
}
