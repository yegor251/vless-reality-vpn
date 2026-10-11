package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"time"
)

type AuthInfo struct {
	AuthKey []byte // HKDF(X25519(static key, client key share)), used for the cert HMAC
	Time    time.Time
	ShortID [8]byte
}

// Verify checks the REALITY authentication sealed into the ClientHello
// session_id. It returns nil whenever anything does not match.
func Verify(ch *ClientHello, privateKey [32]byte, shortIDs map[[8]byte]bool, maxTimeDiff time.Duration) *AuthInfo {
	if !ch.SupportsTLS13 {
		return nil
	}
	// The X25519MLKEM768 share must be offered; a plain X25519 share that
	// follows it takes precedence, mirroring the reference implementation.
	var peerPub, peerPubHybrid []byte
	for _, ks := range ch.KeyShares {
		if ks.Group == groupX25519MLKEM768 && len(ks.Data) == mlkem768EncapsulationKeySize+32 {
			if peerPubHybrid != nil {
				return nil
			}
			peerPubHybrid = ks.Data[mlkem768EncapsulationKeySize:]
			continue
		}
		if ks.Group == groupX25519 && len(ks.Data) == 32 {
			peerPub = ks.Data
			break
		}
	}
	if peerPubHybrid == nil {
		return nil
	}
	if peerPub == nil {
		peerPub = peerPubHybrid
	}

	priv, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil {
		return nil
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil
	}
	ikm, err := priv.ECDH(pub)
	if err != nil {
		return nil
	}

	authKey := hkdfSHA256(ikm, ch.Random[:20], []byte("REALITY"), 32)

	if len(ch.SessionID) != 32 {
		return nil
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	plain := make([]byte, 16)
	if _, err := aead.Open(plain[:0], ch.Random[20:32], ch.SessionID, ch.Raw); err != nil {
		return nil
	}

	info := &AuthInfo{AuthKey: authKey}
	info.Time = time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)
	copy(info.ShortID[:], plain[8:16])

	if maxTimeDiff > 0 && time.Since(info.Time).Abs() > maxTimeDiff {
		return nil
	}
	if !shortIDs[info.ShortID] {
		return nil
	}
	return info
}
