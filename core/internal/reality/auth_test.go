package reality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// buildClientHelloMessage assembles a ClientHello handshake message the way a
// REALITY client would: key_share carrying the ephemeral x25519 public key,
// given random and session_id.
// shares selects the key_share layout: "both", "hybrid" or "plain".
func buildClientHelloMessage(t *testing.T, random, sessionID, keySharePub []byte, sni string, shares string) []byte {
	t.Helper()
	body := make([]byte, 0, 256)
	body = append(body, 0x03, 0x03) // legacy version
	body = append(body, random...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression: null

	var exts []byte
	// server_name
	name := []byte(sni)
	exts = append(exts, 0x00, 0x00)
	exts = append(exts, byte((len(name)+5)>>8), byte(len(name)+5))
	exts = append(exts, byte((len(name)+3)>>8), byte(len(name)+3))
	exts = append(exts, 0x00)
	exts = append(exts, byte(len(name)>>8), byte(len(name)))
	exts = append(exts, name...)
	// supported_versions: TLS 1.3
	exts = append(exts, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04)
	// key_share entries: X25519MLKEM768 hybrid first, optional plain x25519 after
	var entries []byte
	addEntry := func(group uint16, data []byte) {
		entries = append(entries, byte(group>>8), byte(group))
		entries = append(entries, byte(len(data)>>8), byte(len(data)))
		entries = append(entries, data...)
	}
	hybrid := make([]byte, mlkem768EncapsulationKeySize+32)
	copy(hybrid[mlkem768EncapsulationKeySize:], keySharePub)
	if shares != "plain" {
		addEntry(groupX25519MLKEM768, hybrid)
	}
	if shares == "both" || shares == "plain" {
		addEntry(groupX25519, keySharePub)
	}
	extDataLen := 2 + len(entries)
	exts = append(exts, 0x00, 0x33)
	exts = append(exts, byte(extDataLen>>8), byte(extDataLen))
	exts = append(exts, byte(len(entries)>>8), byte(len(entries)))
	exts = append(exts, entries...)

	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := make([]byte, 0, len(body)+4)
	msg = append(msg, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	msg = append(msg, body...)
	return msg
}

func wrapRecord(msg []byte) []byte {
	rec := make([]byte, 0, len(msg)+5)
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(msg)>>8), byte(len(msg)))
	return append(rec, msg...)
}

// sealSessionID produces the REALITY session_id exactly like the Xray client:
// X25519(ephemeral, server public) -> HKDF -> AES-GCM over the 16-byte prefix.
func sealSessionID(t *testing.T, ephemeral *ecdh.PrivateKey, serverPub []byte, random, msgZeroedSID []byte, ts uint32, shortID []byte) []byte {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	ikm, err := ephemeral.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	authKey := hkdfSHA256(ikm, random[:20], []byte("REALITY"), 32)

	plain := make([]byte, 16)
	plain[0], plain[1], plain[2] = 25, 1, 0 // client version
	binary.BigEndian.PutUint32(plain[4:8], ts)
	copy(plain[8:], shortID)

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	return aead.Seal(nil, random[20:32], plain, msgZeroedSID)
}

func TestVerifyRoundTrip(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var random [32]byte
	rand.Read(random[:])
	shortID := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	var privBytes [32]byte
	copy(privBytes[:], serverPriv.Bytes())

	shortIDs := map[[8]byte]bool{}
	shortIDs[[8]byte(shortID)] = true

	// build with zero session_id first (that buffer is the AEAD AAD), then seal
	msg := buildClientHelloMessage(t, random[:], make([]byte, 32), ephemeral.PublicKey().Bytes(), "www.apple.com", "both")
	ch, err := parseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	sid := sealSessionID(t, ephemeral, serverPriv.PublicKey().Bytes(), random[:], ch.Raw, uint32(time.Now().Unix()), shortID)

	msg = buildClientHelloMessage(t, random[:], sid, ephemeral.PublicKey().Bytes(), "www.apple.com", "both")
	ch, err = parseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}

	info := Verify(ch, privBytes, shortIDs, 5*time.Minute)
	if info == nil {
		t.Fatal("verify failed")
	}
	if info.ShortID != [8]byte(shortID) {
		t.Errorf("short id = %x", info.ShortID)
	}

	// tampered session_id must fail
	msg[len(msg)-1] ^= 0xff
	ch, err = parseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(ch, privBytes, shortIDs, 5*time.Minute) != nil {
		t.Error("tampered session id verified")
	}

	// wrong server key must fail
	msg = buildClientHelloMessage(t, random[:], sid, ephemeral.PublicKey().Bytes(), "www.apple.com", "both")
	ch, _ = parseClientHello(msg)
	otherPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var otherBytes [32]byte
	copy(otherBytes[:], otherPriv.Bytes())
	if Verify(ch, otherBytes, shortIDs, 5*time.Minute) != nil {
		t.Error("wrong server key verified")
	}

	// expired timestamp must fail
	sidOld := sealSessionID(t, ephemeral, serverPriv.PublicKey().Bytes(), random[:], ch.Raw, uint32(time.Now().Unix()-6000), shortID)
	msg = buildClientHelloMessage(t, random[:], sidOld, ephemeral.PublicKey().Bytes(), "www.apple.com", "both")
	ch, _ = parseClientHello(msg)
	if Verify(ch, privBytes, shortIDs, 5*time.Minute) != nil {
		t.Error("expired timestamp verified")
	}
}

// The reference rejects ClientHellos without an X25519MLKEM768 key share.
func TestVerifyRequiresHybridShare(t *testing.T) {
	serverPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephemeral, _ := ecdh.X25519().GenerateKey(rand.Reader)

	var random [32]byte
	rand.Read(random[:])
	shortID := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	var privBytes [32]byte
	copy(privBytes[:], serverPriv.Bytes())
	shortIDs := map[[8]byte]bool{}
	shortIDs[[8]byte(shortID)] = true

	// hybrid-only seal, then rebuild with the plain share dropped
	msg := buildClientHelloMessage(t, random[:], make([]byte, 32), ephemeral.PublicKey().Bytes(), "www.apple.com", "plain")
	ch, _ := parseClientHello(msg)
	sid := sealSessionID(t, ephemeral, serverPriv.PublicKey().Bytes(), random[:], ch.Raw, uint32(time.Now().Unix()), shortID)
	msg = buildClientHelloMessage(t, random[:], sid, ephemeral.PublicKey().Bytes(), "www.apple.com", "plain")
	ch, err := parseClientHello(msg)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(ch, privBytes, shortIDs, 5*time.Minute) != nil {
		t.Error("verified a client hello without X25519MLKEM768")
	}
}

func TestReadClientHelloFromConn(t *testing.T) {
	var random [32]byte
	rand.Read(random[:])
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)

	msg := buildClientHelloMessage(t, random[:], make([]byte, 32), key.PublicKey().Bytes(), "example.com", "hybrid")
	rec := wrapRecord(msg)

	client, server := net.Pipe()
	go client.Write(rec)

	ch, raw, err := ReadClientHello(server)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(rec) {
		t.Errorf("consumed %d bytes, want %d", len(raw), len(rec))
	}
	if ch.ServerName != "example.com" {
		t.Errorf("server name = %q", ch.ServerName)
	}
	if !ch.SupportsTLS13 {
		t.Error("supports TLS 1.3 not detected")
	}
	if len(ch.KeyShares) != 1 || ch.KeyShares[0].Group != groupX25519MLKEM768 {
		t.Errorf("key shares = %+v", ch.KeyShares)
	}
	// Raw must equal the message with a zeroed session_id
	if len(ch.Raw) != len(msg) {
		t.Fatalf("raw length %d, want %d", len(ch.Raw), len(msg))
	}
	want := append([]byte(nil), msg...)
	copy(want[39:71], make([]byte, 32))
	for i := range want {
		if ch.Raw[i] != want[i] {
			t.Fatalf("raw differs at %d: %x != %x", i, ch.Raw[i], want[i])
		}
	}
}
