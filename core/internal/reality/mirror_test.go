package reality

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

// buildServerHelloRecord assembles a wire ServerHello record the way a dest
// would send it.
func buildServerHelloRecord(t *testing.T, suiteID uint16, group uint16, share []byte) []byte {
	t.Helper()
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, 32)                             // session id length
	body = append(body, bytes.Repeat([]byte{9}, 32)...)
	body = append(body, byte(suiteID>>8), byte(suiteID), 0x00)

	var exts []byte
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions: 1.3
	ksLen := len(share) + 4
	exts = append(exts, 0x00, 0x33, byte(ksLen>>8), byte(ksLen),
		byte(group>>8), byte(group), byte(len(share)>>8), byte(len(share)))
	exts = append(exts, share...)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	msg := handshakeMsg(handshakeTypeServerHello, body)
	rec := append([]byte{recordTypeHandshake, 0x03, 0x03, byte(len(msg) >> 8), byte(len(msg))}, msg...)
	return rec
}

func TestParseServerHelloRecord(t *testing.T) {
	rec := buildServerHelloRecord(t, 0x1302, groupX25519MLKEM768, bytes.Repeat([]byte{1}, mlkem768CiphertextSize+32))
	f, err := newDestFlight(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !f.isMirrored() || f.suiteID != 0x1302 || f.group != groupX25519MLKEM768 {
		t.Fatalf("flight: mirrored=%v suite=%04x group=%04x", f.isMirrored(), f.suiteID, f.group)
	}
	if f.shareLen != mlkem768CiphertextSize+32 {
		t.Fatalf("share len %d", f.shareLen)
	}
	// patching must not change the record length
	before := len(rec)
	copy(rec[f.shareOff:f.shareOff+f.shareLen], bytes.Repeat([]byte{2}, f.shareLen))
	if len(rec) != before {
		t.Fatal("share patch changed record length")
	}
}

func TestSuitePatchedToAES128(t *testing.T) {
	rec := buildServerHelloRecord(t, 0x1303, groupX25519, bytes.Repeat([]byte{1}, 32))
	f, err := newDestFlight(rec)
	if err != nil {
		t.Fatal(err)
	}
	if f.suiteID != 0x1301 {
		t.Fatalf("suite = %04x, want 1301", f.suiteID)
	}
	// the bytes were patched in place: re-parse and confirm
	patch, err := parseServerHelloRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if patch.suiteID != 0x1301 {
		t.Fatalf("re-parsed suite = %04x, want 1301", patch.suiteID)
	}
}

func TestParseServerHelloRejects(t *testing.T) {
	bad := buildServerHelloRecord(t, 0x1301, groupX25519, bytes.Repeat([]byte{1}, 32))
	// TLS 1.2 supported_versions
	bad[5+4+2+32+1+32+2+1+2+4+2] = 0x03
	if _, err := parseServerHelloRecord(bad); err == nil {
		t.Fatal("accepted non-1.3 server hello")
	}
	// unsupported group (secp256r1)
	bad2 := buildServerHelloRecord(t, 0x1301, 0x0017, bytes.Repeat([]byte{1}, 32))
	if _, err := parseServerHelloRecord(bad2); err == nil {
		t.Fatal("accepted secp256r1 share")
	}
}

func TestNegotiateForGroupPlainX25519(t *testing.T) {
	clientKey, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	shares := []KeyShare{{Group: groupX25519, Data: clientKey.PublicKey().Bytes()}}
	serverShare, ss, err := negotiateForGroup(shares, groupX25519)
	if err != nil {
		t.Fatal(err)
	}
	if len(serverShare) != 32 || len(ss) != 32 {
		t.Fatalf("share %d, secret %d", len(serverShare), len(ss))
	}
	srvPub, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		t.Fatal(err)
	}
	want, err := clientKey.ECDH(srvPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, want) {
		t.Fatal("shared secret mismatch")
	}
}
