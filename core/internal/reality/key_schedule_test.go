package reality

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The early secret is the RFC 8448 section 3 intermediate; the derived and
// handshake secrets are cross-checked against an independent Python
// implementation of RFC 8446 section 7.1.
func TestKeyScheduleRFC8448(t *testing.T) {
	h := sha256.New
	ecdhe, _ := hex.DecodeString("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
	wantEarly, _ := hex.DecodeString("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	wantDerived, _ := hex.DecodeString("d65dba9d40e954898205baa678a8c288ac6a51b094ba120dead316d3b247f663")
	wantHS, _ := hex.DecodeString("08c1c949d24009c3b14ed7c56e35801955e5bcf09a403db342bfcb6eeb8669e9")

	early := hkdfExtract(h, zeros(h), zeros(h))
	if string(early) != string(wantEarly) {
		t.Errorf("early secret = %x, want %x", early, wantEarly)
	}
	derived := hkdfExpandLabel(h, early, "derived", nil, 32)
	if string(derived) != string(wantDerived) {
		t.Errorf("derived = %x, want %x", derived, wantDerived)
	}
	hs := hkdfExtract(h, derived, ecdhe)
	if string(hs) != string(wantHS) {
		t.Errorf("handshake secret = %x, want %x", hs, wantHS)
	}
}
