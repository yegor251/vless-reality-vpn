package vless

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

type UserID [16]byte

func ParseUserID(s string) (UserID, error) {
	var id UserID
	cleaned := strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(s, "urn:uuid:")), "-", "")
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return id, fmt.Errorf("invalid uuid %q: %w", s, err)
	}
	if len(b) != 16 {
		return id, fmt.Errorf("invalid uuid %q: want 32 hex digits, got %d", s, hex.EncodedLen(len(b)))
	}
	copy(id[:], b)
	return id, nil
}

func NewUserID() (UserID, error) {
	var id UserID
	_, err := rand.Read(id[:])
	return id, err
}

func (id UserID) String() string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
