package auth

import (
	"crypto/subtle"

	"vpn/internal/config"
	"vpn/internal/vless"
)

type Store struct {
	ids []vless.UserID
}

func NewStore(users []config.User) (*Store, error) {
	ids := make([]vless.UserID, 0, len(users))
	for _, u := range users {
		id, err := vless.ParseUserID(u.ID)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return &Store{ids: ids}, nil
}

func (s *Store) Authenticate(id vless.UserID) bool {
	for _, known := range s.ids {
		if subtle.ConstantTimeCompare(known[:], id[:]) == 1 {
			return true
		}
	}
	return false
}
