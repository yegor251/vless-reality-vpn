package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type User struct {
	ID string `json:"id"`
}

type Reality struct {
	Dest           string   `json:"dest"`
	ServerNames    []string `json:"server_names"`
	PrivateKey     string   `json:"private_key"` // base64, 32 bytes
	ShortIds       []string `json:"short_ids"`   // hex, up to 8 bytes each
	MaxTimeDiffSec int      `json:"max_time_diff_sec"`
}

type Server struct {
	Listen  string   `json:"listen"`
	Users   []User   `json:"users"`
	Reality *Reality `json:"reality"`
}

func Load(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Server
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Listen == "" {
		return nil, fmt.Errorf("listen is required")
	}
	if len(s.Users) == 0 {
		return nil, fmt.Errorf("at least one user is required")
	}
	return &s, nil
}
