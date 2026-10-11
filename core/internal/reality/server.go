package reality

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Config struct {
	PrivateKey  [32]byte
	ServerNames map[string]bool
	ShortIds    map[[8]byte]bool
	MaxTimeDiff time.Duration // 0 disables the timestamp check
	Dest        string        // camouflage target, host:port
	DialTimeout time.Duration
}

const handshakeTimeout = 15 * time.Second

// Handle processes an incoming connection. On successful REALITY
// authentication it returns an established TLS 1.3 connection carrying the
// client's stream. Otherwise the connection is transparently relayed to Dest
// (blocking until the relay ends, so a prober sees the real target site) and
// nil is returned.
func Handle(conn net.Conn, cfg *Config) net.Conn {
	ch, raw, err := ReadClientHello(conn)
	if err != nil {
		log.Printf("%s: read client hello: %v", conn.RemoteAddr(), err)
		fallback(conn, cfg, raw)
		return nil
	}
	if !cfg.ServerNames[ch.ServerName] {
		log.Printf("%s: server name mismatch: %q", conn.RemoteAddr(), ch.ServerName)
		fallback(conn, cfg, raw)
		return nil
	}
	info := Verify(ch, cfg.PrivateKey, cfg.ShortIds, cfg.MaxTimeDiff)
	if info == nil {
		log.Printf("%s: reality auth failed", conn.RemoteAddr())
		fallback(conn, cfg, raw)
		return nil
	}

	// The dest must answer like a TLS 1.3 server, as in the reference
	// implementation — it doubles as a liveness check for the camouflage and
	// provides the handshake template our flight is mirrored onto.
	flight := readDestFlight(cfg, raw)
	if flight == nil {
		log.Printf("%s: dest oracle failed", conn.RemoteAddr())
		fallback(conn, cfg, raw)
		return nil
	}

	certDER, certPriv := buildCert(info.AuthKey)
	if deadline, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		deadline.SetDeadline(time.Now().Add(handshakeTimeout))
		defer deadline.SetDeadline(time.Time{})
	}
	tlsConn, err := serverHandshake(conn, ch, certDER, certPriv, flight)
	if err != nil {
		log.Printf("%s: tls handshake: %v", conn.RemoteAddr(), err)
		conn.Close()
		return nil
	}
	log.Printf("%s: reality established", conn.RemoteAddr())
	return tlsConn
}

// fallback relays the connection to Dest, writing any already consumed bytes
// first. It returns only after both directions are done.
func fallback(conn net.Conn, cfg *Config, first []byte) {
	target, err := net.DialTimeout("tcp", cfg.Dest, cfg.DialTimeout)
	if err != nil {
		log.Printf("fallback dial %s: %v", cfg.Dest, err)
		conn.Close()
		return
	}
	defer target.Close()
	if len(first) > 0 {
		if _, err := target.Write(first); err != nil {
			return
		}
	}
	done := make(chan struct{})
	go func() {
		io.Copy(target, conn)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()
	io.Copy(conn, target)
	<-done
}

// NewConfig parses the wire-format fields of the server REALITY settings.
func NewConfig(dest string, serverNames []string, privateKeyB64 string, shortIdsHex []string, maxTimeDiff time.Duration) (*Config, error) {
	if dest == "" {
		return nil, errors.New("reality: dest is required")
	}
	if len(serverNames) == 0 {
		return nil, errors.New("reality: at least one server name is required")
	}
	priv, err := base64.RawURLEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("reality: private key: %w", err)
	}
	if len(priv) != 32 {
		return nil, errors.New("reality: private key must decode to 32 bytes")
	}

	cfg := &Config{
		ServerNames: make(map[string]bool, len(serverNames)),
		ShortIds:    make(map[[8]byte]bool, len(shortIdsHex)),
		MaxTimeDiff: maxTimeDiff,
		Dest:        dest,
		DialTimeout: 10 * time.Second,
	}
	copy(cfg.PrivateKey[:], priv)
	for _, n := range serverNames {
		cfg.ServerNames[n] = true
	}
	for _, s := range shortIdsHex {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("reality: short id %q: %w", s, err)
		}
		if len(b) > 8 {
			return nil, fmt.Errorf("reality: short id %q longer than 8 bytes", s)
		}
		var id [8]byte
		copy(id[:], b)
		cfg.ShortIds[id] = true
	}
	return cfg, nil
}
