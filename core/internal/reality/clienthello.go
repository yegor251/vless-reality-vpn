package reality

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1

	groupX25519         uint16 = 0x001d // IANA: 29
	groupX25519MLKEM768 uint16 = 0x11ec // IANA: 4588

	mlkem768EncapsulationKeySize = 1184
	mlkem768CiphertextSize       = 1088
	maxRecordSize                = 16384 + 1024
)

type KeyShare struct {
	Group uint16
	Data  []byte
}

type ClientHello struct {
	// Raw is the full handshake message bytes (type, length, body) with the
	// session_id contents zeroed — this is the AEAD associated data.
	Raw          []byte
	RawOriginal  []byte // same bytes exactly as received, for the TLS transcript
	SessionID    []byte // session_id as received (REALITY ciphertext)
	Random       []byte // 32 bytes
	ServerName   string
	ALPN         []string
	CipherSuites []uint16
	KeyShares    []KeyShare
	SupportsTLS13 bool
}

func be16(b []byte) int { return int(b[0])<<8 | int(b[1]) }

// ReadClientHello reads the first ClientHello from conn, returning the parsed
// hello and every byte consumed from conn (the caller needs the raw bytes to
// replay the message to a TLS server or relay it to the camouflage target).
func ReadClientHello(conn net.Conn) (*ClientHello, []byte, error) {
	var consumed []byte
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, consumed, fmt.Errorf("read record header: %w", err)
		}
		if header[0] != recordTypeHandshake {
			return nil, consumed, fmt.Errorf("not a handshake record: type %d", header[0])
		}
		length := be16(header[3:5])
		if length == 0 || length > maxRecordSize {
			return nil, consumed, fmt.Errorf("bad record length %d", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, consumed, fmt.Errorf("read record body: %w", err)
		}
		consumed = append(consumed, header...)
		consumed = append(consumed, payload...)

		if len(payload) < 4 {
			return nil, consumed, errors.New("short handshake message")
		}
		if payload[0] != handshakeTypeClientHello {
			return nil, consumed, fmt.Errorf("not a client hello: type %d", payload[0])
		}
		msgLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
		if msgLen < 40 || 4+msgLen > maxRecordSize {
			return nil, consumed, fmt.Errorf("bad client hello length %d", msgLen)
		}
		if len(payload) >= 4+msgLen {
			ch, err := parseClientHello(payload[:4+msgLen])
			return ch, consumed, err
		}
		// the message spans several records; keep reading
	}
}

func parseClientHello(msg []byte) (*ClientHello, error) {
	body := msg[4:]
	if len(body) < 35+2+1+1 {
		return nil, errors.New("client hello too short")
	}

	sidLen := int(body[34])
	if len(body) < 35+sidLen {
		return nil, errors.New("truncated session id")
	}
	sid := body[35 : 35+sidLen]

	off := 35 + sidLen
	if len(body) < off+2 {
		return nil, errors.New("truncated cipher suites")
	}
	csLen := be16(body[off : off+2])
	if csLen%2 == 1 || len(body) < off+2+csLen {
		return nil, errors.New("bad cipher suites length")
	}
	ch := &ClientHello{
		Random:    bytes.Clone(body[2:34]),
		SessionID: bytes.Clone(sid),
	}
	for p := off + 2; p < off+2+csLen; p += 2 {
		ch.CipherSuites = append(ch.CipherSuites, uint16(be16(body[p:p+2])))
	}
	off += 2 + csLen

	if len(body) < off+1 {
		return nil, errors.New("truncated compression methods")
	}
	off += 1 + int(body[off])

	if len(body) < off+2 {
		return nil, errors.New("truncated extensions length")
	}
	extEnd := off + 2 + be16(body[off:off+2])
	if extEnd > len(body) {
		return nil, errors.New("truncated extensions")
	}
	off += 2

	for off+4 <= extEnd {
		extType := uint16(be16(body[off : off+2]))
		extLen := be16(body[off+2 : off+4])
		off += 4
		if off+extLen > extEnd {
			return nil, errors.New("truncated extension")
		}
		data := body[off : off+extLen]
		off += extLen

		switch extType {
		case 0: // server_name
			if len(data) >= 5 && data[2] == 0 {
				nameLen := be16(data[3:5])
				if 5+nameLen <= len(data) {
					ch.ServerName = string(data[5 : 5+nameLen])
				}
			}
		case 16: // ALPN
			if len(data) >= 2 {
				listEnd := 2 + be16(data[0:2])
				if listEnd <= len(data) {
					for p := 2; p+1 <= listEnd; {
						protoLen := int(data[p])
						if p+1+protoLen > listEnd {
							break
						}
						ch.ALPN = append(ch.ALPN, string(data[p+1:p+1+protoLen]))
						p += 1 + protoLen
					}
				}
			}
		case 43: // supported_versions
			if len(data) >= 1 {
				vlen := int(data[0])
				for i := 1; i+1 < len(data) && i <= vlen; i += 2 {
					if data[i] == 0x03 && data[i+1] == 0x04 {
						ch.SupportsTLS13 = true
					}
				}
			}
		case 51: // key_share
			if len(data) >= 2 {
				listEnd := 2 + be16(data[0:2])
				if listEnd <= len(data) {
					for p := 2; p+4 <= listEnd; {
						group := uint16(be16(data[p : p+2]))
						shareLen := be16(data[p+2 : p+4])
						p += 4
						if p+shareLen > listEnd {
							break
						}
						ch.KeyShares = append(ch.KeyShares, KeyShare{Group: group, Data: data[p : p+shareLen]})
						p += shareLen
					}
				}
			}
		}
	}

	ch.RawOriginal = bytes.Clone(msg)
	ch.Raw = bytes.Clone(msg)
	copy(ch.Raw[39:39+sidLen], make([]byte, sidLen))
	return ch, nil
}
