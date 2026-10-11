package reality

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Dest mirroring, per the reference REALITY: the camouflage target's
// handshake response is used as a template for our own — its ServerHello
// record is echoed verbatim (with our key share patched in) and the
// encrypted flight is padded so every record matches the length of the
// corresponding dest record. A passive observer cannot tell our handshake
// from a genuine one by record sizes.

const (
	flightBudget = 3 * time.Second
	extraIdle    = 40 * time.Millisecond
	maxExtraRecs = 2
)

type destFlight struct {
	serverHello []byte // full ServerHello record from dest (or a synthetic handshake message)
	mirrored    bool   // true when serverHello is a dest record to echo verbatim
	suiteID     uint16
	group       uint16
	shareOff    int // offset of the key share inside serverHello
	shareLen    int
	appLens     [4]int // lengths of dest's first four app-data records
	nstLen      int    // fifth record (NewSessionTicket), 0 if none
	postLens    []int  // further records, fake post-handshake material
}

func (f *destFlight) isMirrored() bool { return f != nil && f.mirrored }

// readDestFlight forwards the original ClientHello to dest and mirrors the
// response. It returns nil when dest does not answer the way the reference
// expects (caller falls back to a transparent relay).
func readDestFlight(cfg *Config, clientHello []byte) *destFlight {
	target, err := net.DialTimeout("tcp", cfg.Dest, cfg.DialTimeout)
	if err != nil {
		return nil
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(flightBudget))
	if _, err := target.Write(clientHello); err != nil {
		return nil
	}

	typ, rec, err := readWireRecord(target)
	if err != nil || typ != recordTypeHandshake {
		return nil
	}
	f, err := newDestFlight(rec)
	if err != nil || f == nil {
		return nil
	}

	typ, rec, err = readWireRecord(target)
	if err != nil || typ != recordTypeChangeCipherSpec || len(rec) != 6 {
		return nil
	}

	appCount := 0
	for appCount < 4+1+maxExtraRecs {
		if appCount >= 4 {
			target.SetReadDeadline(time.Now().Add(extraIdle))
		}
		typ, rec, err = readWireRecord(target)
		if err != nil {
			if appCount >= 4 && isTimeout(err) {
				break
			}
			return nil
		}
		if typ != recordTypeApplicationData {
			if appCount >= 4 {
				break
			}
			return nil
		}
		switch {
		case appCount < 4:
			f.appLens[appCount] = len(rec)
		case appCount == 4:
			f.nstLen = len(rec)
		default:
			f.postLens = append(f.postLens, len(rec))
		}
		appCount++
	}
	return f
}

// newDestFlight validates a dest ServerHello record and records where our
// key share must be patched in. Cipher suites we cannot serve are replaced
// in place with TLS_AES_128_GCM_SHA256 (same length, and the transcript is
// computed over the patched bytes, so both sides stay consistent).
func newDestFlight(rec []byte) (*destFlight, error) {
	patch, err := parseServerHelloRecord(rec)
	if err != nil {
		return nil, err
	}
	if patch.suiteID != cipherSuites[0].id && patch.suiteID != cipherSuites[1].id {
		rec[patch.suiteOff], rec[patch.suiteOff+1] = byte(cipherSuites[0].id>>8), byte(cipherSuites[0].id)
		patch.suiteID = cipherSuites[0].id
	}
	return &destFlight{
		serverHello: rec,
		mirrored:    true,
		suiteID:     patch.suiteID,
		group:       patch.group,
		shareOff:    patch.shareOff,
		shareLen:    patch.shareLen,
	}, nil
}

type shPatch struct {
	group     uint16
	suiteID   uint16
	suiteOff  int
	shareOff  int
	shareLen  int
}

func parseServerHelloRecord(rec []byte) (*shPatch, error) {
	if len(rec) < 5+4+2+32+1+2+1+2 {
		return nil, errors.New("mirror: short server hello record")
	}
	body := rec[5:]
	if body[0] != handshakeTypeServerHello {
		return nil, errors.New("mirror: not a server hello")
	}
	i := 4 + 2 + 32 // handshake header, version, random
	sidLen := int(body[i])
	i += 1 + sidLen
	if len(body) < i+2+1+2 {
		return nil, errors.New("mirror: truncated server hello")
	}
	p := &shPatch{
		suiteID:  uint16(body[i])<<8 | uint16(body[i+1]),
		suiteOff: 5 + i,
	}
	i += 2 + 1 // cipher suite, compression method
	extEnd := i + 2 + (int(body[i])<<8 | int(body[i+1]))
	i += 2
	if extEnd > len(body) {
		return nil, errors.New("mirror: bad extensions length")
	}
	sawVersions := false
	for i+4 <= extEnd {
		extType := int(body[i])<<8 | int(body[i+1])
		extLen := int(body[i+2])<<8 | int(body[i+3])
		i += 4
		if i+extLen > extEnd {
			return nil, errors.New("mirror: bad extension length")
		}
		ext := body[i : i+extLen]
		switch extType {
		case 0x002b: // supported_versions
			if extLen != 2 || ext[0] != 0x03 || ext[1] != 0x04 {
				return nil, errors.New("mirror: server hello is not TLS 1.3")
			}
			sawVersions = true
		case 0x0033: // key_share
			if extLen < 4 {
				return nil, errors.New("mirror: bad key share")
			}
			group := uint16(ext[0])<<8 | uint16(ext[1])
			shareLen := int(ext[2])<<8 | int(ext[3])
			switch {
			case group == groupX25519 && shareLen == 32,
				group == groupX25519MLKEM768 && shareLen == mlkem768CiphertextSize+32:
				p.group, p.shareLen, p.shareOff = group, shareLen, 5+i+4
			default:
				return nil, fmt.Errorf("mirror: unsupported key share group 0x%04x", group)
			}
		}
		i += extLen
	}
	if !sawVersions || p.shareOff == 0 {
		return nil, errors.New("mirror: missing supported_versions or key_share")
	}
	return p, nil
}

func readWireRecord(r io.Reader) (byte, []byte, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return 0, nil, err
	}
	n := int(head[3])<<8 | int(head[4])
	if n == 0 || n > 1<<14+256 {
		return 0, nil, fmt.Errorf("mirror: bad record length %d", n)
	}
	rec := make([]byte, 5+n)
	copy(rec, head)
	if _, err := io.ReadFull(r, rec[5:]); err != nil {
		return 0, nil, err
	}
	return rec[0], rec, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// negotiateForGroup performs the key exchange against the client's share
// matching the group the dest ServerHello advertised, so the patched share
// length stays identical.
func negotiateForGroup(shares []KeyShare, group uint16) (serverShare, sharedSecret []byte, err error) {
	var hybrid, plain *KeyShare
	for i := range shares {
		ks := &shares[i]
		switch {
		case ks.Group == groupX25519MLKEM768 && len(ks.Data) == mlkem768EncapsulationKeySize+32:
			hybrid = ks
		case ks.Group == groupX25519 && len(ks.Data) == 32:
			plain = ks
		}
	}
	if group == groupX25519MLKEM768 {
		if hybrid == nil {
			return nil, nil, errors.New("mirror: client lacks the hybrid share")
		}
		k, err := mlkem.NewEncapsulationKey768(hybrid.Data[:mlkem768EncapsulationKeySize])
		if err != nil {
			return nil, nil, err
		}
		mlkemSS, ct := k.Encapsulate()
		xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		pub, err := ecdh.X25519().NewPublicKey(hybrid.Data[mlkem768EncapsulationKeySize:])
		if err != nil {
			return nil, nil, err
		}
		xSS, err := xkey.ECDH(pub)
		if err != nil {
			return nil, nil, err
		}
		share := append(append([]byte{}, ct...), xkey.PublicKey().Bytes()...)
		return share, append(mlkemSS, xSS...), nil
	}
	peer := plain
	if peer == nil && hybrid != nil {
		tail := KeyShare{Group: groupX25519, Data: hybrid.Data[mlkem768EncapsulationKeySize:]}
		peer = &tail
	}
	if peer == nil {
		return nil, nil, errors.New("mirror: client lacks an x25519 share")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peer.Data)
	if err != nil {
		return nil, nil, err
	}
	ss, err := key.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	return key.PublicKey().Bytes(), ss, nil
}
