package reality

// A minimal TLS 1.3 server handshake, just enough for REALITY: it completes
// the handshake with the ClientHello we already hold and always signs
// CertificateVerify with the ed25519 certificate key, ignoring the client's
// offered signature algorithms the way the reference implementation does.
// Record framing and the key schedule follow RFC 8446.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
)

const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeApplicationData  = 23

	handshakeTypeServerHello     = 2
	handshakeTypeEncryptedExt    = 8
	handshakeTypeCertificate     = 11
	handshakeTypeCertificateVer  = 15
	handshakeTypeFinished        = 20
	handshakeTypeKeyUpdate       = 24

	ed25519SigAlg = 0x0807
)

type suiteInfo struct {
	id      uint16
	hash    func() hash.Hash
	keyLen  int
	newAEAD func(key []byte) (cipher.AEAD, error)
}

var cipherSuites = []suiteInfo{
	{0x1301, sha256.New, 16, newAESGCM},
	{0x1302, sha512.New384, 32, newAESGCM},
}

func newAESGCM(k []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

var (
	serverSignatureContext = []byte("TLS 1.3, server CertificateVerify\x00")
	signaturePadding       = bytes.Repeat([]byte{0x20}, 64)
)

func hkdfExtract(h func() hash.Hash, salt, ikm []byte) []byte {
	mac := hmac.New(h, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// zeros returns a zero string of the hash length, as in the RFC 8446
// HKDF-Extract(salt=0, IKM=0) notation.
func zeros(h func() hash.Hash) []byte {
	return make([]byte, h().Size())
}

func hkdfExpand(h func() hash.Hash, prk, info []byte, length int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(h, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// hkdfExpandLabel implements RFC 8446 section 7.1.
func hkdfExpandLabel(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	fullLabel := append([]byte("tls13 "), label...)
	var info []byte
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return hkdfExpand(h, secret, info, length)
}

func deriveSecret(h func() hash.Hash, secret []byte, label string, transcript hash.Hash) []byte {
	return hkdfExpandLabel(h, secret, label, transcript.Sum(nil), h().Size())
}

func finishedKey(h func() hash.Hash, trafficSecret []byte) []byte {
	return hkdfExpandLabel(h, trafficSecret, "finished", nil, h().Size())
}

func pickSuite(client []uint16) (suiteInfo, error) {
	for _, s := range cipherSuites {
		for _, c := range client {
			if c == s.id {
				return s, nil
			}
		}
	}
	return suiteInfo{}, errors.New("no common cipher suite")
}

// negotiateKeyShare encapsulates against the client's X25519MLKEM768 share
// (Verify already made its presence mandatory) and returns the group, the
// server share to echo, and the concatenated shared secret.
func negotiateKeyShare(shares []KeyShare) (group uint16, serverShare, sharedSecret []byte, err error) {
	for _, ks := range shares {
		if ks.Group != groupX25519MLKEM768 || len(ks.Data) != mlkem768EncapsulationKeySize+32 {
			continue
		}
		k, err := mlkem.NewEncapsulationKey768(ks.Data[:mlkem768EncapsulationKeySize])
		if err != nil {
			return 0, nil, nil, err
		}
		mlkemSS, ct := k.Encapsulate()
		xkey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return 0, nil, nil, err
		}
		pub, err := ecdh.X25519().NewPublicKey(ks.Data[mlkem768EncapsulationKeySize:])
		if err != nil {
			return 0, nil, nil, err
		}
		xSS, err := xkey.ECDH(pub)
		if err != nil {
			return 0, nil, nil, err
		}
		sharedSecret = append(mlkemSS, xSS...)
		serverShare = append(append([]byte{}, ct...), xkey.PublicKey().Bytes()...)
		return groupX25519MLKEM768, serverShare, sharedSecret, nil
	}
	return 0, nil, nil, errors.New("no usable key share")
}

func handshakeMsg(msgType byte, body []byte) []byte {
	m := make([]byte, 0, 4+len(body))
	m = append(m, msgType, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(m, body...)
}

// tls13Conn is the established connection returned after the handshake.
type tls13Conn struct {
	net.Conn // underlying transport; deadlines pass through
	suite    suiteInfo

	readAEAD, writeAEAD cipher.AEAD
	readIV, writeIV     []byte
	readSeq, writeSeq   uint64
	readSecret          []byte // current read application secret, for KeyUpdate

	pending []byte // bytes read off the wire but not yet parsed into records
	plain   []byte // decrypted application data not yet returned by Read
}

func (c *tls13Conn) setReadKeys(secret []byte) error {
	aead, iv, err := trafficKeys(c.suite, secret)
	if err != nil {
		return err
	}
	c.readAEAD, c.readIV, c.readSeq = aead, iv, 0
	return nil
}

func (c *tls13Conn) setWriteKeys(secret []byte) error {
	aead, iv, err := trafficKeys(c.suite, secret)
	if err != nil {
		return err
	}
	c.writeAEAD, c.writeIV, c.writeSeq = aead, iv, 0
	return nil
}

func trafficKeys(s suiteInfo, secret []byte) (cipher.AEAD, []byte, error) {
	key := hkdfExpandLabel(s.hash, secret, "key", nil, s.keyLen)
	iv := hkdfExpandLabel(s.hash, secret, "iv", nil, 12)
	aead, err := s.newAEAD(key)
	return aead, iv, err
}

func (c *tls13Conn) nonce(iv []byte, seq uint64) []byte {
	n := append([]byte{}, iv...)
	binary.BigEndian.PutUint64(n[4:], binary.BigEndian.Uint64(n[4:])^seq)
	return n
}

func (c *tls13Conn) readN(n int) ([]byte, error) {
	for len(c.pending) < n {
		buf := make([]byte, 4096)
		nr, err := c.Conn.Read(buf)
		if nr > 0 {
			c.pending = append(c.pending, buf[:nr]...)
		}
		if err != nil {
			return nil, err
		}
	}
	b := c.pending[:n]
	c.pending = c.pending[n:]
	return b, nil
}

func (c *tls13Conn) readPhysicalRecord() (byte, []byte, error) {
	head, err := c.readN(5)
	if err != nil {
		return 0, nil, err
	}
	length := int(head[3])<<8 | int(head[4])
	if length == 0 || length > 1<<14+256 {
		return 0, nil, fmt.Errorf("bad record length %d", length)
	}
	body, err := c.readN(length)
	if err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

func (c *tls13Conn) decrypt(body []byte, recordType byte) ([]byte, error) {
	header := []byte{recordType, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}
	plain, err := c.readAEAD.Open(nil, c.nonce(c.readIV, c.readSeq), body, header)
	if err != nil {
		return nil, err
	}
	c.readSeq++
	return plain, nil
}

// readRecord returns the inner content type and plaintext of the next record.
func (c *tls13Conn) readRecord() (byte, []byte, error) {
	for {
		typ, body, err := c.readPhysicalRecord()
		if err != nil {
			return 0, nil, err
		}
		switch typ {
		case recordTypeChangeCipherSpec:
			continue // middlebox compatibility
		case recordTypeAlert:
			return typ, body, nil
		case recordTypeHandshake, recordTypeApplicationData:
			if c.readAEAD == nil {
				if typ != recordTypeHandshake {
					return 0, nil, errors.New("unexpected application data")
				}
				return typ, body, nil
			}
			plain, err := c.decrypt(body, typ)
			if err != nil {
				return 0, nil, err
			}
			if len(plain) == 0 {
				return 0, nil, errors.New("empty record")
			}
			return plain[len(plain)-1], plain[:len(plain)-1], nil
		default:
			return 0, nil, fmt.Errorf("unexpected record type %d", typ)
		}
	}
}

func (c *tls13Conn) writePlainRecord(recordType byte, payload []byte) error {
	_, err := c.Conn.Write([]byte{recordType, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))})
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(payload)
	return err
}

func (c *tls13Conn) writeRecord(innerType byte, payload []byte) error {
	inner := append(append([]byte{}, payload...), innerType)
	header := []byte{recordTypeApplicationData, 0x03, 0x03,
		byte((len(inner) + c.writeAEAD.Overhead()) >> 8), byte(len(inner) + c.writeAEAD.Overhead())}
	cipherText := c.writeAEAD.Seal(nil, c.nonce(c.writeIV, c.writeSeq), inner, header)
	c.writeSeq++
	_, err := c.Conn.Write(append(header, cipherText...))
	return err
}

// serverHandshake drives the TLS 1.3 server side. ch must be the parse of
// the ClientHello received on conn (raw bytes already consumed from it).
func serverHandshake(conn net.Conn, ch *ClientHello, certDER []byte, certPriv ed25519.PrivateKey) (*tls13Conn, error) {
	suite, err := pickSuite(ch.CipherSuites)
	if err != nil {
		return nil, err
	}
	group, serverShare, sharedSecret, err := negotiateKeyShare(ch.KeyShares)
	if err != nil {
		return nil, err
	}

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	var shExts []byte
	shExts = append(shExts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions
	ksLen := len(serverShare) + 4
	shExts = append(shExts, 0x00, 0x33, byte(ksLen>>8), byte(ksLen),
		byte(group>>8), byte(group), byte(len(serverShare)>>8), byte(len(serverShare)))
	shExts = append(shExts, serverShare...)

	shBody := []byte{0x03, 0x03}
	shBody = append(shBody, serverRandom...)
	shBody = append(shBody, byte(len(ch.SessionID)))
	shBody = append(shBody, ch.SessionID...)
	shBody = append(shBody, byte(suite.id>>8), byte(suite.id), 0x00)
	shBody = append(shBody, byte(len(shExts)>>8), byte(len(shExts)))
	shBody = append(shBody, shExts...)
	serverHello := handshakeMsg(handshakeTypeServerHello, shBody)

	th := suite.hash()
	th.Write(ch.RawOriginal)

	c := &tls13Conn{Conn: conn, suite: suite}
	if err := c.writePlainRecord(recordTypeHandshake, serverHello); err != nil {
		return nil, err
	}
	th.Write(serverHello)

	early := hkdfExtract(suite.hash, zeros(suite.hash), zeros(suite.hash))
	derived1 := deriveSecret(suite.hash, early, "derived", suite.hash())
	handshakeSecret := hkdfExtract(suite.hash, derived1, sharedSecret)
	chsSecret := deriveSecret(suite.hash, handshakeSecret, "c hs traffic", th)
	shsSecret := deriveSecret(suite.hash, handshakeSecret, "s hs traffic", th)
	if err := c.setWriteKeys(shsSecret); err != nil {
		return nil, err
	}
	if err := c.setReadKeys(chsSecret); err != nil {
		return nil, err
	}

	var flight []byte
	ee := buildEncryptedExtensions(ch)
	th.Write(ee)
	flight = append(flight, ee...)

	certMsg := buildCertificateMsg(certDER)
	th.Write(certMsg)
	flight = append(flight, certMsg...)

	cvInput := append(append([]byte{}, signaturePadding...), serverSignatureContext...)
	cvInput = append(cvInput, th.Sum(nil)...)
	cv := handshakeMsg(handshakeTypeCertificateVer, append([]byte{0x08, 0x07, 0x00, 0x40}, ed25519.Sign(certPriv, cvInput)...))
	th.Write(cv)
	flight = append(flight, cv...)

	fin := hmac.New(suite.hash, finishedKey(suite.hash, shsSecret))
	fin.Write(th.Sum(nil))
	finMsg := handshakeMsg(handshakeTypeFinished, fin.Sum(nil))
	th.Write(finMsg)
	flight = append(flight, finMsg...)

	if err := c.writeRecord(recordTypeHandshake, flight); err != nil {
		return nil, err
	}

	if err := c.readClientFinished(th, chsSecret); err != nil {
		return nil, err
	}

	derived2 := deriveSecret(suite.hash, handshakeSecret, "derived", suite.hash())
	master := hkdfExtract(suite.hash, derived2, zeros(suite.hash))
	caps := deriveSecret(suite.hash, master, "c ap traffic", th)
	saps := deriveSecret(suite.hash, master, "s ap traffic", th)
	c.readSecret = caps
	if err := c.setReadKeys(caps); err != nil {
		return nil, err
	}
	if err := c.setWriteKeys(saps); err != nil {
		return nil, err
	}
	return c, nil
}

func buildEncryptedExtensions(ch *ClientHello) []byte {
	selected := ""
	for _, want := range []string{"h2", "http/1.1"} {
		for _, offered := range ch.ALPN {
			if offered == want {
				selected = want
				break
			}
		}
		if selected != "" {
			break
		}
	}
	var body []byte
	if selected != "" {
		ext := append([]byte{0x00, 0x10, byte((len(selected) + 3) >> 8), byte(len(selected) + 3),
			byte((len(selected) + 1) >> 8), byte(len(selected) + 1), byte(len(selected))}, selected...)
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	} else {
		body = append(body, 0x00, 0x00)
	}
	return handshakeMsg(handshakeTypeEncryptedExt, body)
}

func buildCertificateMsg(certDER []byte) []byte {
	entryLen := len(certDER) + 3 + 2
	body := []byte{0x00, byte(entryLen >> 16), byte(entryLen >> 8), byte(entryLen),
		byte(len(certDER) >> 16), byte(len(certDER) >> 8), byte(len(certDER))}
	body = append(body, certDER...)
	body = append(body, 0x00, 0x00)
	return handshakeMsg(handshakeTypeCertificate, body)
}

func (c *tls13Conn) readClientFinished(th hash.Hash, chsSecret []byte) error {
	expected := hmac.New(c.suite.hash, finishedKey(c.suite.hash, chsSecret))
	expected.Write(th.Sum(nil))
	for {
		typ, raw, err := c.readPhysicalRecord()
		if err != nil {
			return err
		}
		if typ == recordTypeChangeCipherSpec {
			continue
		}
		innerTyp, body, err := c.decryptAndUnpad(raw, typ)
		if err != nil {
			return err
		}
		typ = innerTyp
		if typ == recordTypeAlert {
			return errors.New("client sent an alert")
		}
		if typ != recordTypeHandshake {
			return fmt.Errorf("unexpected record type %d in client flight", typ)
		}
		for len(body) >= 4 {
			msgType := body[0]
			msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
			if len(body) < 4+msgLen {
				return errors.New("truncated handshake message")
			}
			msg := body[4 : 4+msgLen]
			body = body[4+msgLen:]
			if msgType == handshakeTypeFinished {
				if !hmac.Equal(expected.Sum(nil), msg) {
					return errors.New("client finished mismatch")
				}
				return nil
			}
			// a client Certificate (empty, when we requested none) is skipped
		}
	}
}

func (c *tls13Conn) decryptAndUnpad(body []byte, recordType byte) (byte, []byte, error) {
	plain, err := c.decrypt(body, recordType)
	if err != nil {
		return 0, nil, err
	}
	if len(plain) == 0 {
		return 0, nil, errors.New("empty record")
	}
	return plain[len(plain)-1], plain[:len(plain)-1], nil
}

func (c *tls13Conn) Read(p []byte) (int, error) {
	for len(c.plain) == 0 {
		typ, body, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		switch typ {
		case recordTypeApplicationData:
			c.plain = body
		case recordTypeHandshake:
			if err := c.handlePostHandshake(body); err != nil {
				return 0, err
			}
		case recordTypeAlert:
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected record type %d", typ)
		}
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

func (c *tls13Conn) handlePostHandshake(msg []byte) error {
	if len(msg) < 4 {
		return errors.New("bad post-handshake message")
	}
	if msg[0] != handshakeTypeKeyUpdate {
		return fmt.Errorf("unexpected post-handshake message %d", msg[0])
	}
	next := hkdfExpandLabel(c.suite.hash, c.readSecret, "traffic upd", nil, c.suite.hash().Size())
	c.readSecret = next
	return c.setReadKeys(next)
}

func (c *tls13Conn) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 1<<14 {
			chunk = chunk[:1<<14]
		}
		if err := c.writeRecord(recordTypeApplicationData, chunk); err != nil {
			return total - len(p), err
		}
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *tls13Conn) Close() error {
	if c.writeAEAD != nil {
		c.writeRecord(recordTypeAlert, []byte{1, 0}) // close_notify, best effort
	}
	return c.Conn.Close()
}
