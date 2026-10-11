package vless

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
)

var visionDebug = os.Getenv("VPN_VISION_DEBUG") != ""

// Vision framing (xtls-rprx-vision), mirroring Xray-core's proxy package:
//
//	[uuid(16, first record only)][command][content_len:2][padding_len:2][content][padding]
//
// Padding records continue until the inner stream produces complete TLS
// application-data records (or the packet filter runs out for non-TLS
// traffic); afterwards the stream is raw bytes.

const (
	cmdPadContinue byte = 0x00
	cmdPadEnd      byte = 0x01
	cmdPadDirect   byte = 0x02
)

const (
	filterPackets  = 8
	longContentMin = 900
	longPadRand    = 500
	longPadBase    = 900
	shortPadRand   = 256
	visionHeadLen  = 5 // command + two uint16 lengths
	visionPrefix   = 16 + visionHeadLen + 1
)

var tls13VersionsExt = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}

type VisionConn struct {
	net.Conn
	br   *bufio.Reader
	uuid []byte

	// read half
	raw        bool
	uuidSeen   bool
	pre        bytes.Buffer
	out        bytes.Buffer
	pendingErr error
	cmdLeft    int
	content    int
	padding    int
	command    byte
	inBlock    bool // a frame header has been read and its body is pending
	scratch    [8192]byte

	// write half
	wFirst   bool
	wPadding bool
	wConn    net.Conn // set after sending cmdPadDirect: bypass the outer TLS layer

	detMu sync.Mutex
	det   tlsDetector
}

func NewVisionConn(conn net.Conn, br *bufio.Reader, userID UserID) *VisionConn {
	return &VisionConn{
		Conn:     conn,
		br:       br,
		uuid:     append([]byte(nil), userID[:]...),
		wFirst:   true,
		wPadding: true,
		det:      tlsDetector{packets: filterPackets},
	}
}

func (c *VisionConn) Read(p []byte) (int, error) {
	for {
		if c.out.Len() > 0 {
			return c.out.Read(p)
		}
		if c.pendingErr != nil {
			err := c.pendingErr
			c.pendingErr = nil
			return 0, err
		}
		if c.raw {
			return c.br.Read(p)
		}
		n, err := c.br.Read(c.scratch[:])
		if n > 0 {
			c.parse(c.scratch[:n])
		}
		if err != nil {
			if visionDebug {
				log.Printf("vision read: underlying error: %v", err)
			}
			c.pendingErr = err
		}
	}
}

func (c *VisionConn) parse(b []byte) {
	if !c.uuidSeen {
		c.pre.Write(b)
		if c.pre.Len() < visionPrefix {
			return
		}
		head := c.pre.Bytes()
		if !bytes.Equal(head[:16], c.uuid) {
			// not a vision stream; pass everything through untouched
			c.raw = true
			c.out.Write(c.pre.Bytes())
			c.pre.Reset()
			return
		}
		c.uuidSeen = true
		c.cmdLeft = visionHeadLen
		b = c.pre.Bytes()[16:]
		c.pre.Reset()
	}
	if visionDebug {
		log.Printf("vision parse: fill=%d state cmdLeft=%d content=%d padding=%d out=%d",
			len(b), c.cmdLeft, c.content, c.padding, c.out.Len())
	}
	i := 0
	for i < len(b) {
		if c.cmdLeft > 0 {
			ch := b[i]
			i++
			switch c.cmdLeft {
			case visionHeadLen:
				c.command = ch
			case 4:
				c.content = int(ch) << 8
			case 3:
				c.content |= int(ch)
			case 2:
				c.padding = int(ch) << 8
			case 1:
				c.padding |= int(ch)
				if visionDebug {
					log.Printf("vision read: frame cmd=%d content=%d pad=%d", c.command, c.content, c.padding)
				}
			}
			c.cmdLeft--
			if c.cmdLeft == 0 {
				c.inBlock = true
			}
			continue
		}
		if c.content > 0 {
			n := min(c.content, len(b)-i)
			c.detMu.Lock()
			c.det.filter(b[i : i+n])
			c.detMu.Unlock()
			c.out.Write(b[i : i+n])
			i += n
			c.content -= n
		} else if c.padding > 0 {
			n := min(c.padding, len(b)-i)
			i += n
			c.padding -= n
		}
		if c.inBlock && c.cmdLeft == 0 && c.content == 0 && c.padding == 0 {
			// the frame completed — possibly exactly at this fill's end, so
			// the transition must happen now, not on the next chunk
			c.inBlock = false
			if c.command != cmdPadContinue {
				c.raw = true
				c.out.Write(b[i:])
				if n := c.br.Buffered(); n > 0 {
					buf := make([]byte, n)
					if _, err := io.ReadFull(c.br, buf); err == nil {
						c.out.Write(buf)
					}
				}
				if c.command == cmdPadDirect {
					// the peer has dropped the outer record layer: whatever
					// still looks like outer records is raw stream from now on
					if rf, ok := c.Conn.(interface{ SetRawFallback() }); ok {
						rf.SetRawFallback()
					}
				}
				if visionDebug {
					log.Printf("vision read: end cmd=%d, %d raw tail bytes", c.command, len(b)-i)
				}
				return
			}
			c.cmdLeft = visionHeadLen
		}
	}
}

func (c *VisionConn) Write(p []byte) (int, error) {
	if !c.wPadding {
		w := c.Conn
		if c.wConn != nil {
			w = c.wConn
		}
		return w.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}

	c.detMu.Lock()
	c.det.filter(p)
	isTLS, isTLS12, direct := c.det.isTLS, c.det.isTLS12, c.det.enableXtls
	packets := c.det.packets
	c.detMu.Unlock()

	long := isTLS
	command := cmdPadContinue
	if isTLS && len(p) >= 6 && bytes.HasPrefix(p, []byte{0x17, 0x03, 0x03}) && completeTLSRecords(p) {
		command = cmdPadEnd
		if direct {
			command = cmdPadDirect
		}
		c.wPadding = false
		long = true
	} else if !isTLS12 && packets <= 1 {
		command = cmdPadEnd
		c.wPadding = false
	}

	pad := padLen(len(p), long)
	frame := make([]byte, 0, len(c.uuid)+visionHeadLen+len(p)+pad)
	if c.wFirst {
		frame = append(frame, c.uuid...)
		c.wFirst = false
	}
	var head [visionHeadLen]byte
	head[0] = command
	binary.BigEndian.PutUint16(head[1:3], uint16(len(p)))
	binary.BigEndian.PutUint16(head[3:5], uint16(pad))
	frame = append(frame, head[:]...)
	frame = append(frame, p...)
	frame = append(frame, make([]byte, pad)...)

	if _, err := c.Conn.Write(frame); err != nil {
		return 0, err
	}
	if command == cmdPadDirect {
		if u, ok := c.Conn.(interface{ Underlying() net.Conn }); ok {
			c.wConn = u.Underlying()
			if visionDebug {
				log.Printf("vision write: direct copy engaged, raw=%T", c.wConn)
			}
		} else if visionDebug {
			log.Printf("vision write: DIRECT SWITCH FAILED, conn=%T", c.Conn)
		}
	}
	if visionDebug {
		log.Printf("vision write: frame cmd=%d content=%d pad=%d (isTLS=%v isTLS12=%v packets=%d)",
			command, len(p), pad, isTLS, isTLS12, packets)
	}
	return len(p), nil
}

func padLen(content int, long bool) int {
	var pad int
	if long && content < longContentMin {
		pad = randInt(longPadRand) + longPadBase - content
	} else {
		pad = randInt(shortPadRand)
	}
	if maxPad := 65535 - visionHeadLen - content; pad > maxPad {
		pad = max(0, maxPad)
	}
	return pad
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func completeTLSRecords(p []byte) bool {
	i := 0
	for i < len(p) {
		if len(p)-i < 5 || p[i] != 0x17 || p[i+1] != 0x03 || p[i+2] != 0x03 {
			return false
		}
		n := int(binary.BigEndian.Uint16(p[i+3 : i+5]))
		if n == 0 || len(p)-i-5 < n {
			return false
		}
		i += 5 + n
	}
	return true
}

// Close sends no outer close_notify once the write side went raw: the peer
// reads that region as stream bytes, and a sealed alert would corrupt it.
func (c *VisionConn) Close() error {
	if c.wConn != nil {
		return c.wConn.Close()
	}
	return c.Conn.Close()
}

// tlsDetector recognizes the inner stream's TLS handshake, replicating
// Xray-core's XtlsFilterTls: it decides when padding ends and whether the
// direct command may be used (inner TLS 1.3).
type tlsDetector struct {
	packets    int
	isTLS      bool
	isTLS12    bool
	enableXtls bool
	remSH      int
	sh         bytes.Buffer
}

func (d *tlsDetector) filter(b []byte) {
	if d.packets <= 0 {
		return
	}
	d.packets--
	if len(b) >= 6 {
		if b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x03 && b[5] == 0x02 { // ServerHello
			d.remSH = int(b[3])<<8 | int(b[4])
			d.remSH += 5
			d.isTLS12 = true
			d.isTLS = true
			d.sh.Reset()
		} else if b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 { // ClientHello
			d.isTLS = true
		}
	}
	if d.remSH > 0 {
		end := min(d.remSH, len(b))
		d.sh.Write(b[:end])
		d.remSH -= end
		if bytes.Contains(d.sh.Bytes(), tls13VersionsExt) {
			d.enableXtls = true
			d.packets = 0
			return
		}
		if d.remSH <= 0 { // whole ServerHello scanned, no TLS 1.3 marker
			d.packets = 0
		}
	}
}

var _ io.ReadWriter = (*VisionConn)(nil)
