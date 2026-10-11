package vless

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestParseFlow(t *testing.T) {
	cases := []struct {
		addons []byte
		want   string
	}{
		{nil, ""},
		{[]byte{}, ""},
		{[]byte{0x00}, ""},
		{append([]byte{0x0a, byte(len(XRV))}, []byte(XRV)...), XRV},
		{[]byte{0x0a, 0x02, 'o', 'k', 0x12, 0x01, 0xff}, "ok"}, // trailing Seed field
		{[]byte{0x0a, 0x05, 'h', 'i'}, ""},                     // truncated
	}
	for _, c := range cases {
		if got := ParseFlow(c.addons); got != c.want {
			t.Errorf("ParseFlow(%v) = %q, want %q", c.addons, got, c.want)
		}
	}
}

// visionClient mimics the framing an Xray vision client produces.
type visionClient struct {
	w      io.Writer
	uuid   []byte
	first  bool
}

func (c *visionClient) frame(cmd byte, content []byte, pad int) {
	var head bytes.Buffer
	if !c.first {
		head.Write(c.uuid)
		c.first = true
	}
	head.WriteByte(cmd)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(len(content)))
	head.Write(tmp[:])
	binary.BigEndian.PutUint16(tmp[:], uint16(pad))
	head.Write(tmp[:])
	head.Write(content)
	head.Write(make([]byte, pad))
	c.w.Write(head.Bytes())
}

func TestVisionRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var uid UserID
	uid[0] = 0xAB

	go func() {
		vc := &visionClient{w: client, uuid: append([]byte(nil), uid[:]...)}
		vc.frame(cmdPadContinue, []byte("GET / HTTP/1.1"), 11)
		vc.frame(cmdPadEnd, []byte("done"), 0)
		client.Write([]byte("raw tail bytes"))
		client.Close()
	}()

	v := NewVisionConn(server, bufio.NewReader(server), uid)
	got, err := io.ReadAll(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "GET / HTTP/1.1" + "done" + "raw tail bytes"
	if string(got) != want {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func TestVisionPartialReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var uid UserID
	payload := bytes.Repeat([]byte{0x42}, 5000)

	go func() {
		vc := &visionClient{w: client, uuid: append([]byte(nil), uid[:]...)}
		vc.frame(cmdPadContinue, payload, 7)
		vc.frame(cmdPadEnd, nil, 0)
		io.WriteString(client, "after")
		client.Close()
	}()

	v := NewVisionConn(server, bufio.NewReader(server), uid)
	buf := make([]byte, 97)
	var acc bytes.Buffer
	for acc.Len() < len(payload)+len("after") {
		n, err := v.Read(buf)
		if n > 0 {
			acc.Write(buf[:n])
		}
		if err != nil {
			t.Fatalf("read: %v (got %d bytes)", err, acc.Len())
		}
	}
	want := string(payload) + "after"
	if acc.String() != want {
		t.Fatalf("stream mismatch: got %d bytes, want %d", acc.Len(), len(want))
	}
}

func TestVisionWriteFrames(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var uid UserID
	uid[15] = 1

	wire := make(chan []byte, 4)
	go func() {
		var all bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				all.Write(buf[:n])
			}
			if err != nil {
				wire <- all.Bytes()
				return
			}
		}
	}()

	v := NewVisionConn(server, bufio.NewReader(server), uid)
	if _, err := v.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	// non-TLS traffic: after the filter runs out padding must end
	for i := 0; i < 8; i++ {
		v.detMu.Lock()
		v.det.filter([]byte("plain http text"))
		v.detMu.Unlock()
	}
	if _, err := v.Write([]byte("final")); err != nil {
		t.Fatal(err)
	}
	server.Close()

	b := <-wire
	if !bytes.HasPrefix(b, uid[:]) {
		t.Fatal("first frame missing uuid prefix")
	}
	b = b[16:]
	// walk all frames; the last one must close the padding phase
	var cmd byte
	var content []byte
	var padLen int
	for len(b) > 0 {
		cmd = b[0]
		contentLen := int(binary.BigEndian.Uint16(b[1:3]))
		padLen = int(binary.BigEndian.Uint16(b[3:5]))
		content = b[5 : 5+contentLen]
		if len(b) < 5+contentLen+padLen {
			t.Fatalf("truncated frame: have %d bytes, want %d", len(b), 5+contentLen+padLen)
		}
		b = b[5+contentLen+padLen:]
	}
	if cmd != cmdPadEnd {
		t.Fatalf("last frame command = %d, want %d (early end)", cmd, cmdPadEnd)
	}
	if string(content) != "final" {
		t.Fatalf("last frame content = %q", content)
	}
}

func TestVisionFrameEndAtChunkBoundary(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var uid UserID
	uid[7] = 0x33

	// each Write is one Read on net.Pipe, so framing the end frame alone
	// reproduces a frame ending exactly at a chunk boundary
	go func() {
		vc := &visionClient{w: client, uuid: append([]byte(nil), uid[:]...)}
		vc.frame(cmdPadContinue, []byte("first"), 3)
		vc.frame(cmdPadEnd, []byte("last"), 0)
		client.Close() // no trailing bytes: the end must be processed on the spot
	}()

	v := NewVisionConn(server, bufio.NewReader(server), uid)
	got, err := io.ReadAll(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "firstlast" {
		t.Fatalf("read %q", got)
	}
	if !v.raw {
		t.Fatal("padding phase not closed after end frame at chunk boundary")
	}
}

func TestTLSDetector(t *testing.T) {
	var d tlsDetector = tlsDetector{packets: filterPackets}
	clientHello := make([]byte, 64)
	clientHello[0], clientHello[1], clientHello[5] = 0x16, 0x03, 0x01
	d.filter(clientHello)
	if !d.isTLS || d.isTLS12 {
		t.Fatalf("after ClientHello: isTLS=%v isTLS12=%v", d.isTLS, d.isTLS12)
	}

	// ServerHello: TLS 1.3 with supported_versions, split across two chunks
	sh := make([]byte, 100)
	sh[0], sh[1], sh[2] = 0x16, 0x03, 0x03
	binary.BigEndian.PutUint16(sh[3:5], 95) // record length
	sh[5] = 0x02                            // ServerHello
	copy(sh[60:], tls13VersionsExt)         // marker in second half
	d2 := tlsDetector{packets: filterPackets}
	d2.filter(sh[:50])
	if d2.isTLS12 && d2.enableXtls {
		t.Fatal("detector concluded on partial ServerHello")
	}
	d2.filter(sh[50:])
	if !d2.isTLS12 || !d2.enableXtls || d2.packets != 0 {
		t.Fatalf("after ServerHello: isTLS12=%v enableXtls=%v packets=%d", d2.isTLS12, d2.enableXtls, d2.packets)
	}
}

func TestCompleteTLSRecords(t *testing.T) {
	rec := func(n int) []byte {
		b := make([]byte, 5+n)
		b[0], b[1], b[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(b[3:5], uint16(n))
		return b
	}
	if !completeTLSRecords(append(rec(3), rec(0x10)...)) {
		t.Fatal("two complete records reported incomplete")
	}
	if completeTLSRecords(rec(3)[:7]) {
		t.Fatal("truncated record reported complete")
	}
	if completeTLSRecords([]byte{0x16, 0x03, 0x03, 0, 1, 0}) {
		t.Fatal("handshake record accepted as app data")
	}
}
