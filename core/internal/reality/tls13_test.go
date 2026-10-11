package reality

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// A standard library TLS client must complete a handshake against our
// minimal server and exchange data.
func TestTLS13HandshakeWithStdlibClient(t *testing.T) {
	client, server := net.Pipe()

	clientDone := make(chan error, 1)
	go func() {
		defer close(clientDone)
		c := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "www.apple.com",
			NextProtos:         []string{"h2", "http/1.1"},
		})
		defer c.Close()
		if err := c.Handshake(); err != nil {
			clientDone <- err
			return
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			clientDone <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			clientDone <- err
			return
		}
		if string(buf) != "pong" {
			clientDone <- io.ErrUnexpectedEOF
			return
		}
		clientDone <- nil
	}()

	ch, _, err := ReadClientHello(server)
	if err != nil {
		t.Fatal(err)
	}
	certDER, certPriv := buildCert(bytes.Repeat([]byte{3}, 32))
	conn, err := serverHandshake(server, ch, certDER, certPriv, nil)
	if err != nil {
		server.Close()
		select {
		case cerr := <-clientDone:
			t.Fatalf("server handshake: %v (client error: %v)", err, cerr)
		case <-time.After(3 * time.Second):
			t.Fatalf("server handshake: %v (no client error)", err)
		}
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read ping: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q, want ping", buf)
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("write pong: %v", err)
	}

	select {
	case err := <-clientDone:
		if err != nil {
			t.Fatalf("client side: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}
