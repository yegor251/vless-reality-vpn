package vless

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func buildRequest(uuid UserID, command byte, port uint16, addrType byte, addr []byte, addons, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(Version)
	b.Write(uuid[:])
	b.WriteByte(byte(len(addons)))
	b.Write(addons)
	b.WriteByte(command)
	b.WriteByte(byte(port >> 8))
	b.WriteByte(byte(port))
	b.WriteByte(addrType)
	b.Write(addr)
	b.Write(payload)
	return b.Bytes()
}

var testUUID = UserID{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
}

func TestParseRequestDomain(t *testing.T) {
	addr := append([]byte{9}, []byte("127.0.0.1")...)
	raw := buildRequest(testUUID, CommandTCP, 8080, AddrDomain, addr, nil, []byte("payload-after-header"))

	r := bufio.NewReader(bytes.NewReader(raw))
	req, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if req.UserID != testUUID {
		t.Errorf("user id mismatch")
	}
	if req.Command != CommandTCP {
		t.Errorf("command = 0x%02x, want 0x%02x", req.Command, CommandTCP)
	}
	if req.Host != "127.0.0.1" {
		t.Errorf("host = %q, want %q", req.Host, "127.0.0.1")
	}
	if req.Port != 8080 {
		t.Errorf("port = %d, want 8080", req.Port)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "payload-after-header" {
		t.Errorf("payload after header = %q", rest)
	}
}

func TestParseRequestIPv4AndIPv6(t *testing.T) {
	raw := buildRequest(testUUID, CommandTCP, 443, AddrIPv4, []byte{8, 8, 8, 8}, nil, nil)
	req, err := ParseRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse ipv4: %v", err)
	}
	if req.Host != "8.8.8.8" {
		t.Errorf("ipv4 host = %q", req.Host)
	}

	ipv6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	raw = buildRequest(testUUID, CommandTCP, 443, AddrIPv6, ipv6, nil, nil)
	req, err = ParseRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse ipv6: %v", err)
	}
	if req.Host != "2001:db8::1" {
		t.Errorf("ipv6 host = %q", req.Host)
	}
}

func TestParseRequestWithAddons(t *testing.T) {
	addr := append([]byte{11}, []byte("example.com")...)
	raw := buildRequest(testUUID, CommandTCP, 80, AddrDomain, addr, []byte{0x0a, 0x03, 'a', 'b', 'c'}, nil)

	req, err := ParseRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(req.Addons, []byte{0x0a, 0x03, 'a', 'b', 'c'}) {
		t.Errorf("addons = %x", req.Addons)
	}
	if req.Host != "example.com" {
		t.Errorf("host = %q", req.Host)
	}
}

func TestParseRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"truncated", buildRequest(testUUID, CommandTCP, 80, AddrDomain, []byte{11}, []byte("example.com")[:5], nil)},
		{"empty domain", buildRequest(testUUID, CommandTCP, 80, AddrDomain, []byte{0}, nil, nil)},
	}
	for _, c := range cases {
		if _, err := ParseRequest(bufio.NewReader(bytes.NewReader(c.raw))); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}

	badVersion := buildRequest(testUUID, CommandTCP, 80, AddrDomain, []byte{4}, nil, nil)
	badVersion[0] = 1
	if _, err := ParseRequest(bufio.NewReader(bytes.NewReader(badVersion))); err == nil {
		t.Error("bad version: expected error")
	}

	badCommand := buildRequest(testUUID, 0x7f, 80, AddrDomain, []byte{4}, nil, nil)
	if _, err := ParseRequest(bufio.NewReader(bytes.NewReader(badCommand))); err == nil {
		t.Error("unknown command: expected error")
	}
}

func TestParseUserID(t *testing.T) {
	id, err := ParseUserID("01234567-89AB-cdef-FEdc-ba9876543210")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id != testUUID {
		t.Errorf("round-trip mismatch: %v", id)
	}
	if got := id.String(); got != "01234567-89ab-cdef-fedc-ba9876543210" {
		t.Errorf("String() = %q", got)
	}

	if _, err := ParseUserID("not-a-uuid"); err == nil {
		t.Error("garbage: expected error")
	}
	if _, err := ParseUserID("01234567"); err == nil {
		t.Error("short uuid: expected error")
	}
}
