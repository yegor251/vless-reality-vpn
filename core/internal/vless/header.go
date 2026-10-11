package vless

import (
	"bufio"
	"fmt"
	"io"
	"net"
)

const Version byte = 0

const (
	CommandTCP byte = 0x01
	CommandUDP byte = 0x02
	CommandMux byte = 0x03
	CommandRvs byte = 0x04
)

const (
	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x02
	AddrIPv6   byte = 0x03
)

// ResponseHeader is what the server sends before relaying: version + empty addons.
var ResponseHeader = []byte{Version, 0}

type Request struct {
	UserID  UserID
	Addons  []byte
	Command byte
	Host    string
	Port    uint16
}

// ParseRequest reads the VLESS request header from r. Any bytes already
// buffered in r after the header belong to the payload stream.
func ParseRequest(r *bufio.Reader) (*Request, error) {
	version, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if version != Version {
		return nil, fmt.Errorf("unsupported version %d", version)
	}

	req := &Request{}
	if _, err := io.ReadFull(r, req.UserID[:]); err != nil {
		return nil, fmt.Errorf("read user id: %w", err)
	}

	addonsLen, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read addons length: %w", err)
	}
	if addonsLen > 0 {
		req.Addons = make([]byte, addonsLen)
		if _, err := io.ReadFull(r, req.Addons); err != nil {
			return nil, fmt.Errorf("read addons: %w", err)
		}
	}

	req.Command, err = r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read command: %w", err)
	}
	switch req.Command {
	case CommandTCP, CommandUDP:
	case CommandMux, CommandRvs:
		return req, fmt.Errorf("command 0x%02x carries no address, not supported", req.Command)
	default:
		return req, fmt.Errorf("unknown command 0x%02x", req.Command)
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	req.Port = uint16(port[0])<<8 | uint16(port[1])

	addrType, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read address type: %w", err)
	}
	switch addrType {
	case AddrIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("read ipv4: %w", err)
		}
		req.Host = net.IP(ip[:]).String()
	case AddrIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, fmt.Errorf("read ipv6: %w", err)
		}
		req.Host = net.IP(ip[:]).String()
	case AddrDomain:
		domainLen, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		if domainLen == 0 {
			return nil, fmt.Errorf("empty domain")
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		req.Host = string(domain)
	default:
		return req, fmt.Errorf("unknown address type %d", addrType)
	}

	return req, nil
}

func WriteResponse(w io.Writer) error {
	_, err := w.Write(ResponseHeader)
	return err
}
