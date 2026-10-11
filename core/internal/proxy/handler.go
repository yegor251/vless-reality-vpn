package proxy

import (
	"bufio"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"vpn/internal/auth"
	"vpn/internal/reality"
	"vpn/internal/vless"
)

const dialTimeout = 10 * time.Second

func Handle(conn net.Conn, users *auth.Store, rcfg *reality.Config) {
	defer conn.Close()

	if rcfg != nil {
		tlsConn := reality.Handle(conn, rcfg)
		if tlsConn == nil {
			return
		}
		conn = tlsConn
	}

	r := bufio.NewReader(conn)
	req, err := vless.ParseRequest(r)
	if err != nil {
		log.Printf("%s: parse request: %v", conn.RemoteAddr(), err)
		return
	}
	if !users.Authenticate(req.UserID) {
		log.Printf("%s: auth failed", conn.RemoteAddr())
		return
	}
	if req.Command != vless.CommandTCP {
		log.Printf("%s: unsupported command 0x%02x", conn.RemoteAddr(), req.Command)
		return
	}

	target, err := net.DialTimeout("tcp",
		net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))), dialTimeout)
	if err != nil {
		log.Printf("%s: dial %s:%d: %v", conn.RemoteAddr(), req.Host, req.Port, err)
		return
	}
	defer target.Close()

	if err := vless.WriteResponse(conn); err != nil {
		log.Printf("%s: write response: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("%s -> %s:%d", conn.RemoteAddr(), req.Host, req.Port)

	relay(target, conn, r)
}

func relay(target, client net.Conn, up io.Reader) {
	go func() {
		io.Copy(target, up)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	io.Copy(client, target)
}
