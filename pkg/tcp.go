package httpproxy

import (
	"net"
	"context"
	"net/http"
)

func MustListenRandom() net.Listener {
	return MustListenAddr(&net.TCPAddr{})
}

func MustListen(port int) net.Listener {
	return MustListenAddr(&net.TCPAddr{
		Port: port,
	})
}

func MustListenAddr(addr *net.TCPAddr) net.Listener {
	conn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	return conn
}

type dialer func(context.Context, *http.Request) (net.Conn, error)

func URLDialer(dialer *net.Dialer) dialer {
	return func(ctx context.Context, req *http.Request) (net.Conn, error) {
		// See RFC7230 section 5.4 for address construction
		address := req.URL.Host
		if req.URL.Port() == "" {
			address += ":80"
		}
		return dialer.DialContext(ctx, "tcp", address)
	}
}