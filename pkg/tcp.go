package httpproxy

import (
	"net"
	"context"
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

type dialer func(context.Context, string) (net.Conn, error)

func DefaultDialer(dialer *net.Dialer) dialer {
	return func(ctx context.Context, remote string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", remote)
	}
}