package httpproxy

import "net"

func MustListen(port int) net.Listener {
	conn, err := net.ListenTCP("tcp", &net.TCPAddr{
		Port: port,
	})
	if err != nil {
		panic(err)
	}
	return conn
}
