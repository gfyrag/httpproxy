package httpproxy

import (
	"net"
	"context"
	"net/http"
	"syscall"
	"encoding/binary"
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

var netDialer = &net.Dialer{}

var URLDialer = func(ctx context.Context, req *http.Request) (net.Conn, error) {
	// See RFC7230 section 5.4 for address construction
	address := req.URL.Host
	if req.URL.Port() == "" {
		address += ":80"
	}
	return netDialer.DialContext(ctx, "tcp", address)
}

const (
	SO_ORIGINAL_DST      = 80 // from linux/include/uapi/linux/netfilter_ipv4.h
	IP6T_SO_ORIGINAL_DST = 80 // from linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h
)

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func getOriginalIPV4Dst(fd uintptr) (rawaddr []byte, err error) {
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	addr, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return nil, err
	}

	rawaddr = make([]byte, 1+net.IPv4len+2)
	// address type, 1 - IPv4, 4 - IPv6, 3 - hostname
	rawaddr[0] = 1
	// raw IP address, 4 bytes for IPv4 or 16 bytes for IPv6
	copy(rawaddr[1:], addr.Multiaddr[4:4+net.IPv4len])
	// port
	copy(rawaddr[1+net.IPv4len:], addr.Multiaddr[2:2+2])

	return rawaddr, nil
}

// Call ipv6_getorigdst() from linux/net/ipv6/netfilter/nf_conntrack_l3proto_ipv6.c
// NOTE: I haven't tried yet but it should work since Linux 3.8.
func getOriginalIPV6Dst(fd uintptr) (addr []byte, err error) {
	mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
	if err != nil {
		return nil, err
	}
	raw := mtuinfo.Addr

	addr = make([]byte, 1+net.IPv6len+2)
	addr[0] = 4
	copy(addr[1:1+net.IPv6len], raw.Addr[:])
	binary.LittleEndian.PutUint16(addr[1+net.IPv6len:], raw.Port)
	return addr, nil
}

// Get the original destination of a TCP connection.
func getOriginalIPDst(c *net.TCPConn) (*net.TCPAddr, *net.TCPConn, error) {
	newTCPConn := c
	f, err := c.File()
	if err != nil {
		return nil, newTCPConn, err
	}
	defer f.Close()

	fd := f.Fd()

	// The File() call above puts both the original socket fd and the file fd in blocking mode.
	// Set the file fd back to non-blocking mode and the original socket fd will become non-blocking as well.
	// Otherwise blocking I/O will waste OS threads.
	if err = syscall.SetNonblock(int(fd), true); err != nil {
		return nil, newTCPConn, err
	}
	rawaddr, err := getOriginalIPV6Dst(fd)
	if err == nil {
		return &net.TCPAddr{
			IP: net.IP(rawaddr[1 : 1+net.IPv6len]),
			Port: int(uint16(rawaddr[1+net.IPv6len])<<8+uint16(rawaddr[1+net.IPv6len+1])),
		}, newTCPConn, nil
	}

	rawaddr, err = getOriginalIPV4Dst(fd)
	if err != nil {
		return nil, newTCPConn, err
	}

	return &net.TCPAddr{
		IP: net.IP(rawaddr[1 : 1+net.IPv4len]),
		Port: int(uint16(rawaddr[1+net.IPv4len])<<8+uint16(rawaddr[1+net.IPv4len+1])),
	}, newTCPConn, nil
}