package httpproxy

import (
	"net/http"
	"net"
	"time"
	"io"
	"crypto/tls"
	"bufio"
	"fmt"
)

type ConnectHandler interface {
	Serve(net.Conn, *Request) error
}
type ConnectHandlerFn func(net.Conn, *Request) error

func (fn ConnectHandlerFn) Serve(w net.Conn, r *Request) error {
	return fn(w, r)
}

var DefaultConnectHandler ConnectHandlerFn = func(remote net.Conn, request *Request) error {
	go io.Copy(remote, request.clientConn)
	io.Copy(request.clientConn, remote)
	return nil
}

type SSLBump struct {
	Config *tls.Config
}

func (b *SSLBump) Serve(w net.Conn, r *Request) error {
	r.clientConn = tls.Server(r.clientConn, b.Config)

	req, err := http.ReadRequest(bufio.NewReader(r.clientConn))
	if err != nil {
		return err
	}

	client := tls.Client(w, b.Config)

	req.Host = r.Host
	err = req.Write(client)
	if err != nil {
		return err
	}

	rsp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		return err
	}

	return rsp.Write(r.clientConn)
}

type Request struct {
	*http.Request
	clientConn     net.Conn
	remoteConn     net.Conn
	connectHandler ConnectHandler
}

func (r *Request) handleRequest() error {

	err := r.Request.Write(r.remoteConn)
	if err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(r.remoteConn), r.Request)
	if err != nil {
		return err
	}
	return resp.Write(r.clientConn)
}

func (r *Request) writeStatusLine(status int, text string) error {
	_, err := fmt.Fprintf(r.clientConn, "HTTP/%d.%d %03d %s\r\n\r\n", r.ProtoMajor, r.ProtoMinor, status, text)
	return err
}

func (r *Request) handleTunneling() error {
	err := r.writeStatusLine(http.StatusOK, http.StatusText(http.StatusOK))
	if err != nil {
		return err
	}

	if r.connectHandler != nil {
		return r.connectHandler.Serve(r.remoteConn, r)
	} else {
		return DefaultConnectHandler(r.remoteConn, r)
	}
}

func (r *Request) Serve() {
	address := r.URL.Host
	if r.URL.Port() == "" {
		address += ":80"
	}

	var err error
	r.remoteConn, err = net.DialTimeout("tcp", address, 10 * time.Second)
	if err != nil {
		err := r.writeStatusLine(http.StatusServiceUnavailable, err.Error())
		if err != nil {
			panic(err)
		}
		return
	}
	defer r.remoteConn.Close()

	if r.Method == http.MethodConnect {
		err = r.handleTunneling()
	} else {
		err = r.handleRequest()
	}
	if err != nil {
		err = r.writeStatusLine(http.StatusServiceUnavailable, err.Error())
		if err != nil {
			panic(err)
		}
	}
}

type Proxy struct {
	ConnectHandler ConnectHandler
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	hi, ok := w.(http.Hijacker)
	if !ok {
		panic("conn can't be hijacked")
	}

	clientConn, _, err := hi.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	req := &Request{
		clientConn: clientConn,
		Request: r,
		connectHandler: p.ConnectHandler,
	}
	req.Serve()
}
