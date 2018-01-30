package httpproxy

import (
	"net/http"
	"net/url"
	"net"
	"time"
	"io"
)

var (
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: http.DefaultTransport,
	}
)

type ConnectHandler interface {
	Serve(io.Writer, io.Reader) error
}
type ConnectHandlerFn func(net.Conn, net.Conn) error
func (fn ConnectHandlerFn) Serve(w net.Conn, r net.Conn) error {
	return fn(w, r)
}

var DefaultConnectHandler = func(w net.Conn, r net.Conn) error {
	go io.Copy(w, r)
	_, err := io.Copy(r, w)
	return err
}

type Proxy struct {
	ConnectHandler ConnectHandler
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) error {
	hi, ok := w.(http.Hijacker)
	if !ok {
		panic("conn can't be hijacked")
	}

	uri, err := url.Parse(r.RequestURI)
	if err != nil {
		return err
	}

	r.URL = uri
	r.RequestURI = ""

	resp, err := httpClient.Do(r)
	if err != nil {
		return err
	}

	clientConn, _, err := hi.Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	return resp.Write(clientConn)
}

func (p *Proxy) handleTunneling(w http.ResponseWriter, r *http.Request) error {

	remoteConn, err := net.DialTimeout("tcp", r.Host, 10 * time.Second)
	if err != nil {
		return err
	}
	defer remoteConn.Close()
	w.WriteHeader(http.StatusOK)

	hi, ok := w.(http.Hijacker)
	if !ok {
		panic("conn can't be hijacked")
	}

	clientConn, _, err := hi.Hijack()
	if err != nil {
		return err
	}
	defer clientConn.Close()

	if p.ConnectHandler != nil {
		return p.ConnectHandler.Serve(remoteConn, clientConn)
	} else {
		return DefaultConnectHandler(remoteConn, clientConn)
	}

}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method == http.MethodConnect {
		err = p.handleTunneling(w, r)
	} else {
		err = p.handleRequest(w, r)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}
