package httpproxy

import (
	"net/http"
	"net"
	"time"
	"io"
	"crypto/tls"
	"bufio"
	"fmt"
	"github.com/Sirupsen/logrus"
	"sync"
)

type ConnectHandler interface {
	Serve(*Request) error
}
type ConnectHandlerFn func(*Request) error

func (fn ConnectHandlerFn) Serve(r *Request) error {
	return fn(r)
}

var DefaultConnectHandler ConnectHandlerFn = func(request *Request) (err error) {
	err = request.dialRemote()
	if err != nil {
		return err
	}
	go io.Copy(request.remoteConn, request.clientConn)
	io.Copy(request.clientConn, request.remoteConn)
	return nil
}

type ResponseHandlerFn func(*http.Request, *http.Response) error

func (fn ResponseHandlerFn) Serve(req *http.Request, rsp *http.Response) error {
	return fn(req, rsp)
}

type SSLBump struct {
	Config *tls.Config
}

func (b *SSLBump) Serve(r *Request) error {
	r.clientConn = tls.Server(r.clientConn, b.Config)

	req, err := http.ReadRequest(bufio.NewReader(r.clientConn))
	if err != nil {
		return err
	}
	err = r.dialRemote()
	if err != nil {
		return err
	}
	r.remoteConn = tls.Client(r.remoteConn, b.Config)
	return r.handleRequest(req)
}

type Request struct {
	*http.Request
	once sync.Once
	clientConn     net.Conn
	remoteConn     net.Conn
	connectHandler ConnectHandler
	cache          *Cache
}

func (r *Request) dialRemote() (err error) {
	r.once.Do(func() {
		address := r.URL.Host
		if r.URL.Port() == "" {
			address += ":80"
		}

		r.remoteConn, err = net.DialTimeout("tcp", address, 10 * time.Second)
	})
	return err
}

func (r *Request) handleRequest(req *http.Request) error {

	resp, date, err := r.cache.Request(req)
	if err != nil {
		if err != ErrCacheMiss {
			return err
		}

		err = r.dialRemote()
		if err != nil {
			return err
		}

		err := req.Write(r.remoteConn)
		if err != nil {
			return err
		}

		resp, err := http.ReadResponse(bufio.NewReader(r.remoteConn), req)
		if err != nil {
			return err
		}

		err = r.cache.Accept(req, resp)
		if err != nil {
			return err
		}
		return resp.Write(r.clientConn)
	} else {
		resp.Header.Set("Age", fmt.Sprintf("%d", int(time.Now().Sub(date).Seconds())))
		return resp.Write(r.clientConn)
	}
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
		return r.connectHandler.Serve(r)
	} else {
		return DefaultConnectHandler(r)
	}
}

func (r *Request) Serve() {
	defer func() {
		if r.remoteConn != nil {
			r.remoteConn.Close()
		}
	}()
	var err error
	if r.Method == http.MethodConnect {
		err = r.handleTunneling()
	} else {
		err = r.handleRequest(r.Request)
	}
	if err != nil {
		if e, ok := err.(*net.OpError); ok && e.Err.Error() == "tls: bad certificate" {
			logrus.Error(e)
		} else {
			err = r.writeStatusLine(http.StatusServiceUnavailable, err.Error())
			if err != nil {
				panic(err)
			}
		}
	}
}

type Proxy struct {
	ConnectHandler ConnectHandler
	Cache          *Cache
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if p.Cache == nil {
		p.Cache = &Cache{}
	}

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
		cache: p.Cache,
	}
	req.Serve()
}
