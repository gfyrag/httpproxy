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
	"github.com/pborman/uuid"
	"net/http/httputil"
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
	originalDialer := r.dialer
	r.dialer = func() error {
		originalDialer()
		r.remoteConn = tls.Client(r.remoteConn, b.Config)
		return nil
	}
	return r.handleRequest(req)
}

type dialer func() error

type Request struct {
	*http.Request
	proxy      *Proxy
	once       sync.Once
	clientConn net.Conn
	remoteConn net.Conn
	logger     *logrus.Entry
	dialer     dialer
}

func (r *Request) dialRemote() (err error) {
	r.once.Do(func() {
		err = r.dialer()
	})
	return err
}

func (r *Request) handleRequest(req *http.Request) error {

	if r.logger.Logger.Level >= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		r.logger.Logger.Writer().Write(data)
	}

	resp, at, expires, err := r.proxy.Cache.Request(req)

	if err != nil && err != ErrCacheMiss {
		return err
	}

	if err == nil && time.Now().After(expires) {
		r.logger.Debugf("find cached response but expired at %s", expires)
		r.proxy.Cache.Evict(req)
	}

	if err == ErrCacheMiss || time.Now().After(expires) {
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
		defer resp.Body.Close()

		if r.logger.Logger.Level >= logrus.DebugLevel {
			data, _ := httputil.DumpResponse(resp, false)
			r.logger.Logger.Writer().Write(data)
		}

		expires, err = r.proxy.Cache.Accept(req, resp)
		if err != nil {
			fmt.Println("error while caching")
			return err
		}
		if expires.IsZero() {
			r.logger.Debugf("not cacheable response")
		} else {
			r.logger.Debugf("cache response, will expires at %s", expires)
		}
		return resp.Write(r.clientConn)
	}

	r.logger.Debugf("serve cached response, will expires at %s", expires)
	resp.Header.Set("Age", fmt.Sprintf("%d", int(time.Now().Sub(at).Seconds())))
	return resp.Write(r.clientConn)
}

func (r *Request) writeStatusLine(status int, text string) error {
	_, err := fmt.Fprintf(r.clientConn, "HTTP/%d.%d %03d %s\r\n\r\n", r.ProtoMajor, r.ProtoMinor, status, text)
	return err
}

func (r *Request) handleTunneling() error {
	r.logger.Debugf("start tunneling request")
	err := r.writeStatusLine(http.StatusOK, http.StatusText(http.StatusOK))
	if err != nil {
		return err
	}
	return r.proxy.ConnectHandler.Serve(r)
}

func (r *Request) Serve() {
	defer func() {
		if r.remoteConn != nil {
			r.remoteConn.Close()
		}
	}()

	r.dialer = func() (err error) {
		address := r.URL.Host
		if r.URL.Port() == "" {
			address += ":80"
		}
		r.logger.Debugf("dial remote %s", address)
		r.remoteConn, err = net.Dial("tcp", address)
		return err
	}

	var err error
	if r.Method == http.MethodConnect {
		err = r.handleTunneling()
	} else {
		err = r.handleRequest(r.Request)
	}
	if err != nil {
		r.proxy.Logger.Debugf("serve request error: %s", err)
		if e, ok := err.(*net.OpError); ok && e.Err.Error() == "tls: bad certificate" {
			// Cannot respond since the tls handshake is unsuccessful
		} else {
			err = r.writeStatusLine(http.StatusServiceUnavailable, err.Error())
			if err != nil {
				r.proxy.Logger.Errorf("serve request error: %s", err)
			}
		}
	}
}

type Proxy struct {
	ConnectHandler ConnectHandler
	Cache          *Cache
	Logger         *logrus.Logger
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if p.Cache == nil {
		p.Cache = &Cache{}
	}
	if p.Logger == nil {
		p.Logger = logrus.New()
	}
	if p.ConnectHandler == nil {
		p.ConnectHandler = DefaultConnectHandler
	}

	id := uuid.New()
	logger := p.Logger.WithField("id", id)
	logger.Debugf("serve request %s", r.URL)

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
		proxy: p,
		clientConn: clientConn,
		Request: r,
		logger: logger,
	}
	req.Serve()
}
