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
	"io/ioutil"
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

	cachedResponse, at, expires, err := r.proxy.Cache.Request(req)

	if err != nil && err != ErrCacheMiss {
		return err
	}

	if err == nil && time.Now().After(expires) {
		r.logger.Debugf("find cached response but expired at %s", expires)
		r.proxy.Cache.Evict(req)
		etags := cachedResponse.Header.Get("ETags")
		if etags != "" {
			r.logger.Debugf("found etags header in previous response")
			req.Header.Set("If-None-Match", etags)
		}
	}

	if r.logger.Logger.Level >= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		r.logger.Logger.Writer().Write(data)
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

		if resp.StatusCode == http.StatusNotModified {
			if r.logger.Logger.Level >= logrus.DebugLevel {
				data, _ := httputil.DumpResponse(resp, false)
				r.logger.Logger.Writer().Write(data)
			}
			resp.Body.Close()
			r.logger.Debugf("remote return not modified status, use previously cached response")
			if resp.Header.Get("Date") != "" {
				cachedResponse.Header.Set("Date", resp.Header.Get("Date"))
			}
			if resp.Header.Get("Cache-Control") != "" {
				cachedResponse.Header.Set("Cache-Control", resp.Header.Get("Cache-Control"))
			}
			if resp.Header.Get("Expires") != "" {
				cachedResponse.Header.Set("Expires", resp.Header.Get("Expires"))
			}
			if resp.Header.Get("ETags") != "" {
				cachedResponse.Header.Set("ETags", resp.Header.Get("ETags"))
			}
			resp = cachedResponse
		}

		// Store the original body as we need to replace the existing one by a blocking reader
		respBody := resp.Body
		defer respBody.Close()

		if r.logger.Logger.Level >= logrus.DebugLevel {
			data, _ := httputil.DumpResponse(resp, false)
			r.logger.Logger.Writer().Write(data)
		}

		if r.proxy.Cache.IsCacheable(resp, req) {

			// Replace the original cachedResponse.Body with a blocking reader
			// This way we can let cachedResponse.Write method write the response to the client and control the downstream reading
			clientResponseWriter := &blockingReadWriter{}
			resp.Body = ioutil.NopCloser(clientResponseWriter)

			// Start responding to client on another routine
			// Let us read the downstream at the same time
			writeError := make(chan error)
			go func() {
				writeError <- resp.Write(r.clientConn)
			}()

			cachedReponse := new(http.Response)
			*cachedReponse = *resp
			cachedResponseWriter := &blockingReadWriter{}
			cachedReponse.Body = ioutil.NopCloser(cachedResponseWriter)
			go func() {
				expires, err = r.proxy.Cache.Accept(req, cachedReponse)
				if err != nil {
					r.logger.Error("error while caching response: %s", err)
				}
				r.logger.Debugf("cache response, will expires at %s", expires)
			}()

			// Read the downstream data, and write to underlying blocking reader and on a cache buffer
			for {
				data := make([]byte, 1024)
				n, err := respBody.Read(data)
				if n > 0 {
					_, err = cachedResponseWriter.Write(data[:n])
					if err != nil {
						return err
					}
					_, err = clientResponseWriter.Write(data[:n])
					if err != nil {
						return err
					}
				}
				if err != nil {
					if err != io.EOF {
						return err
					} else {
						cachedResponseWriter.Close()
						clientResponseWriter.Close()
						break
					}
				}
			}

			return <-writeError
		}
		return resp.Write(r.clientConn)
	}

	r.logger.Debugf("serve cached response, will expires at %s", expires)
	cachedResponse.Header.Set("Age", fmt.Sprintf("%d", int(time.Now().Sub(at).Seconds())))
	return cachedResponse.Write(r.clientConn)
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
		p.Logger = logrus.StandardLogger()
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

type blockingReadWriter struct {
	sync.Mutex
	data []byte
	closed bool
}

func (r *blockingReadWriter) init() {
	if r.data == nil {
		r.data = make([]byte, 0)
	}
}

func (r *blockingReadWriter) Close() error {
	r.Lock()
	defer r.Unlock()
	r.closed = true
	return nil
}

func (r *blockingReadWriter) Write(p []byte) (int, error) {
	r.Lock()
	defer r.Unlock()
	if r.closed {
		return 0, io.EOF
	}
	r.data = append(r.data, p...)
	return len(p), nil
}

func (r *blockingReadWriter) Read(p []byte) (int, error) {
	r.Lock()
	defer r.Unlock()
	r.init()
	if len(r.data) > 0 {
		l := copy(p, r.data)
		r.data = r.data[l:]
		if len(r.data) == 0 && r.closed {
			return l, io.EOF
		}
		return l, nil
	}
	if r.closed {
		return 0, io.EOF
	}
	return 0, nil
}