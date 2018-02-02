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
	"io/ioutil"
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

func (r *Request) doRequest(req *http.Request) (*http.Response, error) {
	err := r.dialRemote()
	if err != nil {
		return nil, err
	}

	if r.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		r.logger.Logger.Writer().Write([]byte(data))
	}

	err = req.Write(r.remoteConn)
	if err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(r.remoteConn), req)
	if err != nil {
		return nil, err
	}

	if r.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpResponse(resp, false)
		r.logger.Logger.Writer().Write([]byte(data))
	}
	return resp, nil
}

func (r *Request) checkModified(cachedResponse *http.Response, req *http.Request) (*http.Response, bool, error) {
	etag := cachedResponse.Header.Get("ETag")
	if etag != "" {
		r.logger.Debugf("found etag header in previous response: %s", etag)
		req.Header.Set("If-None-Match", etag)
	}
	rsp, err := r.doRequest(req)
	if err != nil {
		return nil, false, err
	}
	if rsp.StatusCode == http.StatusNotModified {
		rsp.Body.Close()
		return rsp, false, nil
	}
	return rsp, true, nil
}

func (r *Request) createBlockingResponse(rsp *http.Response) (*http.Response, *blockingReadWriter) {
	cp := new(http.Response)
	*cp = *rsp
	cachedResponseWriter := &blockingReadWriter{}
	cp.Body = ioutil.NopCloser(cachedResponseWriter)
	return cp, cachedResponseWriter
}

func (r *Request) responseAndCache(rsp *http.Response, req *http.Request) error {
	defer rsp.Body.Close()

	forCacheResponse, forCacheWriter := r.createBlockingResponse(rsp)
	forClientResponse, forClientWriter := r.createBlockingResponse(rsp)
	errCh := make(chan error)
	go func() {
		errCh <- forClientResponse.Write(r.clientConn)
	}()
	go func() {
		meta, err := r.proxy.Cache.Accept(forCacheResponse, req)
		if err != nil {
			r.logger.Error("error while caching response: %s", err)
		}
		r.logger.Debugf("cache response, will expires at %s", meta.Expires)
	}()

	for {
		data := make([]byte, 1024)
		n, err := rsp.Body.Read(data)
		if n > 0 {
			_, err = forCacheWriter.Write(data[:n])
			if err != nil {
				return err
			}
			_, err = forClientWriter.Write(data[:n])
			if err != nil {
				return err
			}
		}
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				forCacheWriter.Close()
				forClientWriter.Close()
				break
			}
		}
	}

	return <- errCh
}

func (r *Request) handleRequest(req *http.Request) error {

	var (
		rsp *http.Response
	)
	cachedResponse, meta, err := r.proxy.Cache.Request(req)
	if err != nil && err != ErrCacheMiss {
		return err
	}

	if err == nil {
		if meta.Expired() {
			r.logger.Debugf("found expired response in cache (%s)", meta.Expires)
			var modified bool
			rsp, modified, err = r.checkModified(cachedResponse, req)
			if err != nil {
				return err
			}
			if modified {
				r.logger.Debugf("server respond with modified content, close the cached response and issue new request")
				cachedResponse.Body.Close()
				if r.proxy.Cache.IsCacheable(rsp, req) {
					return r.responseAndCache(rsp, req)
				}
			} else {
				r.logger.Debugf("server respond with not modified content (304), update meta and respond with cached response")
				r.proxy.Cache.UpdateMeta(cachedResponse, req)
				rsp = cachedResponse
			}
		} else {
			r.logger.Debugf("found fresh response in cache (%s), serve cached response", meta.Expires)
			rsp = cachedResponse
			rsp.Header.Set("Age", fmt.Sprintf("%d", int(time.Now().Sub(meta.Date).Seconds())))
		}
	}

	if rsp == nil {
		r.logger.Debugf("cache miss, issue new request")
		rsp, err = r.doRequest(req)
		if err != nil {
			return err
		}
		if r.proxy.Cache.IsCacheable(rsp, req) {
			return r.responseAndCache(rsp, req)
		}
	}

	defer rsp.Body.Close()
	return rsp.Write(r.clientConn)
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