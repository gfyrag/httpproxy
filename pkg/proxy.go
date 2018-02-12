package httpproxy

import (
	"net/http"
	"time"
	"io"
	"crypto/tls"
	"bufio"
	"github.com/Sirupsen/logrus"
	"github.com/pborman/uuid"
	"context"
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
	r.dialer = func(ctx context.Context) error {
		err := originalDialer(ctx)
		if err != nil {
			return err
		}
		r.remoteConn = tls.Client(r.remoteConn, b.Config)
		return nil
	}
	return r.handleRequest(req)
}

type proxy struct {
	connectHandler ConnectHandler
	cache          *Cache
	logger         *logrus.Logger
	bufferSize     int
	connectTimeout time.Duration
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	id := uuid.New()
	logger := p.logger.WithField("id", id)
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

	ctx := context.Background()
	if p.connectTimeout != 0 {
		ctx, _ = context.WithDeadline(ctx, time.Now().Add(p.connectTimeout))
	}

	req := &Request{
		proxy: p,
		clientConn: clientConn,
		Request: r,
		logger: logger,
		bufferSize: p.bufferSize,
		ctx: ctx,
		tx: p.cache.Tx(r),
	}

	err = req.Serve()
	if err != nil {
		p.logger.Debugf("serve request error: %s", err)
	}
}

type proxyOption interface {
	apply(*proxy)
}
type proxyOptionFn func(*proxy)
func (fn proxyOptionFn) apply(p *proxy) {
	fn(p)
}

func WithLogger(l *logrus.Logger) proxyOptionFn {
	return func(p *proxy) {
		p.logger = l
	}
}

func WithCache(c *Cache) proxyOptionFn {
	return func(p *proxy) {
		p.cache = c
	}
}

func WithConnectHandler(c ConnectHandler) proxyOptionFn {
	return func(p *proxy) {
		p.connectHandler = c
	}
}

func WithBufferSize(bufferSize int) proxyOptionFn {
	return func(p *proxy) {
		p.bufferSize = bufferSize
	}
}

func WithConnectTimeout(t time.Duration) proxyOptionFn {
	return func(p *proxy) {
		p.connectTimeout = t
	}
}

var DefaultOptions = []proxyOption{
	WithLogger(logrus.StandardLogger()),
	WithCache(&Cache{}),
	WithConnectHandler(DefaultConnectHandler),
	WithBufferSize(1024),
	WithConnectTimeout(10*time.Second),
}

func Proxy(opts ...proxyOption) *proxy {
	p := &proxy{}
	for _, o := range append(DefaultOptions, opts...) {
		o.apply(p)
	}
	return p
}