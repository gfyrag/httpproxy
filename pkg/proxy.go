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
	"github.com/gfyrag/httpproxy/pkg/cache"
	"net/http/httputil"
	"net"
	"net/url"
)

type TLSInterceptor interface {
	Serve(*Session) error
}
type ConnectHandlerFn func(*Session) error

func (fn ConnectHandlerFn) Serve(r *Session) error {
	return fn(r)
}

var PassthoughTLSInterceptor ConnectHandlerFn = func(request *Session) (err error) {
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

func (b *SSLBump) Serve(r *Session) error {
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
	tlsInterceptor TLSInterceptor
	cache          *cache.Cache
	logger         *logrus.Logger
	connectTimeout time.Duration
	listener net.Listener
}

func (p *proxy) Url() *url.URL {
	url, err := url.Parse("http://" + p.listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return url
}

func (p *proxy) serve(conn net.Conn) error {
	r, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	id := uuid.New()
	logger := p.logger.WithField("id", id)
	logger.Debugf("serve request %s", r.URL)

	if logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(r, false)
		logger.Logger.Writer().Write([]byte(data))
	}

	ctx := context.Background()
	if p.connectTimeout != 0 {
		ctx, _ = context.WithDeadline(ctx, time.Now().Add(p.connectTimeout))
	}
	return (&Session{
		proxy: p,
		clientConn: conn,
		Request: r,
		logger: logger,
		ctx: ctx,
	}).Serve()
}

func (p *proxy) Run() error {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			p.serve(conn)
		}()
	}
}

type Option interface {
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

func WithCache(c *cache.Cache) proxyOptionFn {
	return func(p *proxy) {
		p.cache = c
	}
}

func WithTLSInterceptor(c TLSInterceptor) proxyOptionFn {
	return func(p *proxy) {
		p.tlsInterceptor = c
	}
}

func WithConnectTimeout(t time.Duration) proxyOptionFn {
	return func(p *proxy) {
		p.connectTimeout = t
	}
}

var DefaultOptions = []Option{
	WithLogger(logrus.StandardLogger()),
	WithCache(cache.New()),
	WithTLSInterceptor(PassthoughTLSInterceptor),
	WithConnectTimeout(10*time.Second),
}

func Proxy(listener net.Listener, opts ...Option) *proxy {
	p := &proxy{
		listener: listener,
	}
	for _, o := range append(DefaultOptions, opts...) {
		o.apply(p)
	}
	return p
}