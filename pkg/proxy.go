package httpproxy

import (
	"net/http"
	"time"
	"io"
	"bufio"
	"github.com/Sirupsen/logrus"
	"github.com/pborman/uuid"
	"context"
	"github.com/gfyrag/httpproxy/pkg/cache"
	"net"
	"net/url"
	"bytes"
)

type TLSInterceptor interface {
	Intercept(*Session, *net.Dialer, *net.TCPAddr) error
}
type TLSInterceptorFn func(*Session, *net.Dialer, *net.TCPAddr) error

func (fn TLSInterceptorFn) Intercept(s *Session, dialer *net.Dialer, remoteAddr *net.TCPAddr) error {
	return fn(s, dialer, remoteAddr)
}

func PassthroughTLSInterceptor(session *Session, dialer *net.Dialer, remoteAddr *net.TCPAddr) error {
	remoteConn, err := dialer.DialContext(session.ctx, "tcp", remoteAddr.String())
	if err != nil {
		return err
	}
	defer remoteConn.Close()

	go io.Copy(remoteConn, session.clientConn)
	io.Copy(session.clientConn, remoteConn)
	return nil
}

type proxy struct {
	tlsInterceptor TLSInterceptor
	connectHandler ConnectHandler
	cache          *cache.Cache
	logger         *logrus.Logger
	connectTimeout time.Duration
	listener       net.Listener
	dialer *net.Dialer
}

func (p *proxy) Url() *url.URL {
	url, err := url.Parse("http://" + p.listener.Addr().String())
	if err != nil {
		panic(err)
	}
	return url
}

type wrappedTCPConn struct {
	net.Conn
	reader io.Reader
}

func (c *wrappedTCPConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (p *proxy) serve(conn net.Conn) error {

	ctx := context.Background()
	if p.connectTimeout != 0 {
		ctx, _ = context.WithDeadline(ctx, time.Now().Add(p.connectTimeout))
	}

	session := &Session{
		proxy: p,
		clientConn: conn,
		logger: p.logger.WithField("id", uuid.New()),
		ctx: ctx,
		dialer: URLDialer,
	}

	addr, _, err := getOriginalIPDst(conn.(*net.TCPConn))
	if err == nil { // Detect iptables
		p.logger.Debugf("detect iptables")
		session.dialer = func(ctx context.Context, req *http.Request) (net.Conn, error) {
			return p.dialer.DialContext(ctx, "tcp", addr.String())
		}

		var buf [1]byte
		_, err := conn.Read(buf[:])
		if err != nil {
			return err
		}
		session.clientConn = &wrappedTCPConn{
			Conn: conn,
			reader: io.MultiReader(bytes.NewReader(buf[:1]), conn),
		}

		if buf[0] == 0x16 { // TLS handshake
			p.logger.Debugf("detect ssl connection")
			return p.tlsInterceptor.Intercept(session, p.dialer, addr)
		}
	}

	req, err := http.ReadRequest(bufio.NewReader(session.clientConn))
	if err != nil {
		return err
	}
	if addr != nil {
		p.logger.Debugf("detect plain text connection")
		req = ToProxy(req)
	}
	return session.Serve(req)
}

func (p *proxy) Run() error {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer conn.Close()
			err := p.serve(conn)
			if err != nil {
				p.logger.Debugf("Error handling request: %s", err)
			}
		}()
	}
	return nil
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

func WithConnectHandler(c ConnectHandler) proxyOptionFn {
	return func(p *proxy) {
		p.connectHandler = c
	}
}

func WithConnectTimeout(t time.Duration) proxyOptionFn {
	return func(p *proxy) {
		p.connectTimeout = t
	}
}

func WithTLSInterceptor(tlsInterceptor TLSInterceptor) proxyOptionFn {
	return func(p *proxy) {
		p.tlsInterceptor = tlsInterceptor
	}
}

func WithDialer(dialer *net.Dialer) proxyOptionFn {
	return func(p *proxy) {
		p.dialer = dialer
	}
}

var DefaultOptions = []Option{
	WithLogger(logrus.StandardLogger()),
	WithCache(cache.New()),
	WithConnectTimeout(10*time.Second),
	WithConnectHandler(PassthroughConnectHandler),
	WithTLSInterceptor(TLSInterceptorFn(PassthroughTLSInterceptor)),
	WithDialer(&net.Dialer{}),
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