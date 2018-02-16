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
	"crypto/tls"
	"errors"
	"net/http/httputil"
)

var (
	ErrNoTLSConfig = errors.New("no tls config")
)

type proxy struct {
	tlsConfig *tls.Config
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

func (p *proxy) tlsBridge(session *Session) error {
	if p.tlsConfig == nil {
		return ErrNoTLSConfig
	}
	session.clientConn = tls.Server(session.clientConn, p.tlsConfig)
	session.dialer = func(d dialer) dialer {
		return func(ctx context.Context, req *http.Request) (net.Conn, error) {
			conn, err := d(ctx, req)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, p.tlsConfig), nil
		}
	}(session.dialer)
	return nil
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
		dialer: URLDialer(p.dialer),
	}

	// Try to detect tls connection reading one byte of the handshake
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
		err := p.tlsBridge(session)
		if err != nil {
			return err
		}
	}

	req, err := http.ReadRequest(bufio.NewReader(session.clientConn))
	if err != nil {
		return err
	}

	if p.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		p.logger.Writer().Write([]byte(data))
	}

	req = ToProxy(req)
	if buf[0] == 0x16 && req.URL.Port() == "" {
		req.URL.Host = req.URL.Host + ":443"
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

func WithTLSConfig(tlsConfig *tls.Config) proxyOptionFn {
	return func(p *proxy) {
		p.tlsConfig = tlsConfig
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