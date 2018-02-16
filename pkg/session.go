package httpproxy

import (
	"net"
	"context"
	"net/http"
	"sync"
	"github.com/Sirupsen/logrus"
	"net/http/httputil"
	"bufio"
	"fmt"
	"github.com/pkg/errors"
	"github.com/gfyrag/httpproxy/pkg/cache"
	"io"
	"strings"
	"crypto/tls"
)

type ConnectHandler interface {
	Serve(*Session, *http.Request) error
}
type ConnectHandlerFn func(*Session, *http.Request) error

func (fn ConnectHandlerFn) Serve(s *Session, r *http.Request) error {
	return fn(s, r)
}

var PassthroughConnectHandler ConnectHandlerFn = func(session *Session, req *http.Request) (err error) {
	conn, err := session.dialer(session.ctx, req)
	if err != nil {
		return err
	}
	go io.Copy(conn, session.clientConn)
	io.Copy(session.clientConn, conn)
	return nil
}

type SSLBump struct {
	Config *tls.Config
}

func (b *SSLBump) Serve(session *Session, connectRequest *http.Request) (err error) {
	session.clientConn = tls.Server(session.clientConn, b.Config)

	req, err := http.ReadRequest(bufio.NewReader(session.clientConn))
	if err != nil {
		return err
	}
	req = ToProxy(req)

	originalDialer := session.dialer
	session.dialer = func(ctx context.Context, req *http.Request) (net.Conn, error) {
		conn, err := originalDialer(ctx, connectRequest)
		if err != nil {
			return nil, err
		}
		return tls.Client(conn, b.Config), nil
	}
	return session.handleRequest(req)
}

type Session struct {
	proxy        *proxy
	once         sync.Once
	clientConn   net.Conn
	logger       *logrus.Entry
	dialer       dialer
	ctx          context.Context
}

func (s *Session) doRequest(req *http.Request, remoteConn net.Conn) (*http.Response, error) {
	if s.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		s.logger.Logger.Writer().Write([]byte(data))
	}

	err := req.Write(remoteConn)
	if err != nil {
		return nil, errors.Wrap(err, "write request to remote")
	}
	resp, err := http.ReadResponse(bufio.NewReader(remoteConn), req)
	if err != nil {
		return nil, errors.Wrap(err, "read response from remote")
	}

	if s.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpResponse(resp, false)
		s.logger.Logger.Writer().Write([]byte(data))
	}
	return resp, nil
}

func (s *Session) handleRequest(req *http.Request) error {

	var (
		remoteConn net.Conn
		err error
	)
	defer func() {
		if remoteConn != nil {
			err = remoteConn.Close()
			if err != nil {
				s.logger.Errorf("Error closing remote conn: %s", err)
			}
		}
	}()

	switch {
	case strings.ToLower(req.Header.Get("Upgrade")) == "websocket":
		remoteConn, err = s.dialer(s.ctx, req)
		if err != nil {
			return err
		}
		go req.Write(remoteConn)
		io.Copy(s.clientConn, remoteConn)
		return nil
	default:
		return s.proxy.cache.
			WithOptions(cache.WithObserver(cache.ObserverFn(func(e cache.Event) {
				switch ee := e.(type) {
				case cache.CacheHitEvent:
					s.logger.Debugf("cache hit")
				case cache.CacheMissEvent:
					s.logger.Debugf("cache miss")
				case cache.NoCachableRequestEvent:
					s.logger.Debugf("request does not allow cache: %s", ee.Err)
				case cache.RevalidatedEvent:
					s.logger.Debugf("remote validate stored response")
				case cache.RevalidatedFromCacheEvent:
					s.logger.Debugf("conditional request validated")
				case cache.RevalidatedFromCacheFailedEvent:
					s.logger.Debugf("conditional request failed")
				case cache.ServedFromCacheEvent:
					s.logger.Debugf("use stored response")
				case cache.NoCachableResponseEvent:
					s.logger.Debugf("response not cachable")
				default:
					s.logger.Debugf("Unknown event: %#T", e)
				}
			}))).
			Serve(s.clientConn, cache.DoerFn(func(r *http.Request) (*http.Response, error) {
				remoteConn, err = s.dialer(s.ctx, req)
				if err != nil {
					return nil, err
				}
				return s.doRequest(req, remoteConn)
			}), req)
	}
}

func (s *Session) writeStatusLine(req *http.Request, status int, text string) error {
	_, err := fmt.Fprintf(s.clientConn, "HTTP/%d.%d %03d %s\r\n\r\n", req.ProtoMajor, req.ProtoMinor, status, text)
	return err
}

func (s *Session) handleTunneling(req *http.Request) error {
	s.logger.Debugf("start tunneling request")
	err := s.writeStatusLine(req, http.StatusOK, http.StatusText(http.StatusOK))
	if err != nil {
		return err
	}
	return s.proxy.connectHandler.Serve(s, req)
}

func (s *Session) Serve(req *http.Request) error {

	var err error
	if req.Method == http.MethodConnect {
		err = s.handleTunneling(req)
	} else {
		err = s.handleRequest(req)
	}
	if err != nil {
		s.logger.Error(err)
		if e, ok := err.(*net.OpError); ok && e.Err.Error() == "tls: bad certificate" {
			return err
			// Cannot respond since the tls handshake is unsuccessful
		} else {
			err = s.writeStatusLine(req, http.StatusServiceUnavailable, err.Error())
			if err != nil {
				return err
			}
		}
	}
	return nil
}