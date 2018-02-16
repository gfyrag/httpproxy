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
)

type dialer func(context.Context) error

type Session struct {
	*http.Request
	proxy        *proxy
	once         sync.Once
	clientConn   net.Conn
	remoteConn   net.Conn
	logger       *logrus.Entry
	dialer       dialer
	connectError error
	ctx          context.Context
}

func (r *Session) dialRemote() error {
	r.once.Do(func() {
		r.connectError = r.dialer(r.ctx)
	})
	return r.connectError
}

func (r *Session) doRequest(req *http.Request) (*http.Response, error) {
	err := r.dialRemote()
	if err != nil {
		return nil, errors.Wrap(err, "dial remote")
	}

	if r.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpRequest(req, false)
		r.logger.Logger.Writer().Write([]byte(data))
	}

	err = req.Write(r.remoteConn)
	if err != nil {
		return nil, errors.Wrap(err, "write request to remote")
	}
	resp, err := http.ReadResponse(bufio.NewReader(r.remoteConn), req)
	if err != nil {
		return nil, errors.Wrap(err, "read response from remote")
	}

	if r.logger.Level <= logrus.DebugLevel {
		data, _ := httputil.DumpResponse(resp, false)
		r.logger.Logger.Writer().Write([]byte(data))
	}
	return resp, nil
}

func (r *Session) handleRequest(req *http.Request) error {
	switch {
	case strings.ToLower(req.Header.Get("Upgrade")) == "websocket":
		err := r.dialRemote()
		if err != nil {
			return err
		}
		go req.Write(r.remoteConn)
		io.Copy(r.clientConn, r.remoteConn)
		return nil
	default:
		return r.proxy.cache.
			WithOptions(cache.WithObserver(cache.ObserverFn(func(e cache.Event) {
				switch ee := e.(type) {
				case cache.CacheHitEvent:
					r.logger.Debugf("cache hit")
				case cache.CacheMissEvent:
					r.logger.Debugf("cache miss")
				case cache.NoCachableRequestEvent:
					r.logger.Debugf("request does not allow cache: %s", ee.Err)
				case cache.RevalidatedEvent:
					r.logger.Debugf("remote validate stored response")
				case cache.RevalidatedFromCacheEvent:
					r.logger.Debugf("conditional request validated")
				case cache.RevalidatedFromCacheFailedEvent:
					r.logger.Debugf("conditional request failed")
				case cache.ServedFromCacheEvent:
					r.logger.Debugf("use stored response")
				case cache.NoCachableResponseEvent:
					r.logger.Debugf("response not cachable")
				default:
					r.logger.Debugf("Unknown event: %#T", e)
				}
			}))).
			Serve(r.clientConn, cache.DoerFn(r.doRequest), req)
	}
}

func (r *Session) writeStatusLine(status int, text string) error {
	_, err := fmt.Fprintf(r.clientConn, "HTTP/%d.%d %03d %s\r\n\r\n", r.ProtoMajor, r.ProtoMinor, status, text)
	return err
}

func (r *Session) handleTunneling() error {
	r.logger.Debugf("start tunneling request")
	err := r.writeStatusLine(http.StatusOK, http.StatusText(http.StatusOK))
	if err != nil {
		return err
	}
	return r.proxy.connectHandler.Serve(r)
}

func (r *Session) Serve() error {
	defer func() {
		if r.remoteConn != nil {
			r.remoteConn.Close()
		}
	}()

	netDialer := net.Dialer{}
	r.dialer = func(ctx context.Context) (err error) {
		// See RFC7230 section 5.4 for address construction
		address := r.URL.Host
		if r.URL.Port() == "" {
			address += ":80"
		}
		r.logger.Debugf("dial remote %s", address)
		r.remoteConn, err = netDialer.DialContext(ctx, "tcp", address)
		return err
	}

	var err error
	if r.Method == http.MethodConnect {
		err = r.handleTunneling()
	} else {
		err = r.handleRequest(r.Request)
	}
	if err != nil {
		r.logger.Error(err)
		if e, ok := err.(*net.OpError); ok && e.Err.Error() == "tls: bad certificate" {
			return err
			// Cannot respond since the tls handshake is unsuccessful
		} else {
			err = r.writeStatusLine(http.StatusServiceUnavailable, err.Error())
			if err != nil {
				return err
			}
		}
	}
	return nil
}