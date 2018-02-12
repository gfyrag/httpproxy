package httpproxy

import (
	"net"
	"context"
	"net/http"
	"sync"
	"github.com/Sirupsen/logrus"
	"net/http/httputil"
	"bufio"
	"io/ioutil"
	"io"
	"fmt"
	"time"
)

type dialer func(context.Context) error

type Request struct {
	*http.Request
	proxy        *proxy
	once         sync.Once
	clientConn   net.Conn
	remoteConn   net.Conn
	logger       *logrus.Entry
	dialer       dialer
	bufferSize   int
	connectError error
	ctx          context.Context
	tx           *cacheTransaction
}

func (r *Request) dialRemote() error {
	r.once.Do(func() {
		r.connectError = r.dialer(r.ctx)
	})
	return r.connectError
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

func (r *Request) handleRequest(req *http.Request) error {

	defer func() {
		r.logger.Info("terminated")
	}()
	r.tx.Start()
	defer r.tx.Release()

	var (
		rsp *http.Response
		cachedResponse *http.Response
	)
	defer func() {
		if rsp != nil {
			rsp.Body.Close()
		}
	}()

	meta, err := r.tx.ReadMetadata()
	if err != nil && err != ErrCacheMiss {
		return err
	}

	if err == nil {
		cachedResponse, err = r.tx.ReadResponse()
		if err != nil {
			panic(err)
		}
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
			} else {
				r.logger.Debugf("server respond with not modified content (304), update meta and respond with cached response")
				rsp = cachedResponse
				meta, err = r.tx.Prepare(rsp)
				if err != nil {
					r.logger.Error("error while writing metadata: %s", err)
					return err
				}
			}
		} else {
			r.logger.Debugf("found fresh response in cache (%s), serve cached response", meta.Expires)
			rsp = cachedResponse
		}
	}

	if rsp == nil {
		r.logger.Debugf("cache miss, issue new request")
		rsp, err = r.doRequest(req)
		if err != nil {
			return err
		}
	}

	if rsp == cachedResponse {
		rsp.Header.Set("Age", fmt.Sprintf("%d", int(time.Now().Sub(meta.Date).Seconds())))
	}

	if rsp != cachedResponse && r.tx.IsCacheable(rsp) {
		var w *io.PipeWriter
		rspCp := new(http.Response)
		*rspCp = *rsp
		rspCp.Body, w = io.Pipe()
		rsp.Body = ioutil.NopCloser(io.TeeReader(rsp.Body, w))
		defer w.Close()

		meta, err := r.tx.Prepare(rspCp)
		if err != nil {
			r.logger.Error("error while writing metadata: %s", err)
			return err
		}
		r.logger.Debugf("cache response, will expires at %s", meta.Expires)
		go func() {
			err = r.tx.WriteResponse(rspCp)
			if err != nil {
				r.logger.Error("error while caching response: %s", err)
				return
			}
		}()
	}

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
	return r.proxy.connectHandler.Serve(r)
}

func (r *Request) Serve() error {
	defer func() {
		if r.remoteConn != nil {
			r.remoteConn.Close()
		}
	}()

	netDialer := net.Dialer{}
	r.dialer = func(ctx context.Context) (err error) {
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