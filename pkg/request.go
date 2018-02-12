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
	"github.com/pkg/errors"
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

func (r *Request) checkModified(cachedResponse *http.Response, req *http.Request) (*http.Response, bool, error) {
	etag := cachedResponse.Header.Get("ETag")
	if etag != "" {
		r.logger.Debugf("found etag header in previous response: %s", etag)
		req.Header.Set("If-None-Match", etag)
	}
	rsp, err := r.doRequest(req)
	if err != nil {
		return nil, false, errors.Wrap(err, "check modified request")
	}
	if rsp.StatusCode == http.StatusNotModified {
		rsp.Body.Close()
		return rsp, false, nil
	}
	return rsp, true, nil
}

func (r *Request) isCacheAware(req *http.Request) bool {
	return req.Header.Get("If-None-Match") != "" ||
		req.Header.Get("If-Match") != "" ||
		req.Header.Get("If-Modified-Since") != ""
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
		return errors.Wrap(err, "reading cache")
	}

	if err == nil {
		cachedResponse, err = r.tx.ReadResponse()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("reading cached response %s", r.tx.id))
		}
		if meta.Expired() {
			r.logger.Debugf("found expired response in cache (%s)", meta.Expires)
			if !r.isCacheAware(req) {
				r.logger.Debugf("request does not contains cache directive")
				var modified bool
				rsp, modified, err = r.checkModified(cachedResponse, req)
				if err != nil {
					return errors.Wrap(err, "checking if response was modified")
				}
				if modified {
					r.logger.Debugf("server respond with modified content, close the cached response and issue new request")
					cachedResponse.Body.Close()
				} else {
					r.logger.Debugf("server respond with not modified content (304), update meta and respond with cached response")
					rsp = cachedResponse
					meta, err = r.tx.Prepare(rsp)
					if err != nil {
						return errors.Wrap(err, "updating metadata")
					}
				}
			} else {
				r.logger.Debugf("request contains cache directive, pass through")
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
			return errors.Wrap(err, "performing request")
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
			return errors.Wrap(err, "writing metadata")
		}
		r.logger.Debugf("cache response, will expires at %s", meta.Expires)
		go func() {
			err = r.tx.WriteResponse(rspCp)
			if err != nil {
				r.logger.Error("caching response: %s", err)
				return
			}
		}()
	}

	err = rsp.Write(r.clientConn)
	if err != nil {
		// Force the complete read of the body to complete caching operation
		_, err := io.Copy(ioutil.Discard, rsp.Body)
		if err != nil {
			return errors.Wrap(err, "flushing response")
		}
		return errors.Wrap(err, "writing response")
	}
	return nil
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