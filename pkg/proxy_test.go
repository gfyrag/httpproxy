package httpproxy

import (
	"github.com/stretchr/testify/suite"
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"time"
	"context"
	"io/ioutil"
	"io"
	"strings"
	"github.com/gorilla/websocket"
)

var (
	data = make([]byte, 1024*1024*10)
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

type HTTPProxyTestSuite struct {
	suite.Suite
	srv         *httptest.Server
	client      *http.Client
	proxy       *proxy
	httpBackend *httptest.Server
	httpsBackend *httptest.Server
	wsBackend *httptest.Server
	wssBackend *httptest.Server
	rspHeaders http.Header
	rspStatus int
	proxyUrl *url.URL
}

func (s *HTTPProxyTestSuite) SetupTest() {
	var err error
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, h := range s.rspHeaders {
			for _, sh := range h {
				w.Header().Add(k, sh)
			}
		}
		if r.Header.Get("If-None-Match") != "" {
			if r.Header.Get("If-None-Match") == s.rspHeaders.Get("Etag") {
				w.WriteHeader(http.StatusNotModified)
			}
		}
	})
	ws := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			panic(err)
		}
		conn.Close()
	})
	s.rspHeaders = http.Header{}
	s.rspStatus = http.StatusOK
	s.proxy = Proxy()
	s.httpBackend = httptest.NewServer(h)
	s.httpsBackend = httptest.NewTLSServer(h)
	s.wsBackend = httptest.NewServer(ws)
	s.wssBackend = httptest.NewTLSServer(ws)
	s.srv = httptest.NewServer(s.proxy)
	s.proxyUrl, err = url.Parse(s.srv.URL)
	if err != nil {
		s.FailNow(err.Error())
	}
	s.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: http.ProxyURL(s.proxyUrl),
			DisableCompression: true,
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func (s *HTTPProxyTestSuite) TearDownTest() {
	s.srv.Close()
	s.httpsBackend.Close()
	s.httpBackend.Close()
}

func (s *HTTPProxyTestSuite) TestHTTP() {
	rsp, err := s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPS() {
	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPSBump() {
	tlsConfig, err := RSA(RSAConfig{
		Domain: "example.net",
	})
	s.NoError(err)
	s.proxy.connectHandler = &SSLBump{
		Config: tlsConfig,
	}

	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestACMEHTTPSBump() {
	tlsConfig, err := ACME(context.TODO(), ACMEConfig{
		Email: "geoffrey.ragot@gmail.com",
		Url: "https://acme-staging.api.letsencrypt.org/directory",
		Domain: "gfyrag.me",
	})
	if err != nil {
		s.FailNow(err.Error())
	}

	s.proxy.connectHandler = &SSLBump{
		Config: tlsConfig,
	}

	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestCache() {
	s.rspHeaders.Add("Cache-Control", "max-age=2")

	req, err := http.NewRequest("GET", s.httpBackend.URL + "/", nil)
	s.NoError(err)

	rsp, err := s.client.Do(req)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	_, err = s.proxy.cache.ReadMetadata(req)
	s.NoError(err)

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	s.NotEmpty(rsp.Header.Get("Age"))

	<-time.After(2*time.Second)

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	s.Empty(rsp.Header.Get("Age"))
}

func (s *HTTPProxyTestSuite) TestETags() {
	s.rspHeaders.Set("Cache-Control", "max-age=1")
	s.rspHeaders.Set("ETag", "0000")

	req, err := http.NewRequest("GET", s.httpBackend.URL + "/", nil)
	s.NoError(err)

	rsp, err := s.client.Do(req)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	_, err = s.proxy.cache.ReadMetadata(req)
	s.NoError(err)

	<-time.After(time.Second)

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	s.Empty(rsp.Header.Get("Age"))
}

func (s *HTTPProxyTestSuite) TestWebSocket() {
	dialer := websocket.Dialer{
		Proxy: func(*http.Request) (*url.URL, error) {
			return s.proxyUrl, nil
		},
	}

	_, _, err := dialer.Dial(strings.Replace(s.wsBackend.URL, "http", "ws", -1), nil)
	s.NoError(err)
}

func (s *HTTPProxyTestSuite) TestSecuredWebSocket() {
	dialer := websocket.Dialer{
		Proxy: func(*http.Request) (*url.URL, error) {
			return s.proxyUrl, nil
		},
		TLSClientConfig: &tls.Config{
			RootCAs: s.wssBackend.TLS.RootCAs,
			InsecureSkipVerify: true,
		},
	}
	tlsConfig, err := RSA(RSAConfig{
		Domain: "example.net",
	})
	s.NoError(err)
	s.proxy.connectHandler = &SSLBump{
		Config: tlsConfig,
	}

	_, _, err = dialer.Dial(strings.Replace(s.wssBackend.URL, "http", "ws", -1), nil)
	s.NoError(err)
}


func TestProxy(t *testing.T) {
	suite.Run(t, &HTTPProxyTestSuite{})
}

func BenchmarkHTTPSpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data) // 10MB
	})
	proxy := &proxy{}
	httpBackend := httptest.NewServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		b.Error(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequest("GET", httpBackend.URL, nil)
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0 ; i < b.N ; i++ {
		res, err := client.Do(req)
		if err != nil {
			b.Error(err)
		}
		_, err = io.Copy(ioutil.Discard, res.Body)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkHTTPSForwardSpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024*1024*10)) // 10MB
	})
	proxy := &proxy{}
	httpsBackend := httptest.NewTLSServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		b.Error(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequest("GET", httpsBackend.URL, nil)
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0 ; i < b.N ; i++ {
		res, err := client.Do(req)
		if err != nil {
			b.Error(err)
		}
		_, err = io.Copy(ioutil.Discard, res.Body)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkHTTPSBumpRSASpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024*1024*10)) // 10MB
	})
	tlsConfig, err := RSA(RSAConfig{
		Domain: "example.net",
	})
	proxy := &proxy{
		connectHandler: &SSLBump{
			Config: tlsConfig,
		},
	}
	httpsBackend := httptest.NewTLSServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		b.Error(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequest("GET", httpsBackend.URL, nil)
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0 ; i < b.N ; i++ {
		res, err := client.Do(req)
		if err != nil {
			b.Error(err)
		}
		_, err = io.Copy(ioutil.Discard, res.Body)
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkHTTPSBumpECDSASpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data) // 10MB
	})

	tlsConfig, err := ECDSA(ECDSAConfig{
		Domain: "example.net",
	})
	if err != nil {
		b.Error(err)
		return
	}
	proxy := &proxy{
		connectHandler: &SSLBump{
			Config: tlsConfig,
		},
		bufferSize: 1024*1024,
	}
	httpsBackend := httptest.NewTLSServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		b.Error(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequest("GET", httpsBackend.URL, nil)
	if err != nil {
		b.Error(err)
	}

	b.ResetTimer()
	for i := 0 ; i < b.N ; i++ {
		res, err := client.Do(req)
		if err != nil {
			b.Error(err)
			continue
		}
		_, err = io.Copy(ioutil.Discard, res.Body)
		if err != nil {
			b.Error(err)
		}
	}
}