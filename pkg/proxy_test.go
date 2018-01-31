package httpproxy

import (
	"github.com/stretchr/testify/suite"
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"context"
	"time"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

type HTTPProxyTestSuite struct {
	suite.Suite
	srv         *httptest.Server
	client      *http.Client
	proxy       *Proxy
	httpBackend *httptest.Server
	httpsBackend *httptest.Server
}

func (s *HTTPProxyTestSuite) SetupTest() {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=2")
		w.WriteHeader(http.StatusNoContent)
	})
	s.proxy = &Proxy{}
	s.httpBackend = httptest.NewServer(h)
	s.httpsBackend = httptest.NewTLSServer(h)
	s.srv = httptest.NewServer(s.proxy)
	proxyUrl, err := url.Parse(s.srv.URL)
	if err != nil {
		s.FailNow(err.Error())
	}
	s.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
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
	s.Equal(http.StatusNoContent, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPS() {
	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPSBump() {
	s.proxy.ConnectHandler = &SSLBump{
		Config: DefaultTLSConfig(),
	}

	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
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

	s.proxy.ConnectHandler = &SSLBump{
		Config: tlsConfig,
	}

	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestCache() {
	rsp, err := s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
	_, _, _, err = s.proxy.Cache.Storage.Get("GET:" + s.httpBackend.URL + "/")
	s.NoError(err)

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
	s.NotEmpty(rsp.Header.Get("Age"))

	<-time.After(2*time.Second)

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusNoContent, rsp.StatusCode)
	s.Empty(rsp.Header.Get("Age"))
}

func TestProxy(t *testing.T) {
	suite.Run(t, &HTTPProxyTestSuite{})
}
