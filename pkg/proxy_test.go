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
	rspHeaders http.Header
	rspStatus int
}

func (s *HTTPProxyTestSuite) SetupTest() {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, h := range s.rspHeaders {
			for _, sh := range h {
				w.Header().Add(k, sh)
			}
		}
		if r.Header.Get("If-None-Match") != "" {
			if r.Header.Get("If-None-Match") == s.rspHeaders.Get("Etags") {
				w.WriteHeader(http.StatusNotModified)
			}
		}
	})
	s.rspHeaders = http.Header{}
	s.rspStatus = http.StatusOK
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
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPS() {
	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPSBump() {
	s.proxy.ConnectHandler = &SSLBump{
		Config: DefaultTLSConfig(),
	}

	rsp, err := s.client.Get(s.httpsBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
}

/*
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
	s.Equal(http.StatusOK, rsp.StatusCode)
}*/

func (s *HTTPProxyTestSuite) TestCache() {
	s.rspHeaders.Add("Cache-Control", "max-age=2")

	req, err := http.NewRequest("GET", s.httpBackend.URL + "/", nil)
	s.NoError(err)

	rsp, err := s.client.Do(req)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	_, _, _, err = s.proxy.Cache.Request(req)
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
	s.rspHeaders.Set("ETags", "0000")

	req, err := http.NewRequest("GET", s.httpBackend.URL + "/", nil)
	s.NoError(err)

	rsp, err := s.client.Do(req)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	_, _, _, err = s.proxy.Cache.Request(req)
	s.NoError(err)

	<-time.After(time.Second)
	s.rspHeaders.Set("Cache-Control", "max-age=2")

	rsp, err = s.client.Get(s.httpBackend.URL)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusOK, rsp.StatusCode)
	s.Empty(rsp.Header.Get("Age"))
	s.Equal(s.rspHeaders.Get("Cache-Control"), rsp.Header.Get("Cache-Control"))
}

func TestProxy(t *testing.T) {
	suite.Run(t, &HTTPProxyTestSuite{})
}
