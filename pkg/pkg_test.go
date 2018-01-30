package httpproxy

import (
	"github.com/stretchr/testify/suite"
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
)

type HTTPProxyTestSuite struct {
	suite.Suite
}

func (s *HTTPProxyTestSuite) TestHTTP() {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	proxyUrl, err := url.Parse(srv.URL)
	s.NoError(err)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			DisableCompression: true,
		},
	}
	req, err := http.NewRequest("GET", "http://google.fr", nil)
	s.NoError(err)

	rsp, err := client.Do(req)
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusMovedPermanently, rsp.StatusCode)
}

func (s *HTTPProxyTestSuite) TestHTTPS() {
	srv := httptest.NewServer(Handler())
	defer srv.Close()

	proxyUrl, err := url.Parse(srv.URL)
	s.NoError(err)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
		},
	}

	rsp, err := client.Get("https://google.fr")
	s.NoError(err)
	s.NotNil(rsp)
	s.Equal(http.StatusMovedPermanently, rsp.StatusCode)
}

func TestHTTPProxy(t *testing.T) {
	suite.Run(t, &HTTPProxyTestSuite{})
}
