package httpproxy

import (
	"github.com/stretchr/testify/suite"
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
)

type HTTPProxyTestSuite struct {
	suite.Suite
}

func (s *HTTPProxyTestSuite) TestHandler() {
	srv := httptest.NewServer(Handler())
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

func TestHTTPProxy(t *testing.T) {
	suite.Run(t, &HTTPProxyTestSuite{})
}
