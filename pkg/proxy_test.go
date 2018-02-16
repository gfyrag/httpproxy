package httpproxy

import (
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"strings"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestHTTP(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	proxy := Proxy()
	httpBackend := httptest.NewServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
	}

	rsp, err := client.Get(httpBackend.URL)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
	assert.Equal(t, http.StatusOK, rsp.StatusCode)
}

func TestHTTPS(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	proxy := Proxy()
	httpsBackend := httptest.NewTLSServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
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


	rsp, err := client.Get(httpsBackend.URL)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
	assert.Equal(t, http.StatusOK, rsp.StatusCode)
}

func TestHTTPSBump(t *testing.T) {
	tlsConfig, err := RSA()
	assert.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	proxy := Proxy(WithConnectHandler(&SSLBump{
		Config: tlsConfig,
	}))
	httpsBackend := httptest.NewTLSServer(h)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
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

	rsp, err := client.Get(httpsBackend.URL)
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
	assert.Equal(t, http.StatusOK, rsp.StatusCode)
}

func TestSecuredWebSocket(t *testing.T) {

	ws := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			panic(err)
		}
		conn.Close()
	})
	tlsConfig, err := RSA()
	assert.NoError(t, err)
	proxy := Proxy(WithConnectHandler(&SSLBump{
		Config: tlsConfig,
	}))
	wssBackend := httptest.NewTLSServer(ws)
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	dialer := websocket.Dialer{
		Proxy: func(*http.Request) (*url.URL, error) {
			return proxyUrl, nil
		},
		TLSClientConfig: &tls.Config{
			RootCAs: wssBackend.TLS.RootCAs,
			InsecureSkipVerify: true,
		},
	}

	_, _, err = dialer.Dial(strings.Replace(wssBackend.URL, "http", "ws", -1), nil)
	assert.NoError(t, err)
}

func TestInvalidRemote(t *testing.T) {
	proxy := Proxy()
	srv := httptest.NewServer(proxy)
	proxyUrl, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
	}

	rsp, err := client.Get("http://127.0.0.1:1234")
	assert.NoError(t, err)
	assert.NotNil(t, rsp)
	assert.Equal(t, http.StatusServiceUnavailable, rsp.StatusCode)
}
