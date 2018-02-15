package httpproxy

import (
	"testing"
	"net/http/httptest"
	"net/http"
	"net/url"
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"io"
)

var (
	data = make([]byte, 1024*1024*10)
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
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
	tlsConfig, err := RSA()
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

	tlsConfig, err := ECDSA()
	if err != nil {
		b.Error(err)
		return
	}
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
			continue
		}
		_, err = io.Copy(ioutil.Discard, res.Body)
		if err != nil {
			b.Error(err)
		}
	}
}