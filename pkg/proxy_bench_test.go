package httpproxy

import (
	"testing"
	"net/http/httptest"
	"net/http"
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
	l := MustListen(8080)
	defer l.Close()
	proxy := Proxy(l)
	go proxy.Run()
	httpBackend := httptest.NewServer(h)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy.Url()),
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
		if err == nil {
			_, err = io.Copy(ioutil.Discard, res.Body)
			if err != nil {
				b.Error(err)
			}
		}
	}
}

func BenchmarkHTTPSForwardSpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024*1024*10)) // 10MB
	})
	l := MustListen(8080)
	defer l.Close()
	proxy := Proxy(l)
	go proxy.Run()
	httpsBackend := httptest.NewTLSServer(h)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy.Url()),
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
		if err == nil {
			_, err = io.Copy(ioutil.Discard, res.Body)
			if err != nil {
				b.Error(err)
			}
		}
	}
}

func BenchmarkHTTPSBumpRSASpeed(b *testing.B) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1024*1024*10)) // 10MB
	})
	tlsConfig, err := RSA()
	l := MustListen(8080)
	defer l.Close()
	proxy := Proxy(l, WithConnectHandler(&TLSBridge{}), WithTLSConfig(tlsConfig))
	go proxy.Run()
	httpsBackend := httptest.NewTLSServer(h)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy.Url()),
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
		if err == nil {
			_, err = io.Copy(ioutil.Discard, res.Body)
			if err != nil {
				b.Error(err)
			}
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
	l := MustListen(8080)
	defer l.Close()
	proxy := Proxy(l, WithTLSConfig(tlsConfig), WithConnectHandler(&TLSBridge{}))
	go proxy.Run()
	httpsBackend := httptest.NewTLSServer(h)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy.Url()),
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
		if err == nil {
			_, err = io.Copy(ioutil.Discard, res.Body)
			if err != nil {
				b.Error(err)
			}
		}
	}
}