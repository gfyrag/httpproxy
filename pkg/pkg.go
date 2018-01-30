package httpproxy

import (
	"net/http"
	"net/url"
	"net"
	"time"
	"io"
)

var (
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: http.DefaultTransport,
	}
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {

	remoteConn, err := net.DialTimeout("tcp", r.Host, 10 * time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer remoteConn.Close()
	w.WriteHeader(http.StatusOK)

	hi, ok := w.(http.Hijacker)
	if !ok {
		panic("conn can't be hijacked")
	}

	clientConn, _, err := hi.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	go io.Copy(remoteConn, clientConn)
	io.Copy(clientConn, remoteConn)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	hi, ok := w.(http.Hijacker)
	if !ok {
		panic("conn can't be hijacked")
	}

	uri, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	r.URL = uri
	r.RequestURI = ""

	resp, err := httpClient.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientConn, _, err := hi.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	err = resp.Write(clientConn)
	if err != nil {
		panic(err)
	}
}

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleRequest(w, r)
		}
	})
}
