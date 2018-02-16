package httpproxy

import "net/http"

// Proxy requests require no 'Host' header and an absolute url
// Since we are handle this request using iptables
// It look likes a regular http request
func ToProxy(req *http.Request) *http.Request {
	cp := new(http.Request)
	*cp = *req
	if req.URL.Host == "" {
		cp.URL.Host = req.Host
	}
	cp.Host = ""
	cp.Header.Del("Host")
	return cp
}
