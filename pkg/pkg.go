package httpproxy

import (
	"net/http"
	"net/url"
)

var (
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: http.DefaultTransport,
	}
)

func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		hi, ok := w.(http.Hijacker)
		if !ok {
			panic("conn can't be hijacked")
		}

		conn, _, err := hi.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
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

		err = resp.Write(conn)
		if err != nil {
			panic(err)
		}
	})
}
