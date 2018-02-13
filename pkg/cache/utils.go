package cache

import (
	"net/http"
	"net/textproto"
	"strings"
)

func normalizeHeader(key string, bag http.Header) []string {
	res := make([]string, 0)
	for _, h := range bag[textproto.CanonicalMIMEHeaderKey(key)] {
		for _, hh := range strings.Split(h, ",") {
			res = append(res, strings.TrimSpace(hh))
		}
	}
	return res
}
