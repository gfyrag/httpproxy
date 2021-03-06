package cache

import (
	"net/http"
	"strings"
	"time"
	"strconv"
)

var (
	// See RFC2616 section 13.5.1
	hopByHopHeaders = []string {
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
)

// See RFC2616 section 13.5.1
func stripHopByHopHeaders(v interface{}) {
	headers := hopByHopHeaders[:]
	var header http.Header
	switch vv := v.(type) {
	case *http.Request:
		header = vv.Header
		headers = append(headers, Connection(vv)...)
	case *http.Response:
		header = vv.Header
	}
	for _, h := range headers {
		header.Del(h)
	}
}

// See other directives : https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
type cacheControl struct {
	request bool
	maxAge time.Duration
	sMaxAge time.Duration
	public bool
	private bool
	noStore bool
	noCache bool
}

func (c *cacheControl) Parse(v interface{}) error {
	var (
		headers http.Header
	)
	switch vv := v.(type) {
	case *http.Response:
		headers = vv.Header
	case *http.Request:
		headers = vv.Header
		c.request = true
	default:
		panic("unexpected object")
	}
	for _, h := range normalizeHeader("Cache-Control", headers) {
		h = strings.ToLower(h)
		switch {
		case h == "private":
			c.private = true
		case h == "no-store":
			c.noStore = true
		case h == "no-cache":
			c.noCache = true
		case h == "public":
			c.public = true
		case strings.HasPrefix(h, "max-age"):
			parsed, err := strconv.ParseInt(h[8:], 10, 0)
			if err != nil {
				return err
			}
			c.maxAge = time.Duration(parsed) * time.Second
		case strings.HasPrefix(h, "s-maxage"):
			parsed, err := strconv.ParseInt(h[9:], 10, 0)
			if err != nil {
				return err
			}
			c.sMaxAge = time.Duration(parsed)*time.Second
		}
	}
	return nil
}

func (c *cacheControl) Cacheable() bool {
	if c.request {
		return !c.private && !c.noStore
	} else {
		return c.maxAge > 0 || c.sMaxAge > 0
	}
}

func CacheControl(v interface{}) (cacheControl, error) {
	cc := cacheControl{}
	err := cc.Parse(v)
	if err != nil {
		return cacheControl{}, err
	}
	return cc, nil
}

func Expires(r *http.Response) *time.Time {
	expiresHeader := r.Header.Get("Expires")
	if expiresHeader == "" {
		return nil
	}

	// See RFC7234 section 5.3
	//  A cache recipient MUST interpret invalid date formats, especially the
	// value "0", as representing a time in the past (i.e., "already
	// expired").
	// So we ignore err
	expires, _ := http.ParseTime(expiresHeader)
	return &expires
}

func LastModified(r *http.Response) time.Time {
	t, _ := http.ParseTime(r.Header.Get("Last-Modified"))
	return t
}

func ETag(r *http.Response) string {
	return r.Header.Get("ETag")
}

func IfNoneMatch(r *http.Request) string {
	return r.Header.Get("If-None-Match")
}

func IfModifiedSince(r *http.Request) time.Time {
	t, _ := http.ParseTime(r.Header.Get("If-Nodified-Since"))
	return t
}

func Connection(r *http.Request) []string {
	return normalizeHeader("Connection", r.Header)
}