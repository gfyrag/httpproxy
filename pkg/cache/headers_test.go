package cache

import (
	"testing"
	"net/http"
	"github.com/stretchr/testify/assert"
	"time"
)

func TestCacheControl(t *testing.T) {

	tests := []struct {
		CacheControl string
		Request bool
		Cachable bool
	} {
		{
			Request: true,
			Cachable: true,
		},
		{
			Request: true,
			Cachable: false,
			CacheControl: "no-store",
		},
		{
			Request: true,
			Cachable: false,
			CacheControl: "private",
		},
		{
			Cachable: true,
			CacheControl: "max-age=10",
		},
		{
			Cachable: true,
			CacheControl: "s-maxage=10",
		},
		{
			Cachable: false,
		},
	}

	for _, test := range tests {
		var v interface{}
		if test.Request {
			req, err := http.NewRequest("GET", "http://127.0.0.1", nil)
			assert.NoError(t, err)
			req.Header.Set("Cache-Control", test.CacheControl)
			v = req
		} else {
			v = &http.Response{
				Status: "200 OK",
				StatusCode: 200,
				Proto: "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					"Cache-Control": []string {
						test.CacheControl,
					},
				},
			}
		}
		cc, err := CacheControl(v)
		assert.NoError(t, err)
		assert.Equal(t, test.Cachable, cc.Cacheable())
	}
}

func TestFreshness(t *testing.T) {

	tests := []struct {
		Headers http.Header
		ExpectedFreshnessLifetime time.Duration
	} {
		{
			Headers: http.Header{
				"Cache-Control": []string { "max-age=10" },
			},
			ExpectedFreshnessLifetime: 10*time.Second,
		},
	}

	for _, test := range tests {
		rsp := &http.Response{
			Status: "200 OK",
			StatusCode: 200,
			Proto: "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: test.Headers,
		}
		d, err := FreshnessLifetime(rsp, time.Now().UTC())
		assert.NoError(t, err)
		assert.Equal(t, test.ExpectedFreshnessLifetime, d)
	}

}
