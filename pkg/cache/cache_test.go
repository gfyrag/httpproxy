package cache

import (
	"testing"
	"net/http"
	"github.com/stretchr/testify/assert"
	"io"
	"bufio"
	"net/http/httptest"
	"time"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"fmt"
	"bytes"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func TestCache(t *testing.T) {

	type Request struct {
		Header http.Header
	}

	type Response struct {
		ExpectHeader http.Header
		StatusCode   int
		Header       http.Header
	}

	type FinalResponse struct {
		StatusCode   int
		Header       http.Header
		ExpectHeader []string
	}

	suites := [][]struct {
		Response Response
		Request Request
		FinalResponse FinalResponse
	} {
		// Cache should handle request and cache the response
		{
			{
				Response: Response{
					Header: http.Header{
						"Cache-Control": []string { "max-age=10" },
					},
				},
			},
		},
		// Cache should handle request and cache the response
		{
			{
				Response: Response{
					Header: http.Header{
						"Cache-Control": []string { "max-age=10" },
						"Date": []string { time.Now().UTC().Format(http.TimeFormat) },
					},
				},
			},
		},
		// Cache should handle request and cache the response even if expires in the past
		// A subsequent request should revalidate
		{
			{
				Response: Response{
					Header: http.Header{
						"Expires": []string { time.Now().UTC().Add(10*time.Second).Format(http.TimeFormat) },
					},
				},
			},
		},
		{
			// Cache should handle request and cache the response even if expires in the past
			{
				Response: Response{
					Header: http.Header{
						"Expires": []string { time.Now().UTC().Add(-10*time.Second).Format(http.TimeFormat) },
						"Last-Modified": []string { http.TimeFormat },
					},
				},
			},
			// Client performing a condition request, cache should reply with a 304
			{
				Response: Response{
					// Should not hit the backend since the response is in cache
					StatusCode: http.StatusInternalServerError,
				},
				Request: Request{
					Header: http.Header{
						"If-Modified-Since": []string { http.TimeFormat },
					},
				},
				FinalResponse: FinalResponse{
					// Finally, the cache should respond with a 304
					StatusCode: http.StatusNotModified,
				},
			},
		},
		{
			// Cache should handle request and cache the response even if expires in the past
			{
				Response: Response{
					Header: http.Header{
						"Expires": []string { time.Now().UTC().Add(-10*time.Second).Format(http.TimeFormat) },
						"Etag": []string { "0000" },
					},
				},
			},
			// The cache should generate a conditional request with If-None-Match condition
			{
				Response: Response{
					StatusCode: http.StatusNotModified,
					ExpectHeader: http.Header{
						"If-None-Match": []string { "0000" },
					},
				},
			},
		},
		{
			{
				Response: Response{
					Header: http.Header{
						"Expires": []string { time.Now().UTC().Add(-10*time.Second).Format(http.TimeFormat) },
						"Etag": []string { "0000" },
					},
				},
			},
			// Client performing a condition request, cache should reply with a 304
			{
				Response: Response{
					StatusCode: http.StatusNotModified,
				},
				Request: Request{
					Header: http.Header{
						"If-None-Match": []string { "0000" },
					},
				},
				FinalResponse: FinalResponse{
					StatusCode: http.StatusNotModified,
				},
			},
		},
		{
			{
				Response: Response{
					Header: http.Header{
						"Cache-Control": []string { "max-age=10" },
					},
				},
			},
			{
				Response: Response{
					Header: http.Header{
						"Cache-Control": []string { "max-age=10" },
					},
				},
				FinalResponse: FinalResponse{
					StatusCode: http.StatusOK,
					ExpectHeader: []string { "Age" },
				},
			},
		},
		{
			{},
		},
	}

	for i, suite := range suites {

		storage := MemStorage()
		c := New(WithStorage(storage))

		for j, test := range suite {
			t.Run(fmt.Sprintf("%d/%d", i, j), func(t *testing.T) {
				doer := DoerFn(func(r *http.Request) (*http.Response, error) {
					rsp := &http.Response{
						Header: http.Header{
							"Date": []string { time.Now().UTC().Format(http.TimeFormat) },
						},
						StatusCode: 200,
						Body: ioutil.NopCloser(bytes.NewBufferString("")),
					}
					for k, hh := range test.Response.ExpectHeader {
						if r.Header.Get(k) != hh[0] {
							rsp.StatusCode = http.StatusPreconditionFailed
							return rsp, nil
						}
					}
					for k, hh := range test.Response.Header {
						for _, h := range hh {
							rsp.Header.Add(k, h)
						}
					}
					if test.Response.StatusCode != 0 {
						rsp.StatusCode = test.Response.StatusCode
					}
					return rsp, nil
				})
				req, err := http.NewRequest("GET", "http://127.0.0.1", nil)
				assert.NoError(t, err)
				if test.Request.Header != nil {
					req.Header = test.Request.Header
				}

				r, w := io.Pipe()
				go func() {
					defer w.Close()
					assert.NoError(t, c.Serve(w, doer, req))
				}()
				rsp, err := http.ReadResponse(bufio.NewReader(r), req)
				assert.NoError(t, err)
				if rsp != nil && rsp.Body != nil {
					io.Copy(ioutil.Discard, rsp.Body)
				}

				if err == nil {
					if test.FinalResponse.StatusCode == 0 {
						assert.Equal(t, http.StatusOK, rsp.StatusCode)
					} else {
						assert.Equal(t, test.FinalResponse.StatusCode, rsp.StatusCode)
					}
					for k, v := range test.FinalResponse.Header {
						assert.Equal(t, v, rsp.Header[k])
					}
					for _, k := range test.FinalResponse.ExpectHeader {
						assert.NotEmpty(t, rsp.Header.Get(k))
					}
				}
			})
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	storage := MemStorage()
	c := New(WithStorage(storage))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			panic("expected flushed")
		}
		w.Header().Set("Cache-Control", "max-age=10")
		w.WriteHeader(200)
		for i := 0 ; i < 5 ; i++ {
			_, err := w.Write([]byte("foo"))
			assert.NoError(t, err)
			f.Flush()
			<-time.After(100*time.Millisecond)
		}
	}))

	req, err := http.NewRequest("GET", srv.URL, nil)
	assert.NoError(t, err)
	r, w := io.Pipe()
	go func(w *io.PipeWriter) {
		defer w.Close()
		assert.NoError(t, c.Serve(w, srv.Client(), req))
	}(w)

	<-time.After(100*time.Millisecond)

	go io.Copy(ioutil.Discard, r)

	req, err = http.NewRequest("GET", srv.URL, nil)
	assert.NoError(t, err)
	r, w = io.Pipe()
	go func(w *io.PipeWriter) {
		defer w.Close()
		assert.NoError(t, c.Serve(w, srv.Client(), req))
	}(w)

	rsp, err := http.ReadResponse(bufio.NewReader(r), req)
	assert.NoError(t, err)

	data , err := ioutil.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "foofoofoofoofoo", string(data))

}