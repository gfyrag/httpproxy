package httpproxy

import (
	"testing"
	"net/http"
	"bytes"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
)

func TestDir(t *testing.T) {
	req, err := http.NewRequest("GET", "http://127.0.0.1", ioutil.NopCloser(bytes.NewBufferString("foo")))
	assert.NoError(t, err)

	rsp := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("bar")),
		Status: "200 OK",
		StatusCode: 200,
		Proto: "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Cache-Control": []string {
				"max-age=10",
			},
			"Transfer-Encoding": []string {
				"chunked",
			},
		},
		ContentLength: 0,
		TransferEncoding: nil,
		Request: req,
	}

	d := Cache{
		Storage: Dir("/tmp"),
	}
	tx := d.Tx(req)

	_, err = tx.Prepare(rsp)
	assert.NoError(t, err)

	err = tx.WriteResponse(rsp)
	assert.NoError(t, err)

	_, err = tx.ReadMetadata()
	assert.NoError(t, err)

	rsp, err = tx.ReadResponse()
	assert.NoError(t, err)

	data, err := ioutil.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "bar", string(data))
}
