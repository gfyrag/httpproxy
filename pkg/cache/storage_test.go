package cache

import (
	"testing"
	"net/http/httptest"
	"net/http"
	"time"
	"github.com/stretchr/testify/assert"
	"bytes"
	"io/ioutil"
)

func TestStorage(t *testing.T) {
	req := httptest.NewRequest("GET", "http://127.0.0.1", nil)
	rsp := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
	}
	now := time.Now().UTC()
	recipe := &Recipe{
		Request: req,
		Response: rsp,
		RequestDate: now,
		ResponseDate: now,
	}

	s := MemStorage()

	recipes, err := s.List(PrimaryKey(req))
	assert.NoError(t, err)
	assert.Len(t, recipes, 0)

	assert.NoError(t, s.Insert(PrimaryKey(req), recipe))

	recipes, err = s.List(PrimaryKey(req))
	assert.NoError(t, err)
	assert.Len(t, recipes, 1)

	assert.Equal(t, recipe.ResponseDate, recipes[0].ResponseDate)
	assert.Equal(t, recipe.RequestDate, recipes[0].RequestDate)
	data, _ := ioutil.ReadAll(recipes[0].Response.Body)
	assert.Equal(t, "foo", string(data))

	assert.NoError(t, s.Delete(PrimaryKey(req), recipe))
	recipes, err = s.List(PrimaryKey(req))
	assert.NoError(t, err)
	assert.Len(t, recipes, 0)
}
