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

func TestVary(t *testing.T) {
	req1 := httptest.NewRequest("GET", "http://127.0.0.1", nil)
	req1.Header.Set("Accept", "text/html")
	rsp1 := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
		Header: http.Header{
			"Vary": []string{"Accept" },
		},
	}

	req2 := httptest.NewRequest("GET", "http://127.0.0.1", nil)
	req2.Header.Set("Accept", "application/json")
	rsp2 := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
		Header: http.Header{
			"Vary": []string{"Accept" },
		},
	}
	now := time.Now().UTC()

	s := MemStorage()

	assert.NoError(t, s.Insert(PrimaryKey(req1), &Recipe{
		Request: req1,
		Response: rsp1,
		RequestDate: now,
		ResponseDate: now,
	}))
	assert.NoError(t, s.Insert(PrimaryKey(req2), &Recipe{
		Request: req2,
		Response: rsp2,
		RequestDate: now,
		ResponseDate: now,
	}))

	recipes, err := s.List(PrimaryKey(req2))
	assert.NoError(t, err)
	assert.Len(t, recipes, 2)
}

func TestMatchRecipe(t *testing.T) {

	req1 := httptest.NewRequest("GET", "http://127.0.0.1", nil)
	req1.Header.Set("Accept", "text/html")
	rsp1 := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
		Header: http.Header{
			"Vary": []string{"Accept" },
		},
	}

	req2 := httptest.NewRequest("GET", "http://127.0.0.1", nil)
	req2.Header.Set("Accept", "application/json")
	rsp2 := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBufferString("foo")),
		Header: http.Header{
			"Vary": []string{"Accept" },
		},
	}
	now := time.Now().UTC()

	r1 := &Recipe{
		Request: req1,
		Response: rsp1,
		RequestDate: now,
		ResponseDate: now,
	}
	assert.True(t, r1.MatchRequest(req1))
	assert.False(t, r1.MatchRequest(req2))
	r2 := &Recipe{
		Request: req2,
		Response: rsp2,
		RequestDate: now,
		ResponseDate: now,
	}
	assert.True(t, r2.MatchRequest(req2))
	assert.False(t, r2.MatchRequest(req1))
}

