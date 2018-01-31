//
// https://tools.ietf.org/html/rfc7234
//
package httpproxy

import (
	"net/http"
	"errors"
	"sync"
	"github.com/pquerna/cachecontrol"
	"github.com/Sirupsen/logrus"
	"fmt"
	"time"
	"io/ioutil"
	"bytes"
)

var (
	ErrCacheMiss = errors.New("cache miss")
)

type CacheStorage interface {
	Get(string) (*http.Response, time.Time, time.Time, error)
	Put(string, *http.Response, time.Time) error
	Delete(string)
}

type cacheEntry struct {
	rsp *http.Response
	at  time.Time
	expires time.Time
	data []byte
}

type inmemoryCacheStorage struct {
	mu sync.Mutex
	responses map[string]cacheEntry
}

func (s *inmemoryCacheStorage) init() {
	if s.responses == nil {
		s.responses = make(map[string]cacheEntry)
	}
}

func (s *inmemoryCacheStorage) Get(id string) (*http.Response, time.Time, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	entry, ok := s.responses[id]
	if !ok {
		return nil, time.Time{}, time.Time{}, ErrCacheMiss
	}
	entry.rsp.Body = ioutil.NopCloser(bytes.NewBuffer(entry.data))
	return entry.rsp, entry.at, entry.expires, nil
}

func (s *inmemoryCacheStorage) Put(id string, rsp *http.Response, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}
	rsp.Body.Close()
	rsp.Body = ioutil.NopCloser(bytes.NewBuffer(data))

	s.responses[id] = cacheEntry{
		rsp: rsp,
		at: time.Now(),
		expires: expires,
		data: data,
	}
	return nil
}

func (s *inmemoryCacheStorage) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	delete(s.responses, id)
}

type Cache struct {
	mu sync.Mutex
	Storage CacheStorage
}

func (c *Cache) id(req *http.Request) string {
	return fmt.Sprintf("%s:%s", req.Method, req.URL.String())
}

func (c *Cache) init() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Storage == nil {
		c.Storage = &inmemoryCacheStorage{}
	}
}

func (c *Cache) Request(req *http.Request) (*http.Response, time.Time, time.Time, error) {
	c.init()
	return c.Storage.Get(c.id(req))
}

func (c *Cache) Evict(req *http.Request) {
	c.init()
	c.Storage.Delete(c.id(req))
}

func (c *Cache) Accept(req *http.Request, rsp *http.Response) error {
	c.init()

	reasons, date, err := cachecontrol.CachableResponse(req, rsp, cachecontrol.Options{})
	if err != nil {
		return err
	}

	if len(reasons) > 0 {
		logrus.Debugf("No caching because of: %s", reasons)
		return nil
	}
	if date.IsZero() {
		// TODO: Use heuristic to make a choice
		logrus.Debugf("No expiration date")
		return nil
	}
	return c.Storage.Put(c.id(req), rsp, date)
}


