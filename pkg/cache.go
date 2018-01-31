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
)

var (
	ErrCacheMiss = errors.New("cache miss")
)

type CacheStorage interface {
	Get(string) (*http.Response, error)
	Put(string, *http.Response) error
}

type inmemoryCacheStorage struct {
	mu sync.Mutex
	responses map[string]*http.Response
}

func (s *inmemoryCacheStorage) init() {
	if s.responses == nil {
		s.responses = make(map[string]*http.Response)
	}
}

func (s *inmemoryCacheStorage) Get(id string) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	rsp, ok := s.responses[id]
	if !ok {
		return nil, ErrCacheMiss
	}
	return rsp, nil
}

func (s *inmemoryCacheStorage) Put(id string, rsp *http.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.responses[id] = rsp
	return nil
}

type Cache struct {
	mu sync.Mutex
	Storage CacheStorage
}

func (c *Cache) id(req *http.Request) string {
	return fmt.Sprintf("%s:%s", req.Method, req.URL.String())
}

func (c *Cache) init() {
	if c.Storage == nil {
		c.Storage = &inmemoryCacheStorage{}
	}
}

func (c *Cache) Request(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	return c.Storage.Get(c.id(req))
}

func (c *Cache) Accept(req *http.Request, rsp *http.Response) error {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	return c.Storage.Put(c.id(req), rsp)
}


