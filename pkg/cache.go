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
	"path/filepath"
	"os"
	"bufio"
	"encoding/base64"
)

var (
	ErrCacheMiss = errors.New("cache miss")
)

type CacheStorage interface {
	Get(string) (*http.Response, time.Time, time.Time, error)
	Put(string, *http.Request, *http.Response, time.Time) error
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

func (s *inmemoryCacheStorage) Put(id string, req *http.Request, rsp *http.Response, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

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

type Dir string
func (s Dir) path(id string) string {
	return filepath.Join(string(s), base64.StdEncoding.EncodeToString([]byte(id)))
}
func (s Dir) Get(id string) (*http.Response, time.Time, time.Time, error) {
	f, err := os.Open(s.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, time.Time{}, ErrCacheMiss
		}
		return nil, time.Time{}, time.Time{}, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	expiresBytes := make([]byte, 15)
	_, err = reader.Read(expiresBytes)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	expires := time.Time{}
	err = expires.UnmarshalBinary(expiresBytes)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	requestData, err := reader.ReadBytes(0)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestData)))
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}

	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	stat, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	at := stat.ModTime()
	return resp, at, expires, nil
}

func (s Dir) Put(id string, req *http.Request, rsp *http.Response, expires time.Time) error {
	f, err := os.OpenFile(s.path(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	expiresBytes, err := expires.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = f.Write(expiresBytes)
	if err != nil {
		return err
	}
	err = req.Write(f)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte{0})
	if err != nil {
		return err
	}
	return rsp.Write(f)
}

func (s Dir) Delete(id string) {
	path := filepath.Join(string(s), base64.StdEncoding.EncodeToString([]byte(id)))
	os.Remove(path)
}

type Cache struct {
	mu sync.Mutex
	Storage CacheStorage
}

func (c *Cache) id(req *http.Request) string {
	return fmt.Sprintf("%s:%s", req.Method, req.URL.Path)
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

func (c *Cache) IsCacheable(rsp *http.Response, req *http.Request) bool {
	reasons, expires, err := cachecontrol.CachableResponse(req, rsp, cachecontrol.Options{})
	if err != nil {
		return false
	}

	if len(reasons) > 0 {
		return false
	}
	if expires.IsZero() {
		return false
	}
	return true
}

func (c *Cache) Accept(req *http.Request, rsp *http.Response) (time.Time, error) {
	c.init()

	reasons, expires, err := cachecontrol.CachableResponse(req, rsp, cachecontrol.Options{})
	if err != nil {
		return time.Time{}, err
	}

	if len(reasons) > 0 {
		logrus.Debugf("No caching because of: %s", reasons)
		return time.Time{}, nil
	}
	if expires.IsZero() {
		// TODO: Use heuristic to make a choice
		logrus.Debugf("No expiration date")
		return time.Time{}, nil
	}

	return expires, c.Storage.Put(c.id(req), req, rsp, expires)
}


