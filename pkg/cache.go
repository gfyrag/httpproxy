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
	"bytes"
	"path/filepath"
	"os"
	"bufio"
	"encoding/base64"
	"github.com/docker/go/canonical/json"
)

var (
	ErrCacheMiss = errors.New("cache miss")
	ErrNotCachable = errors.New("response not cachable")
)

type CacheMetadata struct {
	Date time.Time `json:"date"`
	Expires time.Time `json:"expires"`
}

func (m CacheMetadata) Expired() bool {
	return time.Now().After(m.Expires)
}

type CacheStorage interface {
	DeleteEntry(string)
	ReadResponse(string, *http.Request) (*http.Response, error)
	WriteResponse(string, *http.Response) error
	ReadMetadata(string, *http.Request) (CacheMetadata, error)
	Prepare(string, CacheMetadata) error
}

type cacheEntry struct {
	buf *bytes.Buffer
	meta CacheMetadata
}

type inmemoryCacheStorage struct {
	mu        sync.Mutex
	responses map[string]*cacheEntry
}

func (s *inmemoryCacheStorage) init() {
	if s.responses == nil {
		s.responses = make(map[string]*cacheEntry)
	}
}

func (s *inmemoryCacheStorage) ReadResponse(id string, req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	entry, ok := s.responses[id]
	if !ok {
		return nil, ErrCacheMiss
	}

	return http.ReadResponse(bufio.NewReader(bytes.NewBuffer(entry.buf.Bytes())), req)
}

func (s *inmemoryCacheStorage) ReadMetadata(id string, req *http.Request) (CacheMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	entry, ok := s.responses[id]
	if !ok {
		return CacheMetadata{}, ErrCacheMiss
	}
	return entry.meta, nil
}

func (s *inmemoryCacheStorage) WriteResponse(id string, rsp *http.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	entry, ok := s.responses[id]
	if !ok {
		panic("not prepared")
	}
	entry.buf.Reset()

	return rsp.Write(entry.buf)
}

func (s *inmemoryCacheStorage) Prepare(id string, meta CacheMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	entry, ok := s.responses[id]
	if !ok {
		entry = &cacheEntry{
			buf: bytes.NewBuffer(make([]byte, 0)),
		}
		s.responses[id] = entry
	}
	entry.meta = meta
	return nil
}

func (s *inmemoryCacheStorage) DeleteEntry(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	delete(s.responses, id)
}

type Dir string

func (s Dir) path(id string) string {
	p := ""
	for i := 0 ; i < len(id); i += 4 {
		p = filepath.Join(p, id[i:i+4])
	}
	return filepath.Join(string(s), p)
}
func (s Dir) response(id string) string {
	return filepath.Join(s.path(id), "res")
}
func (s Dir) meta(id string) string {
	return filepath.Join(s.path(id), "meta")
}

func (s Dir) ReadMetadata(id string, req *http.Request) (CacheMetadata, error) {

	metaFile, err := os.Open(s.meta(id))
	if err != nil {
		if os.IsNotExist(err) {
			return CacheMetadata{}, ErrCacheMiss
		}
	}
	meta := CacheMetadata{}
	err = json.NewDecoder(bufio.NewReader(metaFile)).Decode(&meta)
	if err != nil {
		return CacheMetadata{}, err
	}

	return meta, nil
}

func (s Dir) ReadResponse(id string, req *http.Request) (*http.Response, error) {
	responseFile, err := os.Open(s.response(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCacheMiss
		}
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(responseFile), req)
}

func (s Dir) WriteResponse(id string, rsp *http.Response) error {
	responseFile, err := os.OpenFile(s.response(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer responseFile.Close()
	return rsp.Write(responseFile)
}

func (s Dir) Prepare(id string, meta CacheMetadata) error {
	path := s.path(id)
	err := os.MkdirAll(path, 0777)
	if err != nil {
		return err
	}

	f, err := os.Create(s.response(id))
	if err != nil {
		return err
	}
	f.Close()

	metaFile, err := os.OpenFile(s.meta(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer metaFile.Close()

	return json.NewEncoder(metaFile).Encode(meta)
}

func (s Dir) DeleteEntry(id string) {
	os.RemoveAll(s.path(id))
}

type cacheTransaction struct {
	mu    *sync.Mutex
	id    string
	cache *Cache
	req *http.Request
}

func (c *cacheTransaction) Start() {
	c.mu.Lock()
}

func (c *cacheTransaction) Release() {
	c.mu.Unlock()
}

func (c *cacheTransaction) Evict() {
	c.cache.Storage.DeleteEntry(c.id)
}

func (c *cacheTransaction) IsCacheable(rsp *http.Response) bool {
	reasons, expires, err := cachecontrol.CachableResponse(c.req, rsp, cachecontrol.Options{})
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

func (c *cacheTransaction) ReadMetadata() (CacheMetadata, error) {
	return c.cache.Storage.ReadMetadata(c.id, c.req)
}

func (c *cacheTransaction) ReadResponse() (*http.Response, error) {
	return c.cache.Storage.ReadResponse(c.id, c.req)
}

func (c *cacheTransaction) WriteResponse(rsp *http.Response) error {
	return c.cache.Storage.WriteResponse(c.id, rsp)
}

func (c *cacheTransaction) Prepare(rsp *http.Response) (CacheMetadata, error) {
	reasons, expires, err := cachecontrol.CachableResponse(c.req, rsp, cachecontrol.Options{})
	if err != nil {
		return CacheMetadata{}, err
	}

	if len(reasons) > 0 {
		logrus.Debugf("No caching because of: %s", reasons)
		return CacheMetadata{}, err
	}
	if expires.IsZero() {
		return CacheMetadata{}, err
	}

	meta := CacheMetadata{
		Date: time.Now(),
		Expires: expires,
	}

	return meta, c.cache.Storage.Prepare(c.id, meta)
}

type Cache struct {
	mu      sync.Mutex
	Storage CacheStorage
	mutexes map[string]*sync.Mutex
}

func (c *Cache) Tx(req *http.Request) *cacheTransaction {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mutexes == nil {
		c.mutexes = make(map[string]*sync.Mutex)
	}
	if c.Storage == nil {
		c.Storage = &inmemoryCacheStorage{}
	}
	id := base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s:%s:%s", req.URL.Scheme, req.URL.Host, req.Method, req.URL.Path)),
	)
	if _, ok := c.mutexes[id]; !ok {
		c.mutexes[id] = &sync.Mutex{}
	}
	return &cacheTransaction{
		mu: c.mutexes[id],
		id: id,
		req: req,
		cache: c,
	}

}

