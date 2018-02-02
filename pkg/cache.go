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
	"github.com/docker/go/canonical/json"
)

var (
	ErrCacheMiss = errors.New("cache miss")
)

type CacheMetadata struct {
	Date time.Time `json:"date"`
	Expires time.Time `json:"expires"`
}

type CacheStorage interface {
	Get(string) (*http.Response, CacheMetadata, error)
	Put(string, *http.Request, *http.Response, CacheMetadata) error
	Delete(string)
}

type cacheEntry struct {
	rsp     *http.Response
	data    []byte
	meta CacheMetadata
}

type inmemoryCacheStorage struct {
	mu        sync.Mutex
	responses map[string]cacheEntry
}

func (s *inmemoryCacheStorage) init() {
	if s.responses == nil {
		s.responses = make(map[string]cacheEntry)
	}
}

func (s *inmemoryCacheStorage) Get(id string) (*http.Response, CacheMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	entry, ok := s.responses[id]
	if !ok {
		return nil, CacheMetadata{}, ErrCacheMiss
	}
	entry.rsp.Body = ioutil.NopCloser(bytes.NewBuffer(entry.data))
	return entry.rsp, entry.meta, nil
}

func (s *inmemoryCacheStorage) Put(id string, req *http.Request, rsp *http.Response, meta CacheMetadata) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()

	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

	s.responses[id] = cacheEntry{
		rsp:     rsp,
		meta: meta,
		data:    data,
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
	p := ""
	for i := 0 ; i < len(id); i += 4 {
		p = filepath.Join(p, id[i:i+4])
	}
	return filepath.Join(string(s), p)
}
func (s Dir) request(id string) string {
	return filepath.Join(s.path(id), "req")
}
func (s Dir) response(id string) string {
	return filepath.Join(s.path(id), "res")
}
func (s Dir) meta(id string) string {
	return filepath.Join(s.path(id), "meta")
}
func (s Dir) Get(id string) (*http.Response, CacheMetadata, error) {
	requestFile, err := os.Open(s.request(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, CacheMetadata{}, ErrCacheMiss
		}
		return nil, CacheMetadata{}, err
	}
	req, err := http.ReadRequest(bufio.NewReader(requestFile))
	if err != nil {
		return nil, CacheMetadata{}, err
	}

	responseFile, err := os.Open(s.response(id))
	if err != nil {
		panic(err)
	}
	rsp, err := http.ReadResponse(bufio.NewReader(responseFile), req)
	if err != nil {
		return nil, CacheMetadata{}, err
	}

	metaFile, err := os.Open(s.meta(id))
	if err != nil {
		panic(err)
	}
	meta := CacheMetadata{}
	err = json.NewDecoder(bufio.NewReader(metaFile)).Decode(&meta)
	if err != nil {
		return nil, CacheMetadata{}, err
	}

	return rsp, meta, nil
}

func (s Dir) Put(id string, req *http.Request, rsp *http.Response, meta CacheMetadata) error {

	path := s.path(id)
	err := os.MkdirAll(path, 0777)
	if err != nil {
		return err
	}

	requestFile, err := os.OpenFile(s.request(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer requestFile.Close()
	err = req.Write(requestFile)
	if err != nil {
		return err
	}

	responseFile, err := os.OpenFile(s.response(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer responseFile.Close()
	err = rsp.Write(responseFile)
	if err != nil {
		return err
	}

	metaFile, err := os.OpenFile(s.meta(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer metaFile.Close()
	err = json.NewEncoder(metaFile).Encode(meta)
	if err != nil {
		return err
	}
	return nil
}

func (s Dir) Delete(id string) {
	path := filepath.Join(string(s), base64.StdEncoding.EncodeToString([]byte(id)))
	os.Remove(path)
}

type Cache struct {
	mu      sync.Mutex
	Storage CacheStorage
}

func (c *Cache) id(req *http.Request) string {
	return base64.StdEncoding.EncodeToString(
		[]byte(fmt.Sprintf("%s:%s:%s:%s", req.URL.Scheme, req.URL.Host, req.Method, req.URL.Path)),
	)
}

func (c *Cache) init() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Storage == nil {
		c.Storage = &inmemoryCacheStorage{}
	}
}

func (c *Cache) Request(req *http.Request) (*http.Response, CacheMetadata, error) {
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

func (c *Cache) Accept(req *http.Request, rsp *http.Response) (CacheMetadata, error) {
	c.init()

	reasons, expires, err := cachecontrol.CachableResponse(req, rsp, cachecontrol.Options{})
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

	return meta, c.Storage.Put(c.id(req), req, rsp, meta)
}
