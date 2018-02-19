package cache

import (
	"net/http"
	"fmt"
	"time"
	"io"
	"sync"
	"io/ioutil"
	"errors"
	"strings"
)

var (
	ErrValidationFailed = errors.New("validation failed")
)

func PrimaryKey(r *http.Request) string {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		if strings.HasSuffix(host, ":443") {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s:%s:%s:%s?%s", r.Method, scheme, host, r.URL.EscapedPath(), r.URL.RawQuery)
}

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}
type DoerFn func(*http.Request) (*http.Response, error)
func (fn DoerFn) Do(r *http.Request) (*http.Response, error) {
	return fn(r)
}

type Cache struct {
	storage    Storage
	validators Validators
	mu *sync.Mutex
	requestsMu map[string]*sync.Mutex
	observer Observer
}

func (c *Cache) Storage() Storage {
	return c.storage
}

func (c *Cache) lock(req *http.Request) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requestsMu == nil {
		c.requestsMu = make(map[string]*sync.Mutex)
	}
	key := PrimaryKey(req)
	mu, ok := c.requestsMu[key]
	if !ok {
		mu = &sync.Mutex{}
		c.requestsMu[key] = mu
	}
	return mu
}

func (c *Cache) selectCacheEntry(r *http.Request) (*Recipe, error) {
	entries, err := c.storage.List(PrimaryKey(r))
	if err != nil {
		return nil, err
	}
	for i, entry := range entries {
		if entry.MatchRequest(r) {
			if i < len(entries)-1 {
				for _, remainingEntry := range entries[i+1:] {
					remainingEntry.Close()
				}
			}
			return entry, nil
		}
		entry.Close()
	}
	return nil, nil
}

// See RFC7234 section 4.3
func (c *Cache) validationRequest(w io.Writer, cl Doer, recipe *Recipe) (*http.Response, error) {
	valid := new(http.Request)
	*valid = *recipe.Request
	for _, v := range c.validators {
		v.Process(recipe.Response, valid)
	}
	//now := time.Now()
	rsp, err := cl.Do(valid)
	if err != nil {
		return nil, err
	}
	// See RFC7234 section 4.3.3
	if rsp.StatusCode > 500 {
		return nil, ErrValidationFailed
	}
	if rsp.StatusCode == http.StatusNotModified {
		c.observer.Observe(Revalidated(valid))
		// Update stored response
		// See section 4.3.4
		recipe.Response.Header = rsp.Header
		rsp = recipe.Response
	}

	// TODO: See RFC7234 section 4.3.3 for removing warning Header
	return rsp, nil
}

// Return a cached response if found a non expired recipe
// Perform validation request if found an expired request
// See RFC7234 section 4
// TODO: Serve stale responses (See RFC7234 section 4.2.4)
func (c *Cache) Serve(w io.Writer, doer Doer, req *http.Request) error {

	stripHopByHopHeaders(req)

	var (
		rsp *http.Response
		err error
	)
	defer func() {
		if rsp != nil && rsp.Body != nil {
			rsp.Body.Close()
		}
	}()

	err = PermitCache(req)
	if err != nil {
		c.observer.Observe(NoCachableRequest(req, err))
		rsp, err = doer.Do(req)
		if err != nil {
			return err
		}
	} else {
		l := c.lock(req)
		l.Lock()
		defer l.Unlock()
		c.observer.Observe(Lock(req))

		noCacheOnRequest, err := NoCache(req)
		if err != nil {
			return err
		}

		recipe, err := c.selectCacheEntry(req)
		if err != nil {
			return err
		}
		if recipe == nil {
			c.observer.Observe(CacheMiss(req))
		} else {
			c.observer.Observe(CacheHit(req))
		}

		now := time.Now().UTC()

		if IsConditionalRequest(req) {
			if recipe != nil {
				if c.validators.Validate(recipe) {
					rsp = recipe.Response
					if rsp.Body != nil {
						rsp.Body.Close()
						rsp.Body = nil
					}
					recipe.Response.StatusCode = http.StatusNotModified
					c.observer.Observe(RevalidatedFromCache(req))
				} else {
					c.observer.Observe(RevalidatedFromCacheFailed(req))
				}
			}
		} else if recipe != nil {
			if noCacheOnRequest {
				// the request contain the no-cache cache directive
				// (Section 5.2.2.2), we have to revalidate
				rsp, err = c.validationRequest(w, doer, recipe)
			} else {
				// the stored response contain the no-cache cache directive
				// (Section 5.2.2.2), we have to revalidate
				noCacheOnResponse, err := NoCache(recipe.Response)
				if err == nil {
					if noCacheOnResponse || Expired(recipe.Response, now) {
						rsp, err = c.validationRequest(w, doer, recipe)
					} else {
						rsp = recipe.Response
						rsp.Header.Set("Age", fmt.Sprintf("%d", int64(Age(rsp, recipe.RequestDate, recipe.ResponseDate).Seconds())))
						c.observer.Observe(ServedFromCache(req))
					}
				}
			}
		}
		if err != nil {
			return err
		}

		if rsp == nil {
			rsp, err = doer.Do(req)
			if err != nil {
				return err
			}
		}

		if recipe == nil || rsp != recipe.Response {
			// Close the recipe since we have a new response to forward and possibly caching
			if recipe != nil {
				recipe.Close()
			}

			permitCache := PermitCache(rsp)
			if permitCache == nil {
				wg := sync.WaitGroup{}
				wg.Add(1)
				defer wg.Wait()

				c.observer.Observe(CachingResponse(req))
				stripHopByHopHeaders(rsp)
				var w *io.PipeWriter
				rspCp := new(http.Response)
				*rspCp = *rsp
				rspCp.Body, w = io.Pipe()
				rsp.Body = ioutil.NopCloser(io.TeeReader(rsp.Body, w))
				defer w.Close()

				go func() {
					defer wg.Done()
					err = c.storage.Insert(PrimaryKey(req), &Recipe{
						Request: req,
						Response: rspCp,
						RequestDate: now,
						ResponseDate: now,
					})
					if err != nil {
						c.observer.Observe(CachingResponseError(req, err))
						io.Copy(ioutil.Discard, rspCp.Body)
					}
				}()
			} else {
				c.observer.Observe(NoCachableResponse(req, permitCache))
			}
		}

		// Per RFC7231 section 7.1.1.2, the 'Date' header is not absolutely mandatory
		if Date(rsp).IsZero() {
			rsp.Header.Set("Date", now.Format(http.TimeFormat))
		}
	}

	c.observer.Observe(Respond(req, rsp))

	return rsp.Write(w)
}

func (c *Cache) WithOptions(opts ...cacheOption) *Cache {
	cp := new(Cache)
	*cp = *c
	for _, o := range opts {
		o.apply(cp)
	}
	return cp
}

type cacheOption interface {
	apply(*Cache)
}
type cacheOptionFn func(*Cache)
func (fn cacheOptionFn) apply(c *Cache) {
	fn(c)
}

func WithValidators(validators ...Validator) cacheOptionFn {
	return func(c *Cache) {
		c.validators = append(c.validators, validators...)
	}
}

func WithStorage(storage Storage) cacheOptionFn {
	return func(c *Cache) {
		c.storage = storage
	}
}

func WithObserver(observer Observer) cacheOptionFn {
	return func(c *Cache) {
		c.observer = observer
	}
}

var (
	DefaultOptions = []cacheOption{
		WithValidators(ifModifiedSince{}, ifNoneMatch{}),
		WithStorage(MemStorage()),
		WithObserver(NoOpObserver),
	}
)

func New(opts ...cacheOption) *Cache {
	return (&Cache{
		mu: &sync.Mutex{},
		requestsMu: make(map[string]*sync.Mutex),
	}).WithOptions(append(DefaultOptions, opts...)...)
}
