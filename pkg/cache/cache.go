package cache

import (
	"net/http"
	"fmt"
	"time"
	"io"
	"sync"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	"errors"
)

var (
	ErrValidationFailed = errors.New("validation failed")
)

func PrimaryKey(r *http.Request) string {
	strippedUrl := *r.URL
	strippedUrl.RawQuery = ""
	return fmt.Sprintf("%s:%s", r.Method, strippedUrl.String())
	//return base64.StdEncoding.EncodeToString([]byte(primaryKey))
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
	logger Logger
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

	c.logger.Debugf("serve request")
	defer func() {
		c.logger.Debugf("request finished")
	}()

	err := PermitCache(req)
	if err != nil {
		c.logger.Debugf("request does not allow cache: %s", err)
		return err
	}

	l := c.lock(req)
	l.Lock()
	defer l.Unlock()

	noCacheOnRequest, err := NoCache(req)
	if err != nil {
		return err
	}

	recipe, err := c.selectCacheEntry(req)
	if err != nil {
		return err
	}

	var rsp *http.Response
	defer func() {
		if rsp != nil && rsp.Body != nil {
			rsp.Body.Close()
		}
	}()

	now := time.Now().UTC()

	if IsConditionalRequest(req) {

		if recipe == nil {
			c.logger.Debugf("forward conditional request as we have no matching recipe")
		} else {
			if c.validators.Validate(recipe) {
				c.logger.Debugf("conditional request validated")
				rsp = recipe.Response
				if rsp.Body != nil {
					rsp.Body.Close()
					rsp.Body = nil
				}
				recipe.Response.StatusCode = http.StatusNotModified
			} else {
				c.logger.Debugf("conditional request failed")
			}
		}
	} else if recipe != nil {
		if noCacheOnRequest {
			c.logger.Debugf("request queried no-cache")
			// the request contain the no-cache cache directive
			// (Section 5.2.2.2), we have to revalidate
			rsp, err = c.validationRequest(w, doer, recipe)
		} else {
			// the stored response contain the no-cache cache directive
			// (Section 5.2.2.2), we have to revalidate
			noCacheOnResponse, err := NoCache(recipe.Response)
			if err == nil {
				if noCacheOnResponse {
					c.logger.Debugf("response specified no-cache")
				}
				expired := Expired(recipe.Response, now)
				if expired {
					c.logger.Debugf("response expired")
				}
				if noCacheOnResponse || expired {
					c.logger.Debugf("revalidate request")
					rsp, err = c.validationRequest(w, doer, recipe)
				} else {
					c.logger.Debugf("use stored response")
					rsp = recipe.Response
					rsp.Header.Set("Age", fmt.Sprintf("%d", int64(Age(rsp, recipe.RequestDate, recipe.ResponseDate).Seconds())))
				}
			}
		}
	}
	if err != nil {
		return err
	}

	if rsp == nil {
		c.logger.Debugf("unable to find response, contact origin")
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

			c.logger.Debugf("caching response")
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
					c.logger.Errorf("error caching response: %s", err)
					io.Copy(ioutil.Discard, rspCp.Body)
				}
			}()
		} else {
			c.logger.Debugf("response not cachable: %s", permitCache)
		}
	}

	// Per RFC7231 section 7.1.1.2, the 'Date' header is not absolutely mandatory
	if Date(rsp).IsZero() {
		c.logger.Debugf("response does not contains any 'Date', add the generated once")
		rsp.Header.Set("Date", now.Format(http.TimeFormat))
	}

	c.logger.Debugf("write response")
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

func WithLogger(logger Logger) cacheOptionFn {
	return func(c *Cache) {
		c.logger = logger
	}
}

var (
	DefaultOptions = []cacheOption{
		WithValidators(ifModifiedSince{}, ifNoneMatch{}),
		WithStorage(MemStorage()),
		WithLogger(logrus.StandardLogger()),
	}
)

func New(opts ...cacheOption) *Cache {
	return (&Cache{
		mu: &sync.Mutex{},
		requestsMu: make(map[string]*sync.Mutex),
	}).WithOptions(append(DefaultOptions, opts...)...)
}