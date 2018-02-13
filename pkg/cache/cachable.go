package cache

import (
	"net/http"
	"time"
	"strconv"
	"math"
	"errors"
)

var (
	ErrNoFreshnessInfo    = errors.New("no freshness info found")
	ErrNotCachableStatus = errors.New("not cachable status")
	ErrNotCachableMethod = errors.New("not cachable method")
	ErrPrivateCache       = errors.New("private cache")
)

// See RFC7231 section 4.2.3
func CachableMethod(r *http.Request) bool {
	return r.Method == http.MethodGet ||
		r.Method == http.MethodHead ||
		r.Method == http.MethodPost
}

// See RFC7231 section 6.1
// Does not support http.StatusPartialContent (206)
func CachableStatus(r *http.Response) bool {
	return r.StatusCode == http.StatusOK ||
		r.StatusCode == http.StatusNonAuthoritativeInfo ||
		r.StatusCode == http.StatusNoContent ||
		// TODO: In future version, maybe we can properly handle this status which is covered ty the RFC
		// r.StatusCode == http.StatusPartialContent ||
		r.StatusCode == http.StatusMultipleChoices ||
		r.StatusCode == http.StatusMovedPermanently ||
		r.StatusCode == http.StatusNotFound ||
		r.StatusCode == http.StatusMethodNotAllowed ||
		r.StatusCode == http.StatusNotImplemented
}

// See RFC7232 secton 3
func IsConditionalRequest(r *http.Request) bool {
	return r.Header.Get("If-Match") != "" ||
		r.Header.Get("If-None-Match") != "" ||
		r.Header.Get("If-Modified-Since") != "" ||
		r.Header.Get("If-Unmodified-Since") != "" ||
		r.Header.Get("If-Range") != ""
}

// Will panic if called with any type other than *http.Response or *http.Serve
// See RFC7234 section 3
// Does not allow cache-control extensions (See RFC7234 section 5.2.3)
func PermitCache(v interface{}) (error) {

	var (
		expires time.Time
		headers http.Header
	)
	switch vv := v.(type) {
	case *http.Response:
		headers = vv.Header
		if !CachableStatus(vv) {
			return ErrNotCachableStatus
		}
		expires = Expires(vv)
	case *http.Request:
		headers = vv.Header
		if !CachableMethod(vv) {
			return ErrNotCachableMethod
		}
		if headers.Get("Authorization") != "" {
			return ErrPrivateCache
		}
	default:
		panic("unexpected object")
	}
	cc, err := CacheControl(v)
	if err != nil {
		return err
	}
	if expires.IsZero() && !cc.Cacheable() {
		return ErrNoFreshnessInfo
	}

	return nil
}

// Will panic if called with any type other than *http.Response or *http.Serve
// The no-cache directive can be used in request and responses
// In both case, this is used to prevent a cache to use a cached response without revalidating against the origin server
// See RFC7234 section 5.2.2.2
func NoCache(v interface{}) (bool, error) {

	var headers http.Header
	switch vv := v.(type) {
	case *http.Response:
		headers = vv.Header
	case *http.Request:
		headers = vv.Header
		// HTTP/1.0 compatibility
		// See RFC7234 section 5.4
		for _, pragma := range normalizeHeader("Pragma", headers) {
			if pragma == "no-cache" {
				return true, nil
			}
		}
	default:
		panic("unexpected object")
	}

	// See RFC7234 section 5.2.1
	cacheControl := cacheControl{}
	err := cacheControl.Parse(v)
	if err != nil {
		return true, err
	}
	return cacheControl.noCache, nil
}

func Expires(r *http.Response) time.Time {
	expiresHeader := r.Header.Get("Expires")
	expires, _ := http.ParseTime(expiresHeader)
	return expires
}

func Expiration(r *http.Response, responseDate time.Time) (time.Time, error) {
	freshnessLifetime, err := FreshnessLifetime(r, responseDate)
	if err != nil {
		return time.Time{}, err
	}

	date := Date(r)
	if date.IsZero() {
		date = responseDate
	}
	return date.Add(freshnessLifetime), nil
}

func Expired(rsp *http.Response, responseDate time.Time) bool {
	e, err := Expiration(rsp, responseDate)
	if err != nil {
		return true
	}
	now := time.Now().UTC()
	return !e.After(now)
}

func Date(r *http.Response) time.Time {
	date, err := http.ParseTime(r.Header.Get("Date"))
	if err != nil {
		return time.Time{}
	}
	return date
}

// See RFC7234 section 4.2.1 for mechanism
func FreshnessLifetime(r *http.Response, responseDate time.Time) (time.Duration, error) {

	cacheControl := cacheControl{}
	err := cacheControl.Parse(r)
	if err != nil {
		return time.Duration(0), err
	}
	if cacheControl.sMaxAge != 0 {
		return cacheControl.sMaxAge, nil
	}
	if cacheControl.maxAge != 0 {
		return cacheControl.maxAge, nil
	}
	expires := Expires(r)
	date := Date(r)
	if date.IsZero() {
		date = responseDate
	}
	if !expires.IsZero() && !date.IsZero() {
		return expires.Sub(date), nil
	}

	return time.Duration(0), ErrNoFreshnessInfo
}

// See RFC7234 section 4.2.3
func Age(r *http.Response, requestDate, responseDate time.Time) time.Duration {
	ageHeader := r.Header.Get("Age")
	var (
		ageValue time.Duration
	)
	if ageHeader != "" {
		age, err := strconv.ParseInt(ageHeader, 10, 0)
		if err == nil {
			ageValue = time.Duration(age)*time.Second
		}
	}
	apparentAge := time.Duration(math.Max(0, float64(responseDate.Sub(Date(r)))))
	responseDelay := responseDate.Sub(requestDate)
	correctedAgeValue := ageValue + responseDelay
	correctedInitialAge := time.Duration(math.Max(float64(apparentAge), float64(correctedAgeValue)))
	residentTime := time.Now().Sub(responseDate)
	return correctedInitialAge + residentTime
}