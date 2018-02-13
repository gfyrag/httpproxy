package cache

import (
	"net/http"
	"time"
)

type Validator interface {
	// Giving a response, Process() fill request Header with proper validation Header
	Process(*http.Response, *http.Request)
	Validate(*http.Response, *http.Request, time.Time) bool
}

type ifModifiedSince struct {}
func (v ifModifiedSince) Process(rsp *http.Response, req *http.Request) {
	lastModified := LastModified(rsp)
	if !lastModified.IsZero() {
		req.Header.Set("If-Modified-Since", lastModified.Format(http.TimeFormat))
	}
}
func (v ifModifiedSince) Validate(rsp *http.Response, req *http.Request, responseDate time.Time) bool {
	lastModified := LastModified(rsp)
	if lastModified.IsZero() {
		lastModified = Date(rsp)
		if lastModified.IsZero() {
			lastModified = responseDate
		}
	}
	ifModifiedSince := IfModifiedSince(req)
	return lastModified.Sub(ifModifiedSince) <= 0
}

type ifNoneMatch struct {}
func (v ifNoneMatch) Process(rsp *http.Response, req *http.Request) {
	eTag := ETag(rsp)
	if eTag != "" {
		req.Header.Set("If-None-Match", eTag)
	}
}
func (v ifNoneMatch) Validate(rsp *http.Response, req *http.Request, responseDate time.Time) bool {
	eTag := ETag(rsp)
	ifNoneMatch := IfNoneMatch(req)
	return eTag == ifNoneMatch
}

type Validators []Validator
func (vs Validators) Validate(recipe *Recipe) bool {
	for _, v := range vs {
		if v.Validate(recipe.Response, recipe.Request, recipe.ResponseDate) {
			return true
		}
	}
	return false
}