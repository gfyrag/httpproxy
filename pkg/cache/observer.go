package cache

import (
	"net/http"
	"time"
)

type Event interface {
	isEvent()
}

type Observer interface {
	Observe(Event)
}
type ObserverFn func(Event)
func (fn ObserverFn) Observe(e Event) {
	fn(e)
}
var NoOpObserver ObserverFn = func(e Event) {}

type baseEvent struct {
	Request *http.Request
	When time.Time
}

type NoCachableRequestEvent struct {
	baseEvent
	Err error
}
func (e NoCachableRequestEvent) isEvent() {}
func NoCachableRequest(r *http.Request, err error) NoCachableRequestEvent {
	return NoCachableRequestEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
		Err: err,
	}
}

type NoCachableResponseEvent struct {
	baseEvent
	Why error
}
func (e NoCachableResponseEvent) isEvent() {}
func NoCachableResponse(r *http.Request, err error) NoCachableResponseEvent {
	return NoCachableResponseEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
		Why: err,
	}
}

type CacheHitEvent struct {
	baseEvent
}
func (e CacheHitEvent) isEvent() {}
func CacheHit(r *http.Request) CacheHitEvent {
	return CacheHitEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type CacheMissEvent struct {
	baseEvent
}
func (e CacheMissEvent) isEvent() {}
func CacheMiss(r *http.Request) CacheMissEvent {
	return CacheMissEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type RevalidatedEvent struct {
	baseEvent
}
func (e RevalidatedEvent) isEvent() {}
func Revalidated(r *http.Request) RevalidatedEvent {
	return RevalidatedEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type RevalidatedFromCacheEvent struct {
	baseEvent
}
func (e RevalidatedFromCacheEvent) isEvent() {}
func RevalidatedFromCache(r *http.Request) RevalidatedFromCacheEvent {
	return RevalidatedFromCacheEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type RevalidatedFromCacheFailedEvent struct {
	baseEvent
}
func (e RevalidatedFromCacheFailedEvent) isEvent() {}
func RevalidatedFromCacheFailed(r *http.Request) RevalidatedFromCacheFailedEvent {
	return RevalidatedFromCacheFailedEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type ServedFromCacheEvent struct {
	baseEvent
}
func (e ServedFromCacheEvent) isEvent() {}
func ServedFromCache(r *http.Request) ServedFromCacheEvent {
	return ServedFromCacheEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type CachingResponseEvent struct {
	baseEvent
}
func (e CachingResponseEvent) isEvent() {}
func CachingResponse(r *http.Request) CachingResponseEvent {
	return CachingResponseEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}

type CachingResponseErrorEvent struct {
	baseEvent
	Err error
}
func (e CachingResponseErrorEvent) isEvent() {}
func CachingResponseError(r *http.Request, e error) CachingResponseErrorEvent {
	return CachingResponseErrorEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
		Err: e,
	}
}

type RespondEvent struct {
	baseEvent
	Response *http.Response
}
func (e RespondEvent) isEvent() {}
func Respond(r *http.Request, rsp *http.Response) RespondEvent {
	return RespondEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
		Response: rsp,
	}
}

type LockEvent struct {
	baseEvent
}
func (e LockEvent) isEvent() {}
func Lock(r *http.Request) LockEvent {
	return LockEvent{
		baseEvent: baseEvent{
			Request: r,
			When: time.Now(),
		},
	}
}