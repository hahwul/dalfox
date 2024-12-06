package scanning

import (
	"sync"
	"time"
)

// a rateLimiter allows you to delay operations
// on a per-key basis. I.e. only one operation for
// a given key can be done within the delay time
type rateLimiter struct {
	sync.RWMutex
	delay time.Duration
	ops   map[string]time.Time
}

// newRateLimiter returns a new *rateLimiter for the
// provided delay
func newRateLimiter(delay time.Duration) *rateLimiter {
	return &rateLimiter{
		delay: delay,
		ops:   make(map[string]time.Time),
	}
}

// Block blocks until an operation for key is
// allowed to proceed
func (r *rateLimiter) Block(key string) {
	now := time.Now()

	r.Lock()
	defer r.Unlock()

	// if there's nothing in the map we can
	// return straight away
	if t, ok := r.ops[key]; !ok || now.After(t.Add(r.delay)) {
		r.ops[key] = now
		return
	}

	// if time is up we can return straight away
	t := r.ops[key]
	deadline := t.Add(r.delay)
	if now.After(deadline) {
		r.ops[key] = now
		return
	}

	remaining := deadline.Sub(now)

	// Set the time of the operation
	r.ops[key] = now.Add(remaining)

	// Block for the remaining time
	time.Sleep(remaining)
}
