package router

import (
	"sync"
	"time"
)

// dedup suppresses repeats of the same key within a window.
// It stores last-seen time per key and lazily evicts expired entries on Allow.
type dedup struct {
	window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	seen   map[string]time.Time
}

func newDedup(window time.Duration) *dedup {
	return &dedup{
		window: window,
		now:    time.Now,
		seen:   make(map[string]time.Time),
	}
}

// Allow reports whether the key may pass. It returns true if the key has not
// been seen within the window; false if it is a duplicate.
func (d *dedup) Allow(key string) bool {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.seen[key]; ok && now.Sub(last) < d.window {
		return false
	}
	d.seen[key] = now
	if len(d.seen) > 1024 {
		d.evictExpired(now)
	}
	return true
}

func (d *dedup) evictExpired(now time.Time) {
	for k, t := range d.seen {
		if now.Sub(t) >= d.window {
			delete(d.seen, k)
		}
	}
}
