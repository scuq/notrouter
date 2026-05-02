package router

import (
	"sync"
	"time"
)

// tokenBucket is a simple per-route token bucket. ratePerSec tokens are added
// continuously up to burst capacity. Allow returns true if a token was
// available, false otherwise.
type tokenBucket struct {
	ratePerSec float64
	burst      float64
	now        func() time.Time

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newTokenBucket(ratePerSec float64, burst int) *tokenBucket {
	if burst <= 0 {
		if ratePerSec >= 1 {
			burst = int(ratePerSec)
		} else {
			burst = 1
		}
	}
	now := time.Now()
	return &tokenBucket{
		ratePerSec: ratePerSec,
		burst:      float64(burst),
		now:        time.Now,
		tokens:     float64(burst),
		last:       now,
	}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.ratePerSec
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
