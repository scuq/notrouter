package router

import (
	"testing"
	"time"
)

func TestTokenBucketBurstAndRefill(t *testing.T) {
	b := newTokenBucket(1, 3)
	now := time.Unix(0, 0)
	b.now = func() time.Time { return now }
	b.last = now

	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if b.Allow() {
		t.Fatal("4th token should be denied (burst exhausted)")
	}

	now = now.Add(time.Second)
	if !b.Allow() {
		t.Fatal("after 1s should have 1 token")
	}
	if b.Allow() {
		t.Fatal("only 1 token regenerated")
	}
}

func TestTokenBucketDefaultBurst(t *testing.T) {
	b := newTokenBucket(5, 0)
	if b.burst != 5 {
		t.Fatalf("default burst should be int(rate)=5, got %v", b.burst)
	}
}
