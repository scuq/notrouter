package router

import (
	"testing"
	"time"
)

func TestDedupSuppressesWithinWindow(t *testing.T) {
	d := newDedup(time.Minute)
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }

	if !d.Allow("k") {
		t.Fatal("first should pass")
	}
	if d.Allow("k") {
		t.Fatal("immediate repeat should be suppressed")
	}
	now = now.Add(30 * time.Second)
	if d.Allow("k") {
		t.Fatal("still inside window")
	}
	now = now.Add(31 * time.Second)
	if !d.Allow("k") {
		t.Fatal("past window should pass again")
	}
}

func TestDedupDifferentKeys(t *testing.T) {
	d := newDedup(time.Minute)
	if !d.Allow("a") || !d.Allow("b") {
		t.Fatal("distinct keys should both pass")
	}
}
