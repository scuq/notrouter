package silence

import (
	"testing"
	"time"
)

func TestSilenceMatchAndExpire(t *testing.T) {
	s := NewStore()
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	if _, err := s.Add("alert.*", time.Minute); err != nil {
		t.Fatal(err)
	}

	if !s.Silenced("alert.fire") {
		t.Fatal("alert.fire should be silenced")
	}
	if s.Silenced("info.boot") {
		t.Fatal("info.boot should not be silenced")
	}

	now = now.Add(2 * time.Minute)
	if s.Silenced("alert.fire") {
		t.Fatal("expired silence should no longer match")
	}
	if got := s.GC(); got != 1 {
		t.Fatalf("GC removed %d, want 1", got)
	}
	if len(s.List()) != 0 {
		t.Fatal("expected no silences after GC")
	}
}

func TestSilenceList(t *testing.T) {
	s := NewStore()
	if _, err := s.Add("a.*", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add("b.*", time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := len(s.List()); got != 2 {
		t.Fatalf("list len = %d, want 2", got)
	}
}
