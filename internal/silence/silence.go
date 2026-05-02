package silence

import (
	"crypto/rand"
	"encoding/hex"
	"path"
	"sync"
	"time"
)

type Silence struct {
	ID      string    `json:"id"`
	Topic   string    `json:"topic"`
	Expires time.Time `json:"expires"`
}

type Store struct {
	now func() time.Time
	mu  sync.RWMutex
	all map[string]Silence
}

func NewStore() *Store {
	return &Store{now: time.Now, all: make(map[string]Silence)}
}

// Add registers a silence for the given topic glob with the given TTL.
// Returns the assigned ID.
func (s *Store) Add(topic string, ttl time.Duration) (Silence, error) {
	if topic == "" {
		topic = "*"
	}
	if _, err := path.Match(topic, ""); err != nil {
		return Silence{}, err
	}
	id, err := newID()
	if err != nil {
		return Silence{}, err
	}
	sil := Silence{ID: id, Topic: topic, Expires: s.now().Add(ttl)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all[id] = sil
	return sil, nil
}

// Silenced reports whether any active silence matches the given topic.
func (s *Store) Silenced(topic string) bool {
	now := s.now()
	s.mu.RLock()
	for _, sil := range s.all {
		if sil.Expires.Before(now) {
			continue
		}
		if sil.Topic == "*" || sil.Topic == topic {
			s.mu.RUnlock()
			return true
		}
		if ok, err := path.Match(sil.Topic, topic); err == nil && ok {
			s.mu.RUnlock()
			return true
		}
	}
	s.mu.RUnlock()
	return false
}

// List returns currently-active silences (sorted is the caller's job).
func (s *Store) List() []Silence {
	now := s.now()
	s.mu.RLock()
	out := make([]Silence, 0, len(s.all))
	for _, sil := range s.all {
		if sil.Expires.After(now) {
			out = append(out, sil)
		}
	}
	s.mu.RUnlock()
	return out
}

// GC removes expired silences. Call periodically; cheap if list is small.
func (s *Store) GC() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, sil := range s.all {
		if sil.Expires.Before(now) {
			delete(s.all, id)
			removed++
		}
	}
	return removed
}

func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
