package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// histogram is a simple cumulative counter histogram.
// Buckets are upper bounds in seconds.
type histogram struct {
	bounds  []float64 // ascending
	buckets []*atomic.Uint64
	count   atomic.Uint64
	sumNs   atomic.Uint64 // store sum as nanoseconds to keep it integer-safe
}

func newHistogram(bounds []float64) *histogram {
	h := &histogram{bounds: bounds, buckets: make([]*atomic.Uint64, len(bounds))}
	for i := range h.buckets {
		h.buckets[i] = new(atomic.Uint64)
	}
	return h
}

func (h *histogram) observe(d time.Duration) {
	secs := d.Seconds()
	for i, b := range h.bounds {
		if secs <= b {
			h.buckets[i].Add(1)
		}
	}
	h.count.Add(1)
	h.sumNs.Add(uint64(d.Nanoseconds()))
}

// histogramSet keyed by label value (e.g., sink name).
type histogramSet struct {
	bounds []float64
	mu     sync.RWMutex
	all    map[string]*histogram
}

func newHistogramSet(bounds []float64) *histogramSet {
	return &histogramSet{bounds: bounds, all: make(map[string]*histogram)}
}

func (s *histogramSet) observe(label string, d time.Duration) {
	s.mu.RLock()
	h, ok := s.all[label]
	s.mu.RUnlock()
	if !ok {
		s.mu.Lock()
		if h, ok = s.all[label]; !ok {
			h = newHistogram(s.bounds)
			s.all[label] = h
		}
		s.mu.Unlock()
	}
	h.observe(d)
}

func (s *histogramSet) writeText(w io.Writer, name, help, labelKey string) error {
	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name); err != nil {
		return err
	}
	s.mu.RLock()
	keys := make([]string, 0, len(s.all))
	for k := range s.all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h := s.all[k]
		for i, b := range h.bounds {
			if _, err := fmt.Fprintf(w, "%s_bucket{%s=%q,le=%q} %d\n",
				name, labelKey, k, formatBound(b), h.buckets[i].Load()); err != nil {
				s.mu.RUnlock()
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s_bucket{%s=%q,le=\"+Inf\"} %d\n",
			name, labelKey, k, h.count.Load()); err != nil {
			s.mu.RUnlock()
			return err
		}
		sumSec := float64(h.sumNs.Load()) / 1e9
		if _, err := fmt.Fprintf(w, "%s_sum{%s=%q} %g\n", name, labelKey, k, sumSec); err != nil {
			s.mu.RUnlock()
			return err
		}
		if _, err := fmt.Fprintf(w, "%s_count{%s=%q} %d\n", name, labelKey, k, h.count.Load()); err != nil {
			s.mu.RUnlock()
			return err
		}
	}
	s.mu.RUnlock()
	return nil
}

func formatBound(b float64) string {
	if math.Trunc(b) == b {
		return fmt.Sprintf("%g", b)
	}
	return fmt.Sprintf("%g", b)
}
