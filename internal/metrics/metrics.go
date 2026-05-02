package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	mu             sync.RWMutex
	eventsAccepted map[string]*atomic.Uint64
	eventsDropped  map[string]*atomic.Uint64
	delivered      map[string]*atomic.Uint64
	failed         map[string]*atomic.Uint64
	deduped        map[string]*atomic.Uint64
	rateLimited    map[string]*atomic.Uint64
	silenced       map[string]*atomic.Uint64
	unmatched      atomic.Uint64

	deliveryLatency *histogramSet
}

var defaultLatencyBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

func New() *Metrics {
	return &Metrics{
		eventsAccepted: make(map[string]*atomic.Uint64),
		eventsDropped:  make(map[string]*atomic.Uint64),
		delivered:      make(map[string]*atomic.Uint64),
		failed:         make(map[string]*atomic.Uint64),
		deduped:        make(map[string]*atomic.Uint64),
		rateLimited:    make(map[string]*atomic.Uint64),
		silenced:       make(map[string]*atomic.Uint64),
		deliveryLatency: newHistogramSet(defaultLatencyBuckets),
	}
}

func (m *Metrics) ObserveDelivery(sink string, d time.Duration) {
	m.deliveryLatency.observe(sink, d)
}

func (m *Metrics) counter(bucket map[string]*atomic.Uint64, key string) *atomic.Uint64 {
	m.mu.RLock()
	c, ok := bucket[key]
	m.mu.RUnlock()
	if ok {
		return c
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok = bucket[key]; ok {
		return c
	}
	c = new(atomic.Uint64)
	bucket[key] = c
	return c
}

func (m *Metrics) EventAccepted(source string) { m.counter(m.eventsAccepted, source).Add(1) }
func (m *Metrics) EventDropped(source string)  { m.counter(m.eventsDropped, source).Add(1) }
func (m *Metrics) Delivered(sink string)       { m.counter(m.delivered, sink).Add(1) }
func (m *Metrics) Failed(sink string)          { m.counter(m.failed, sink).Add(1) }
func (m *Metrics) Deduped(route string)        { m.counter(m.deduped, route).Add(1) }
func (m *Metrics) RateLimited(route string)    { m.counter(m.rateLimited, route).Add(1) }
func (m *Metrics) Silenced(topic string)       { m.counter(m.silenced, topic).Add(1) }
func (m *Metrics) Unmatched()                  { m.unmatched.Add(1) }

type group struct {
	name   string
	help   string
	bucket map[string]*atomic.Uint64
	label  string
}

func (m *Metrics) WriteText(w io.Writer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	groups := []group{
		{"notrouter_events_accepted_total", "Events accepted by a source.", m.eventsAccepted, "source"},
		{"notrouter_events_dropped_total", "Events dropped at source intake (buffer full).", m.eventsDropped, "source"},
		{"notrouter_delivered_total", "Events successfully delivered to a sink.", m.delivered, "sink"},
		{"notrouter_failed_total", "Sink delivery failures (errors or queue overflow).", m.failed, "sink"},
		{"notrouter_deduped_total", "Events suppressed by per-route dedup.", m.deduped, "route"},
		{"notrouter_rate_limited_total", "Events dropped by per-route rate limiting.", m.rateLimited, "route"},
		{"notrouter_silenced_total", "Events suppressed by an active silence.", m.silenced, "topic"},
	}
	for _, g := range groups {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", g.name, g.help, g.name); err != nil {
			return err
		}
		keys := make([]string, 0, len(g.bucket))
		for k := range g.bucket {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(w, "%s{%s=%q} %d\n", g.name, g.label, k, g.bucket[k].Load()); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w,
		"# HELP notrouter_unmatched_total Events that matched no route and had no fallback.\n# TYPE notrouter_unmatched_total counter\nnotrouter_unmatched_total %d\n",
		m.unmatched.Load()); err != nil {
		return err
	}
	if err := m.deliveryLatency.writeText(w,
		"notrouter_sink_delivery_seconds",
		"Sink delivery latency in seconds.",
		"sink"); err != nil {
		return err
	}
	return nil
}
