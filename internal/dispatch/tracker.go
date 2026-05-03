package dispatch

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/metrics"
)

type DeliveryState string

const (
	StatePending   DeliveryState = "pending"
	StateDelivered DeliveryState = "delivered"
	StateFailed    DeliveryState = "failed"
)

// recentFinalCap caps the ring of finalized deliveries the admin endpoint
// can see. Bigger = more debugging visibility, but unbounded growth is
// a memory leak. 200 is a reasonable middle ground.
const recentFinalCap = 200

type Outcome struct {
	EventID  string
	Instance string
	State    DeliveryState
	Err      error
}

type delivery struct {
	eventID     string
	created     time.Time
	deadline    time.Time
	subscribers map[string]DeliveryState
}

type Tracker struct {
	ttl     time.Duration
	log     *slog.Logger
	mu      sync.Mutex
	pending map[string]*delivery

	// Ring buffer of recent finalized deliveries for /admin/deliveries.
	// We use a fixed-size slice + write index so memory is bounded.
	recentMu  sync.Mutex
	recent    []admin.FinalRecord
	recentPos int
}

func NewTracker(ttl time.Duration, log *slog.Logger) *Tracker {
	return &Tracker{
		ttl:     ttl,
		log:     log,
		pending: make(map[string]*delivery),
		recent:  make([]admin.FinalRecord, 0, recentFinalCap),
	}
}

// Pending implements admin.TrackerProbe.
func (t *Tracker) Pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

// RecentFinal returns up to recentFinalCap most recent finalizations,
// newest first. Implements admin.TrackerProbe.
func (t *Tracker) RecentFinal() []admin.FinalRecord {
	t.recentMu.Lock()
	defer t.recentMu.Unlock()
	// Walk ring backwards from recentPos to produce newest-first order.
	n := len(t.recent)
	out := make([]admin.FinalRecord, 0, n)
	for i := 0; i < n; i++ {
		idx := (t.recentPos - 1 - i + n) % n
		out = append(out, t.recent[idx])
	}
	return out
}

func (t *Tracker) Begin(eventID string, subscribers []string) {
	now := time.Now()
	d := &delivery{
		eventID:     eventID,
		created:     now,
		deadline:    now.Add(t.ttl),
		subscribers: make(map[string]DeliveryState, len(subscribers)),
	}
	for _, s := range subscribers {
		d.subscribers[s] = StatePending
	}
	t.mu.Lock()
	t.pending[eventID] = d
	t.mu.Unlock()
}

func (t *Tracker) Record(o Outcome) {
	t.mu.Lock()
	d, ok := t.pending[o.EventID]
	if !ok {
		t.mu.Unlock()
		return
	}
	d.subscribers[o.Instance] = o.State
	metrics.DeliveryOutcomes.WithLabelValues(o.Instance, string(o.State)).Inc()

	if t.allTerminal(d) {
		t.finalize(d, false)
		delete(t.pending, o.EventID)
	}
	t.mu.Unlock()
}

func (t *Tracker) allTerminal(d *delivery) bool {
	for _, s := range d.subscribers {
		if s == StatePending {
			return false
		}
	}
	return true
}

func (t *Tracker) finalize(d *delivery, expired bool) {
	delivered, failed := 0, 0
	subStates := make(map[string]string, len(d.subscribers))
	for k, v := range d.subscribers {
		subStates[k] = string(v)
		switch v {
		case StateDelivered:
			delivered++
		case StateFailed:
			failed++
		}
	}
	overall := "delivered"
	switch {
	case expired && delivered == 0:
		overall = "expired"
	case expired:
		overall = "expired_partial"
	case delivered > 0 && failed > 0:
		overall = "partial"
	case delivered == 0:
		overall = "failed"
	}
	metrics.DeliveryFinal.WithLabelValues(overall).Inc()
	t.log.Info("delivery final",
		"event", d.eventID,
		"state", overall,
		"delivered", delivered,
		"failed", failed,
		"details", d.subscribers)

	t.appendRecent(admin.FinalRecord{
		EventID:     d.eventID,
		State:       overall,
		Created:     d.created.Format(time.RFC3339Nano),
		Finalized:   time.Now().UTC().Format(time.RFC3339Nano),
		Subscribers: subStates,
	})
}

func (t *Tracker) appendRecent(r admin.FinalRecord) {
	t.recentMu.Lock()
	defer t.recentMu.Unlock()
	if len(t.recent) < recentFinalCap {
		t.recent = append(t.recent, r)
		t.recentPos = len(t.recent) % recentFinalCap
		return
	}
	t.recent[t.recentPos] = r
	t.recentPos = (t.recentPos + 1) % recentFinalCap
}

func (t *Tracker) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sweep()
		}
	}
}

func (t *Tracker) Name() string { return "delivery-tracker" }

func (t *Tracker) sweep() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, d := range t.pending {
		if now.After(d.deadline) {
			t.finalize(d, true)
			delete(t.pending, id)
		}
	}
}
