package dedup

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
)

type Deduplicator struct {
	in        <-chan *event.Event
	out       chan<- *event.Event
	ttl       time.Duration
	keyFields []string
	log       *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
}

func New(in <-chan *event.Event, out chan<- *event.Event, ttl time.Duration, keyFields []string, log *slog.Logger) *Deduplicator {
	return &Deduplicator{
		in:        in,
		out:       out,
		ttl:       ttl,
		keyFields: keyFields,
		log:       log,
		seen:      make(map[string]time.Time),
	}
}

func (d *Deduplicator) Name() string { return "dedup" }

// Size implements admin.DedupProbe.
func (d *Deduplicator) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

// Clear implements admin.DedupProbe. Wipes the entire dedup map - the
// "panic button" for when a misconfigured dedup_window suppresses real
// alerts. Logs at warn level so operators can correlate with their action.
func (d *Deduplicator) Clear() {
	d.mu.Lock()
	d.seen = make(map[string]time.Time)
	d.mu.Unlock()
}

func (d *Deduplicator) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(d.out)

	sweepInterval := d.ttl / 2
	if sweepInterval < time.Second {
		sweepInterval = time.Second
	}
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			d.sweep()
		case ev, ok := <-d.in:
			if !ok {
				return
			}
			if d.isDup(ev) {
				metrics.EventsDropped.WithLabelValues("duplicate").Inc()
				d.log.Debug("dedup drop", "entity", ev.Entity, "topic", ev.Topic)
				continue
			}
			select {
			case d.out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (d *Deduplicator) isDup(ev *event.Event) bool {
	key := d.key(ev)
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if exp, ok := d.seen[key]; ok && now.Before(exp) {
		return true
	}
	d.seen[key] = now.Add(d.ttl)
	return false
}

func (d *Deduplicator) key(ev *event.Event) string {
	parts := make([]string, 0, len(d.keyFields))
	for _, f := range d.keyFields {
		switch f {
		case "entity":
			parts = append(parts, ev.Entity)
		case "topic":
			parts = append(parts, ev.Topic)
		case "urgency":
			parts = append(parts, string(ev.Urgency))
		case "source":
			parts = append(parts, ev.Source)
		default:
			parts = append(parts, ev.Attributes[f])
		}
	}
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

func (d *Deduplicator) sweep() {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, exp := range d.seen {
		if now.After(exp) {
			delete(d.seen, k)
		}
	}
}

// AnalyzeKey returns the dedup key for an event AND reports whether the
// key currently exists in the seen-cache. READ-ONLY: does NOT add to
// the cache. Used by the analyzer for "what would dedup do" queries.
//
// Returns (key, isDup, lastSeenAt). lastSeenAt is meaningful only when
// isDup is true.
func (d *Deduplicator) AnalyzeKey(ev *event.Event) (string, bool, time.Time) {
	key := d.key(ev)
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.seen[key]
	if !ok {
		return key, false, time.Time{}
	}
	now := time.Now()
	if now.Before(exp) {
		return key, true, exp.Add(-d.ttl)
	}
	return key, false, time.Time{}
}
