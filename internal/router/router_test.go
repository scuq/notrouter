package router

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/sink"
	"github.com/scuq/notrouter/internal/source"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type bufSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *bufSink) Deliver(ev source.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(ev.Message + "\n")
	return nil
}

func (b *bufSink) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newWorker(t *testing.T, name string, s sink.Sink) *sink.Worker {
	t.Helper()
	w := sink.NewWorker(name, s, 16, discardLogger(), metrics.New())
	w.Start()
	t.Cleanup(w.Stop)
	return w
}

func waitFor(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout waiting for condition")
}

func TestRouterRoutesByTopic(t *testing.T) {
	alerts := &bufSink{}
	info := &bufSink{}
	r := New(discardLogger(), nil, nil,
		Route{TopicPattern: "alert.*", Workers: []*sink.Worker{newWorker(t, "a", alerts)}},
		Route{TopicPattern: "info.*", Workers: []*sink.Worker{newWorker(t, "i", info)}},
	)
	src := source.NewStatic([]source.Event{
		{Topic: "alert.fire", Message: "FIRE"},
		{Topic: "info.boot", Message: "boot"},
		{Topic: "alert.flood", Message: "FLOOD"},
	})

	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool {
		return strings.TrimSpace(alerts.String()) == "FIRE\nFLOOD" &&
			strings.TrimSpace(info.String()) == "boot"
	})
}

func TestRouterFallback(t *testing.T) {
	out := &bufSink{}
	r := New(discardLogger(), nil, []*sink.Worker{newWorker(t, "out", out)})
	src := source.NewStatic([]source.Event{{Topic: "x", Message: "y"}})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool { return strings.TrimSpace(out.String()) == "y" })
}

type errSink struct{}

func (errSink) Deliver(source.Event) error { return errors.New("boom") }

func TestRouterIsolatesSinkErrors(t *testing.T) {
	good := &bufSink{}
	r := New(discardLogger(), nil, []*sink.Worker{
		newWorker(t, "bad", errSink{}),
		newWorker(t, "good", good),
	})
	src := source.NewStatic([]source.Event{{Topic: "x", Message: "y"}})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool { return strings.TrimSpace(good.String()) == "y" })
}

func TestRouterFiltersBySeverity(t *testing.T) {
	low := &bufSink{}
	high := &bufSink{}
	r := New(discardLogger(), nil, nil,
		Route{TopicPattern: "*", Workers: []*sink.Worker{newWorker(t, "low", low)}},
		Route{TopicPattern: "*", MinSeverity: "warn",
			Workers: []*sink.Worker{newWorker(t, "high", high)}},
	)
	src := source.NewStatic([]source.Event{
		{Topic: "x", Message: "info-msg", Severity: "info"},
		{Topic: "x", Message: "warn-msg", Severity: "warn"},
		{Topic: "x", Message: "err-msg", Severity: "error"},
	})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool {
		return strings.TrimSpace(low.String()) == "info-msg\nwarn-msg\nerr-msg" &&
			strings.TrimSpace(high.String()) == "warn-msg\nerr-msg"
	})
}

func TestRouterDedupesWithinWindow(t *testing.T) {
	out := &bufSink{}
	m := metrics.New()
	r := New(discardLogger(), m, nil,
		Route{
			TopicPattern: "*",
			Workers:      []*sink.Worker{newWorker(t, "out", out)},
			dedup:        newDedup(time.Minute),
		},
	)
	src := source.NewStatic([]source.Event{
		{Topic: "x", Message: "same"},
		{Topic: "x", Message: "same"},
		{Topic: "x", Message: "different"},
	})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool {
		return strings.TrimSpace(out.String()) == "same\ndifferent"
	})
	var buf bytes.Buffer
	_ = m.WriteText(&buf)
	if !strings.Contains(buf.String(), `notrouter_deduped_total{route="*"} 1`) {
		t.Errorf("missing deduped metric:\n%s", buf.String())
	}
}

func TestRouterRateLimitsExcess(t *testing.T) {
	out := &bufSink{}
	m := metrics.New()
	limiter := newTokenBucket(0, 2) // burst 2, no refill within test
	limiter.ratePerSec = 0
	r := New(discardLogger(), m, nil,
		Route{
			TopicPattern: "*",
			Workers:      []*sink.Worker{newWorker(t, "out", out)},
			limiter:      limiter,
		},
	)
	src := source.NewStatic([]source.Event{
		{Topic: "x", Message: "1"},
		{Topic: "x", Message: "2"},
		{Topic: "x", Message: "3"},
		{Topic: "x", Message: "4"},
	})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	waitFor(t, func() bool { return strings.Count(out.String(), "\n") == 2 })
	var buf bytes.Buffer
	_ = m.WriteText(&buf)
	if !strings.Contains(buf.String(), `notrouter_rate_limited_total{route="*"} 2`) {
		t.Errorf("missing rate-limit metric:\n%s", buf.String())
	}
}

func TestRouterMetricsUnmatched(t *testing.T) {
	m := metrics.New()
	r := New(discardLogger(), m, nil,
		Route{TopicPattern: "alert.*", Workers: []*sink.Worker{newWorker(t, "good", &bufSink{})}},
	)
	src := source.NewStatic([]source.Event{
		{Topic: "alert.fire", Message: "y"},
		{Topic: "uncategorized", Message: "z"},
	})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}

	waitFor(t, func() bool {
		var out bytes.Buffer
		_ = m.WriteText(&out)
		return strings.Contains(out.String(), `notrouter_unmatched_total 1`)
	})
}
