package dispatch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/plugins"
)

type instanceRunCfg struct {
	inst  plugins.Instance
	retry config.RetryConfig
	queue chan *event.Event
}

type Dispatcher struct {
	in      <-chan *pipeline.RoutedEvent
	tracker *Tracker
	insts   map[string]*instanceRunCfg
	log     *slog.Logger
}

func NewDispatcher(
	in <-chan *pipeline.RoutedEvent,
	tracker *Tracker,
	instances map[string]plugins.Instance,
	defaultRetry config.RetryConfig,
	instanceCfgs map[string]config.InstanceConfig,
	instanceBufSize int,
	log *slog.Logger,
) *Dispatcher {
	d := &Dispatcher{
		in:      in,
		tracker: tracker,
		insts:   make(map[string]*instanceRunCfg, len(instances)),
		log:     log,
	}
	for name, inst := range instances {
		retry := defaultRetry
		if ic, ok := instanceCfgs[name]; ok {
			retry = mergeRetry(defaultRetry, ic.Retry)
		}
		d.insts[name] = &instanceRunCfg{
			inst:  inst,
			retry: retry,
			queue: make(chan *event.Event, instanceBufSize),
		}
	}
	return d
}

func mergeRetry(def, override config.RetryConfig) config.RetryConfig {
	out := def
	if override.Attempts > 0 {
		out.Attempts = override.Attempts
	}
	if len(override.Backoff) > 0 {
		out.Backoff = override.Backoff
	}
	return out
}

func (d *Dispatcher) Name() string { return "dispatcher" }

// QueueState implements admin.DispatchProbe. Returns sorted-by-name to
// give /healthz and /admin/state stable output (helps diff'ing curls).
func (d *Dispatcher) QueueState() []admin.QueueState {
	out := make([]admin.QueueState, 0, len(d.insts))
	for name, rc := range d.insts {
		out = append(out, admin.QueueState{
			Instance: name,
			Depth:    len(rc.queue),
			Capacity: cap(rc.queue),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}

func (d *Dispatcher) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	var workerWg sync.WaitGroup
	for name, rc := range d.insts {
		workerWg.Add(1)
		go d.runInstance(ctx, &workerWg, name, rc)
	}

	for {
		select {
		case <-ctx.Done():
			d.closeQueues()
			workerWg.Wait()
			return
		case re, ok := <-d.in:
			if !ok {
				d.closeQueues()
				workerWg.Wait()
				return
			}
			d.fanout(ctx, re)
		}
	}
}

func (d *Dispatcher) closeQueues() {
	for _, rc := range d.insts {
		close(rc.queue)
	}
}

func (d *Dispatcher) fanout(ctx context.Context, re *pipeline.RoutedEvent) {
	if re.Event.ID == "" {
		re.Event.ID = newID()
	}
	d.tracker.Begin(re.Event.ID, re.Subscribers)
	metrics.EventsDispatched.Inc()

	for _, sub := range re.Subscribers {
		rc, ok := d.insts[sub]
		if !ok {
			d.tracker.Record(Outcome{EventID: re.Event.ID, Instance: sub, State: StateFailed})
			d.log.Warn("dispatch: unknown subscriber", "subscriber", sub)
			continue
		}
		select {
		case rc.queue <- re.Event:
		case <-ctx.Done():
			return
		default:
			d.tracker.Record(Outcome{EventID: re.Event.ID, Instance: sub, State: StateFailed})
			metrics.InstanceQueueFull.WithLabelValues(sub).Inc()
		}
	}
}

func (d *Dispatcher) runInstance(ctx context.Context, wg *sync.WaitGroup, name string, rc *instanceRunCfg) {
	defer wg.Done()
	for ev := range rc.queue {
		err := sendWithRetry(ctx, rc.inst, ev, rc.retry.Attempts, rc.retry.Backoff)
		state := StateDelivered
		if err != nil {
			state = StateFailed
			d.log.Error("dispatch failed",
				"instance", name,
				"event", ev.ID,
				"attempts", rc.retry.Attempts,
				"err", err)
		}
		d.tracker.Record(Outcome{
			EventID:  ev.ID,
			Instance: name,
			State:    state,
			Err:      err,
		})
	}
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405") + "-" + hex.EncodeToString(b[:])
}
