package sink

import (
	"log/slog"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/source"
)

type Worker struct {
	name    string
	sink    Sink
	queue   chan source.Event
	log     *slog.Logger
	metrics *metrics.Metrics
	wg      sync.WaitGroup
}

func NewWorker(name string, s Sink, queueSize int, log *slog.Logger, m *metrics.Metrics) *Worker {
	if queueSize <= 0 {
		queueSize = 64
	}
	return &Worker{
		name:    name,
		sink:    s,
		queue:   make(chan source.Event, queueSize),
		log:     log,
		metrics: m,
	}
}

func (w *Worker) Start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for ev := range w.queue {
			start := time.Now()
			err := w.sink.Deliver(ev)
			elapsed := time.Since(start)
			if w.metrics != nil {
				w.metrics.ObserveDelivery(w.name, elapsed)
			}
			if err != nil {
				if w.metrics != nil {
					w.metrics.Failed(w.name)
				}
				if w.log != nil {
					w.log.Error("sink delivery failed",
						"sink", w.name, "topic", ev.Topic, "err", err)
				}
				continue
			}
			if w.metrics != nil {
				w.metrics.Delivered(w.name)
			}
		}
	}()
}

// QueueDepth returns (current length, capacity).
func (w *Worker) QueueDepth() (int, int) {
	return len(w.queue), cap(w.queue)
}

func (w *Worker) Submit(ev source.Event) bool {
	select {
	case w.queue <- ev:
		return true
	default:
		if w.metrics != nil {
			w.metrics.Failed(w.name)
		}
		if w.log != nil {
			w.log.Warn("sink queue full, dropping event",
				"sink", w.name, "topic", ev.Topic)
		}
		return false
	}
}

func (w *Worker) Name() string { return w.name }

func (w *Worker) Stop() {
	close(w.queue)
	w.wg.Wait()
}
