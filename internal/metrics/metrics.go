package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	EventsReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_events_received_total",
		Help: "Events received, by source.",
	}, []string{"source"})

	EventsResolved = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_events_resolved_total",
		Help: "Events with successful entity resolution, by source.",
	}, []string{"source"})

	EventsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_events_dropped_total",
		Help: "Events dropped, by reason.",
	}, []string{"reason"})

	EventsDispatched = promauto.NewCounter(prometheus.CounterOpts{
		Name: "notrouter_events_dispatched_total",
		Help: "Events that reached the dispatcher.",
	})

	Suppressed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_suppressed_total",
		Help: "Events suppressed, by rule name.",
	}, []string{"rule"})

	DeliveryOutcomes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_delivery_outcomes_total",
		Help: "Per-instance delivery outcomes.",
	}, []string{"instance", "state"})

	DeliveryFinal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_delivery_final_total",
		Help: "Final per-event delivery state.",
	}, []string{"state"})

	InstanceQueueFull = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notrouter_instance_queue_full_total",
		Help: "Times a plugin instance queue was full.",
	}, []string{"instance"})
)
