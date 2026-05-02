package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMetricsCountAndRender(t *testing.T) {
	m := New()
	m.EventAccepted("public")
	m.EventAccepted("public")
	m.EventDropped("public")
	m.Delivered("console")
	m.Failed("webhook")
	m.Unmatched()
	m.ObserveDelivery("console", 75*time.Millisecond)
	m.ObserveDelivery("console", 200*time.Millisecond)

	var buf bytes.Buffer
	if err := m.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`# TYPE notrouter_events_accepted_total counter`,
		`# HELP notrouter_delivered_total Events successfully delivered to a sink.`,
		`notrouter_events_accepted_total{source="public"} 2`,
		`notrouter_events_dropped_total{source="public"} 1`,
		`notrouter_delivered_total{sink="console"} 1`,
		`notrouter_failed_total{sink="webhook"} 1`,
		`notrouter_unmatched_total 1`,
		`# TYPE notrouter_sink_delivery_seconds histogram`,
		`notrouter_sink_delivery_seconds_count{sink="console"} 2`,
		`notrouter_sink_delivery_seconds_bucket{sink="console",le="0.25"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
