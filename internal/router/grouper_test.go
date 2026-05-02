package router

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/scuq/notrouter/internal/sink"
	"github.com/scuq/notrouter/internal/source"
)

func TestGrouperAggregatesByKey(t *testing.T) {
	out := &bufSink{}
	w := newWorker(t, "out", out)
	g, err := newGrouper(time.Minute, "{{.Topic}}", []*sink.Worker{w})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, 0)
	g.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		_ = g.Add(source.Event{Topic: "alert.fire", Message: "fire"})
		_ = g.Add(source.Event{Topic: "info.boot", Message: "boot"})
	}

	now = now.Add(2 * time.Minute)
	g.FlushExpired()

	waitFor(t, func() bool {
		s := out.String()
		return strings.Contains(s, "alert.fire") &&
			strings.Contains(s, "info.boot") &&
			strings.Contains(s, "3 events")
	})
}

func TestGrouperRouterPath(t *testing.T) {
	out := &bufSink{}
	r := New(discardLogger(), nil, nil,
		Route{TopicPattern: "*", Workers: []*sink.Worker{newWorker(t, "out", out)}},
	)
	g, err := newGrouper(50*time.Millisecond, "{{.Topic}}", r.routes[0].Workers)
	if err != nil {
		t.Fatal(err)
	}
	r.routes[0].grouper = g

	src := source.NewStatic([]source.Event{
		{Topic: "x", Message: "1"},
		{Topic: "x", Message: "2"},
		{Topic: "x", Message: "3"},
	})
	if err := r.Run(context.Background(), src); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		g.FlushExpired()
		if strings.Contains(out.String(), "3 events") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("digest never appeared:\n%s", out.String())
}
