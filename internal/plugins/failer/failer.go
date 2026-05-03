// Package failer provides a plugin that always fails. Intended for
// exercising the dispatcher's retry loop, partial-delivery accounting,
// and the 30-min global TTL tracker without needing a real broken endpoint.
//
// Configure a "failer" instance and add it to a group to see partial
// deliveries surface in metrics:
//
//	plugin_instances:
//	  test_failer:
//	    type: failer
//	    config:
//	      mode: always           # "always" | "transient"
//	      transient_after: 3     # for mode=transient: succeed after N tries
package failer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
)

type plugin struct{}

func (p *plugin) Type() string { return "failer" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
	mode := "always"
	if s, ok := cfg["mode"].(string); ok && s != "" {
		mode = s
	}
	transientAfter := 0
	if v, ok := cfg["transient_after"]; ok {
		switch x := v.(type) {
		case int:
			transientAfter = x
		case float64:
			transientAfter = int(x)
		}
	}
	return &instance{name: name, mode: mode, transientAfter: transientAfter}, nil
}

type instance struct {
	name           string
	mode           string
	transientAfter int

	mu       sync.Mutex
	attempts int
}

func (i *instance) Name() string { return i.name }

func (i *instance) Send(ctx context.Context, ev *event.Event) error {
	i.mu.Lock()
	i.attempts++
	n := i.attempts
	i.mu.Unlock()

	switch i.mode {
	case "transient":
		if i.transientAfter > 0 && n >= i.transientAfter {
			return nil
		}
		return fmt.Errorf("failer %q transient failure (attempt %d)", i.name, n)
	default: // "always"
		return errors.New("failer plugin always fails by design")
	}
}

func (i *instance) Close() error { return nil }

func init() { plugins.Register(&plugin{}) }
