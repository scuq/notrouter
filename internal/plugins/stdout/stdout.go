package stdout

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
)

type plugin struct{}

func (p *plugin) Type() string { return "stdout" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
	return &instance{name: name}, nil
}

type instance struct {
	name string
}

func (i *instance) Name() string { return i.name }

func (i *instance) Send(ctx context.Context, ev *event.Event) error {
	b, _ := json.Marshal(map[string]interface{}{
		"id":         ev.ID,
		"source":     ev.Source,
		"entity":     ev.Entity,
		"topic":      ev.Topic,
		"urgency":    ev.Urgency,
		"timestamp":  ev.Timestamp,
		"attributes": ev.Attributes,
	})
	fmt.Fprintf(os.Stdout, "[%s] %s\n", i.name, b)
	return nil
}

func (i *instance) Close() error { return nil }

func init() { plugins.Register(&plugin{}) }
