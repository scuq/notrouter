package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
)

type plugin struct{}

func (p *plugin) Type() string { return "file" }

func (p *plugin) New(name string, cfg map[string]interface{}) (plugins.Instance, error) {
	pathRaw, ok := cfg["path"]
	if !ok {
		return nil, fmt.Errorf("file plugin %q: missing 'path'", name)
	}
	path, ok := pathRaw.(string)
	if !ok {
		return nil, fmt.Errorf("file plugin %q: 'path' must be string", name)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("file plugin %q: open %s: %w", name, path, err)
	}
	return &instance{name: name, path: path, f: f}, nil
}

type instance struct {
	name string
	path string
	mu   sync.Mutex
	f    *os.File
}

func (i *instance) Name() string { return i.name }

func (i *instance) Send(ctx context.Context, ev *event.Event) error {
	b, err := json.Marshal(map[string]interface{}{
		"id":         ev.ID,
		"source":     ev.Source,
		"entity":     ev.Entity,
		"topic":      ev.Topic,
		"urgency":    ev.Urgency,
		"timestamp":  ev.Timestamp,
		"attributes": ev.Attributes,
	})
	if err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, err := i.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (i *instance) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.f.Close()
}

func init() { plugins.Register(&plugin{}) }
