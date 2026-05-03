package plugins

import (
	"context"
	"fmt"
	"sync"

	"github.com/scuq/notrouter/internal/event"
)

type Plugin interface {
	Type() string
	New(name string, cfg map[string]interface{}) (Instance, error)
}

type Instance interface {
	Name() string
	Send(ctx context.Context, ev *event.Event) error
	Close() error
}

var (
	regMu    sync.RWMutex
	registry = make(map[string]Plugin)
)

// Register is called from each plugin package's init().
func Register(p Plugin) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, exists := registry[p.Type()]; exists {
		panic(fmt.Sprintf("plugin type %q already registered", p.Type()))
	}
	registry[p.Type()] = p
}

func Get(typeName string) (Plugin, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	p, ok := registry[typeName]
	return p, ok
}

func Types() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	return out
}
