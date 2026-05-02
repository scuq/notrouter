package source

import (
	"fmt"
	"log/slog"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/metrics"
)

func Build(cfgs []config.SourceConfig, defaultListen string, log *slog.Logger, m *metrics.Metrics) ([]Source, error) {
	if len(cfgs) == 0 {
		cfgs = []config.SourceConfig{{Name: "http", Type: "http", Listen: defaultListen}}
	}
	sources := make([]Source, 0, len(cfgs))
	for _, c := range cfgs {
		s, err := buildOne(c, defaultListen, log, m)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", c.Name, err)
		}
		sources = append(sources, s)
	}
	return sources, nil
}

func buildOne(c config.SourceConfig, defaultListen string, log *slog.Logger, m *metrics.Metrics) (Source, error) {
	switch c.Type {
	case "http":
		addr := c.Listen
		if addr == "" {
			addr = defaultListen
		}
		opts := []HTTPOption{WithMetrics(c.Name, m)}
		if c.BearerToken != "" {
			opts = append(opts, WithBearerToken(c.BearerToken))
		}
		if c.TLSCert != "" {
			opts = append(opts, WithTLS(c.TLSCert, c.TLSKey))
		}
		if len(c.AllowedTopics) > 0 {
			opts = append(opts, WithAllowedTopics(c.AllowedTopics))
		}
		return NewHTTP(addr, opts...), nil
	case "stdin":
		return NewStdin(
			StdinWithMetrics(c.Name, m),
			StdinWithLogger(log),
		), nil
	default:
		return nil, fmt.Errorf("unknown source type %q", c.Type)
	}
}

type Startable interface {
	Start() error
}

func StartAll(sources []Source) error {
	for _, s := range sources {
		if st, ok := s.(Startable); ok {
			if err := st.Start(); err != nil {
				return err
			}
		}
	}
	return nil
}
