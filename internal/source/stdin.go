package source

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/scuq/notrouter/internal/metrics"
)

// Stdin reads JSON-encoded events, one per line, from a Reader.
// It runs until the reader returns EOF or Close is called.
type Stdin struct {
	r       io.Reader
	name    string
	log     *slog.Logger
	metrics *metrics.Metrics
	ch      chan Event
	closeCh chan struct{}
	once    sync.Once
}

type StdinOption func(*Stdin)

func StdinWithMetrics(name string, m *metrics.Metrics) StdinOption {
	return func(s *Stdin) {
		s.name = name
		s.metrics = m
	}
}

func StdinWithLogger(log *slog.Logger) StdinOption {
	return func(s *Stdin) { s.log = log }
}

func StdinWithReader(r io.Reader) StdinOption {
	return func(s *Stdin) { s.r = r }
}

func NewStdin(opts ...StdinOption) *Stdin {
	s := &Stdin{
		r:       os.Stdin,
		ch:      make(chan Event, 64),
		closeCh: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Stdin) Start() error {
	go s.read()
	return nil
}

func (s *Stdin) read() {
	defer close(s.ch)
	scanner := bufio.NewScanner(s.r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		select {
		case <-s.closeCh:
			return
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			if s.log != nil {
				s.log.Warn("stdin source: bad json line", "err", err)
			}
			continue
		}
		if ev.Topic == "" {
			if s.log != nil {
				s.log.Warn("stdin source: line missing topic")
			}
			continue
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now().UTC()
		}
		select {
		case s.ch <- ev:
			if s.metrics != nil {
				s.metrics.EventAccepted(s.name)
			}
		case <-s.closeCh:
			return
		}
	}
}

func (s *Stdin) Events() <-chan Event { return s.ch }

func (s *Stdin) Close() error {
	s.once.Do(func() { close(s.closeCh) })
	return nil
}
