package source

import "time"

type Event struct {
	Topic    string    `json:"topic"`
	Message  string    `json:"message"`
	Severity string    `json:"severity,omitempty"`
	Time     time.Time `json:"time,omitempty"`
}

type Source interface {
	Events() <-chan Event
	Close() error
}

type Static struct {
	ch chan Event
}

func NewStatic(events []Event) *Static {
	ch := make(chan Event, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch)
	return &Static{ch: ch}
}

func (s *Static) Events() <-chan Event { return s.ch }
func (s *Static) Close() error         { return nil }
