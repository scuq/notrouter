package pipeline

import (
	"context"
	"sync"

	"github.com/scuq/notrouter/internal/event"
)

// RawEvent carries the receiver-tagged payload before entity resolution.
type RawEvent struct {
	Profile string
	Event   *event.Event
}

// RoutedEvent carries an event plus the resolved set of plugin instance names.
type RoutedEvent struct {
	Event       *event.Event
	Subscribers []string
}

type Pipeline struct {
	RawCh      chan *RawEvent
	NormalCh   chan *event.Event
	DispatchCh chan *RoutedEvent

	stages []Stage
	wg     sync.WaitGroup
}

func New(rawBuf, normalBuf, dispatchBuf int) *Pipeline {
	return &Pipeline{
		RawCh:      make(chan *RawEvent, rawBuf),
		NormalCh:   make(chan *event.Event, normalBuf),
		DispatchCh: make(chan *RoutedEvent, dispatchBuf),
	}
}

func (p *Pipeline) AddStage(s Stage) {
	p.stages = append(p.stages, s)
}

func (p *Pipeline) Start(ctx context.Context) {
	for _, s := range p.stages {
		p.wg.Add(1)
		go s.Run(ctx, &p.wg)
	}
}

func (p *Pipeline) Wait() { p.wg.Wait() }
