package source

import "sync"

type FanIn struct {
	sources []Source
	out     chan Event
}

func NewFanIn(sources []Source) *FanIn {
	f := &FanIn{
		sources: sources,
		out:     make(chan Event, 64),
	}
	var wg sync.WaitGroup
	for _, s := range sources {
		wg.Add(1)
		go func(src Source) {
			defer wg.Done()
			for ev := range src.Events() {
				f.out <- ev
			}
		}(s)
	}
	go func() {
		wg.Wait()
		close(f.out)
	}()
	return f
}

func (f *FanIn) Events() <-chan Event { return f.out }

// Close is a no-op; main owns the underlying sources and closes them directly.
func (f *FanIn) Close() error { return nil }
