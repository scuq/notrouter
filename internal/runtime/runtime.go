// Package runtime owns the lifecycle of the event-processing pipeline:
// receivers, the seven pipeline stages, and the plugin instances. It is
// designed to be torn down and rebuilt from a new *config.Config without
// restarting the process.
//
// Reload-immune things (the admin server, log buffer, creds store) live
// outside this package - they survive across pipeline rebuilds. The
// admin server holds a *Pipeline pointer that the reloader updates.
package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/dedup"
	"github.com/scuq/notrouter/internal/dispatch"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/parser"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/receivers"
	"github.com/scuq/notrouter/internal/router"
	"github.com/scuq/notrouter/internal/suppress"
)

// Pipeline is one running incarnation of the event flow. Each Build()
// produces a fresh one with its own goroutines, channels, plugin clients,
// and listener sockets.
type Pipeline struct {
	cfg       *config.Config
	pl        *pipeline.Pipeline
	tracker   *dispatch.Tracker
	dedup     *dedup.Deduplicator
	dispatch  *dispatch.Dispatcher
	instances map[string]plugins.Instance

	// Lifecycle bookkeeping. ctx/cancel govern the pipeline goroutines.
	// ioWg tracks the receiver+admin goroutines spawned via Start().
	ctx    context.Context
	cancel context.CancelFunc
	ioWg   sync.WaitGroup
	log    *slog.Logger

	stopped bool
	stopMu  sync.Mutex
}

// Build constructs a pipeline ready to be Start()ed. It performs all the
// allocations and wiring that used to live in main.go's run() function.
// On any error nothing is started and partial allocations are released.
func Build(cfg *config.Config, log *slog.Logger) (*Pipeline, error) {
	instances, err := buildInstances(cfg)
	if err != nil {
		return nil, fmt.Errorf("build plugin instances: %w", err)
	}

	pl := pipeline.New(
		cfg.Pipeline.RawBufferSize,
		cfg.Pipeline.NormalBufferSize,
		cfg.Pipeline.RawBufferSize,
	)

	resolvedCh := make(chan *pipeline.RawEvent, cfg.Pipeline.NormalBufferSize)
	dedupedCh := make(chan *event.Event, cfg.Pipeline.NormalBufferSize)
	suppressedCh := make(chan *event.Event, cfg.Pipeline.NormalBufferSize)

	resolver, err := parser.NewEntityResolver(pl.RawCh, resolvedCh, cfg.Profiles, cfg.Pipeline.ResolverWorkers, log)
	if err != nil {
		closeInstances(instances, log)
		return nil, fmt.Errorf("entity resolver: %w", err)
	}
	normalizer, err := parser.NewNormalizer(resolvedCh, pl.NormalCh, cfg.Profiles, cfg.Pipeline.NormalizerWorkers, log)
	if err != nil {
		closeInstances(instances, log)
		return nil, fmt.Errorf("normalizer: %w", err)
	}
	deduper := dedup.New(pl.NormalCh, dedupedCh, cfg.Dedup.TTL, cfg.Dedup.KeyFields, log)
	suppr, err := suppress.New(dedupedCh, suppressedCh, cfg.Suppressors, cfg.Logging.SuppressorLogThrottle, log)
	if err != nil {
		closeInstances(instances, log)
		return nil, fmt.Errorf("suppressor: %w", err)
	}
	rtr, err := router.New(suppressedCh, pl.DispatchCh, cfg.Routing, cfg.Groups, log)
	if err != nil {
		closeInstances(instances, log)
		return nil, fmt.Errorf("router: %w", err)
	}

	tracker := dispatch.NewTracker(cfg.Dispatch.GlobalDeliveryTTL, log)
	dsp := dispatch.NewDispatcher(
		pl.DispatchCh,
		tracker,
		instances,
		cfg.Dispatch.DefaultRetry,
		cfg.PluginInstances,
		cfg.Pipeline.InstanceBufferSize,
		log,
	)

	pl.AddStage(resolver)
	pl.AddStage(normalizer)
	pl.AddStage(deduper)
	pl.AddStage(suppr)
	pl.AddStage(rtr)
	pl.AddStage(dsp)
	pl.AddStage(tracker)

	return &Pipeline{
		cfg:       cfg,
		pl:        pl,
		tracker:   tracker,
		dedup:     deduper,
		dispatch:  dsp,
		instances: instances,
		log:       log,
	}, nil
}

// Start launches all goroutines: pipeline stages, receivers, and any
// other goroutines this pipeline needs. The receivers bind their listener
// sockets here - if any port is taken, this returns an error and the
// caller can rebuild from LKG without having torn anything down yet.
func (p *Pipeline) Start(parent context.Context) error {
	p.ctx, p.cancel = context.WithCancel(parent)
	p.pl.Start(p.ctx)

	wh := receivers.NewWebhook(p.cfg.Listen.Webhook, p.cfg.Receivers.Webhook.Endpoints, p.pl.RawCh, p.log)
	if err := wh.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		// pipeline.Wait() blocks until stages drain; safe even though we
		// never started any receivers - the pipeline goroutines respect
		// the cancel and exit promptly.
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("webhook receiver: %w", err)
	}
	udp := receivers.NewSyslogUDP(p.cfg.Listen.SyslogUDP, p.pl.RawCh, p.log)
	if err := udp.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("syslog-udp receiver: %w", err)
	}
	tcp := receivers.NewSyslogTCP(p.cfg.Listen.SyslogTCP, p.pl.RawCh, p.log)
	if err := tcp.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("syslog-tcp receiver: %w", err)
	}
	return nil
}

// Stop tears down the pipeline. After Stop returns, all goroutines have
// exited, plugin Close() has been called, and listener sockets have been
// released. Idempotent.
func (p *Pipeline) Stop() {
	p.stopMu.Lock()
	if p.stopped {
		p.stopMu.Unlock()
		return
	}
	p.stopped = true
	p.stopMu.Unlock()

	p.log.Info("pipeline stop: cancelling context")
	p.cancel()

	// Wait for receivers + admin (if any) bound to our wg.
	p.ioWg.Wait()

	// Close the receivers' input channel so the resolver stage exits its
	// for-range loop, which cascades through the pipeline.
	close(p.pl.RawCh)
	p.pl.Wait()

	closeInstances(p.instances, p.log)
	p.log.Info("pipeline stopped")
}

// Probes returns the admin probes for this pipeline. Called by the
// reloader after each successful rebuild so the admin server's
// /admin/state and dashboard reflect the new pipeline.
func (p *Pipeline) Probes() admin.Probes {
	return admin.Probes{
		Dispatch: p.dispatch,
		Dedup:    p.dedup,
		Tracker:  p.tracker,
	}
}

// Config returns the config this pipeline was built from. Used by the
// admin UI to show what's currently running.
func (p *Pipeline) Config() *config.Config { return p.cfg }

func buildInstances(cfg *config.Config) (map[string]plugins.Instance, error) {
	out := make(map[string]plugins.Instance, len(cfg.PluginInstances))
	for name, ic := range cfg.PluginInstances {
		pl, ok := plugins.Get(ic.Type)
		if !ok {
			closeInstances(out, nil)
			return nil, fmt.Errorf("plugin instance %q: unknown type %q", name, ic.Type)
		}
		inst, err := pl.New(name, ic.Config)
		if err != nil {
			closeInstances(out, nil)
			return nil, fmt.Errorf("plugin instance %q: %w", name, err)
		}
		out[name] = inst
	}
	return out, nil
}

func closeInstances(instances map[string]plugins.Instance, log *slog.Logger) {
	for name, inst := range instances {
		if err := inst.Close(); err != nil {
			if log != nil {
				log.Error("close plugin instance", "name", name, "err", err)
			}
		}
	}
}
