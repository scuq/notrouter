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
	"github.com/scuq/notrouter/internal/parsers"
	"github.com/scuq/notrouter/internal/trace"
	"github.com/scuq/notrouter/internal/receivers"
	"github.com/scuq/notrouter/internal/router"
	"github.com/scuq/notrouter/internal/suppress"
)

type Pipeline struct {
	cfg       *config.Config
	pl        *pipeline.Pipeline
	tracker   *dispatch.Tracker
	dedup     *dedup.Deduplicator
	suppressor *suppress.Suppressor
	router     *router.Router
	dispatch  *dispatch.Dispatcher
	instances map[string]plugins.Instance

	ctx    context.Context
	cancel context.CancelFunc
	ioWg   sync.WaitGroup
	log    *slog.Logger

	// webhookVerifier is passed into the webhook receiver so it can
	// authenticate incoming POSTs against creds.json webhook keys.
	// Lives at the Pipeline level rather than per-receiver so we can
	// thread it cleanly through Build->Start without growing every
	// receiver's constructor.
	webhookVerifier receivers.WebhookKeyVerifier

	// syslogFilter is the early-drop whitelist applied to raw syslog
	// frames. nil means "filter disabled" (the receivers' Allow() short-
	// circuits on nil receivers, so this is the cheap path).
	syslogFilter *receivers.SyslogFilter

	// syslogFilterStop terminates the periodic summary-log goroutine
	// at pipeline shutdown. nil if the filter is disabled.
	syslogFilterStop func()

	// tracer for debug-mode capture of incoming receiver data. nil if
	// trace is globally disabled (the common case).
	tracer *trace.Tracer

	stopped bool
	stopMu  sync.Mutex
}

// Build constructs a pipeline ready to be Start()ed. The webhookVerifier
// is optional - pass nil to get the legacy "no auth" webhook behavior.
// In production wiring (main.go), main always passes the creds store.
func Build(cfg *config.Config, log *slog.Logger, webhookVerifier receivers.WebhookKeyVerifier) (*Pipeline, error) {
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
	if normalizer != nil {
		normalizer.SetSourceAliases(cfg.SourceAliases)
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
		cfg:             cfg,
		pl:              pl,
		tracker:         tracker,
		dedup:           deduper,
		suppressor:      suppr,
		router:          rtr,
		dispatch:        dsp,
		instances:       instances,
		log:             log,
		webhookVerifier: webhookVerifier,
	}, nil
}

func (p *Pipeline) Start(parent context.Context) error {
	p.ctx, p.cancel = context.WithCancel(parent)
	p.pl.Start(p.ctx)

	// Webhook receiver wiring:
	//   - If we have a verifier, use NewWebhookWithAuth - the receiver
	//     enforces auth based on its own logic (key existence + config flag).
	//   - If verifier is nil (test path), fall back to legacy NewWebhook
	//     so existing test code doesn't break.
	var wh *receivers.WebhookReceiver
	if p.webhookVerifier != nil {
		wh = receivers.NewWebhookWithAuth(
			p.cfg.Listen.Webhook,
			p.cfg.Receivers.Webhook.Endpoints,
			p.pl.RawCh,
			p.log,
			p.webhookVerifier,
			p.cfg.Receivers.Webhook.RequireAuth,
		)
	} else {
		wh = receivers.NewWebhook(p.cfg.Listen.Webhook, p.cfg.Receivers.Webhook.Endpoints, p.pl.RawCh, p.log)
	}
	wh.SetTracer(p.tracer)
	if wh != nil {
		if err := wh.SetTrustedProxies(p.cfg.Receivers.Webhook.TrustedProxies); err != nil {
			p.cancel()
			p.pl.Wait()
			closeInstances(p.instances, p.log)
			return fmt.Errorf("webhook trusted_proxies: %w", err)
		}
	}
	if err := wh.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("webhook receiver: %w", err)
	}
	// Build the trace.Tracer if trace is globally enabled. nil otherwise -
	// receivers' SetTracer is nil-safe so no special handling needed.
	tracer, err := trace.New(p.cfg.Trace, p.log)
	if err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("trace: %w", err)
	}
	p.tracer = tracer

	// Build mail parser registry. nil if no parsers configured - SMTP
	// receiver's Dispatch is nil-safe and falls back to smtp_generic.
	parserRegistry, err := parsers.NewRegistry(p.cfg.MailParsers, p.log)
	if err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("mail parsers: %w", err)
	}

	// Build the syslog early-drop filter from config (if enabled).
	// Nil filter means "pass everything", which is the legacy behavior.
	p.syslogFilter = receivers.NewSyslogFilter(p.cfg.Receivers.Syslog.EarlyFilter, p.log)
	if p.syslogFilter != nil {
		p.syslogFilterStop = p.syslogFilter.StartSummaryLogger()
	}

	udp := receivers.NewSyslogUDPWithFilter(p.cfg.Listen.SyslogUDP, p.pl.RawCh, p.syslogFilter, p.log)
	udp.SetTracer(p.tracer)
	if err := udp.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("syslog-udp receiver: %w", err)
	}
	tcp := receivers.NewSyslogTCPWithFilter(p.cfg.Listen.SyslogTCP, p.pl.RawCh, p.syslogFilter, p.log)
	tcp.SetTracer(p.tracer)
	if err := tcp.Start(p.ctx, &p.ioWg); err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("syslog-tcp receiver: %w", err)
	}

	// SMTP receiver. Disabled by default; only constructed if the config
	// has receivers.smtp.port_25.enabled = true. NewSMTPReceiver returns
	// (nil, nil) when disabled, which we skip cleanly.
	smtp25, err := receivers.NewSMTPReceiver(p.cfg.Receivers.SMTP.Port25, p.pl.RawCh, p.log)
	if smtp25 != nil {
		smtp25.SetTracer(p.tracer)
		smtp25.SetParsers(parserRegistry)
	}
	if err != nil {
		p.cancel()
		p.pl.Wait()
		closeInstances(p.instances, p.log)
		return fmt.Errorf("smtp-25 receiver: %w", err)
	}
	if smtp25 != nil {
		if err := smtp25.Start(p.ctx, &p.ioWg); err != nil {
			p.cancel()
			p.pl.Wait()
			closeInstances(p.instances, p.log)
			return fmt.Errorf("smtp-25 receiver start: %w", err)
		}
	}

	// TCP-JSON receiver. Disabled by default; only constructed if
	// receivers.tcp_json.port_5044.enabled = true. Accepts newline-
	// delimited JSON over a persistent TCP connection. Used by the
	// community.general.logstash Ansible callback (and any other
	// json_lines-over-TCP sender) as a Logstash replacement.
	if p.cfg.Receivers.TCPJSON.Port5044.Enabled {
		tcpJSONRecv, err := receivers.NewTCPJSON(p.cfg.Receivers.TCPJSON.Port5044, p.pl.RawCh, p.log)
		if err != nil {
			p.cancel()
			p.pl.Wait()
			closeInstances(p.instances, p.log)
			return fmt.Errorf("tcp_json receiver: %w", err)
		}
		tcpJSONRecv.SetTracer(p.tracer)
		if err := tcpJSONRecv.Start(p.ctx, &p.ioWg); err != nil {
			p.cancel()
			p.pl.Wait()
			closeInstances(p.instances, p.log)
			return fmt.Errorf("tcp_json receiver start: %w", err)
		}
	}
	return nil
}

func (p *Pipeline) Stop() {
	p.stopMu.Lock()
	if p.stopped {
		p.stopMu.Unlock()
		return
	}
	p.stopped = true
	p.stopMu.Unlock()

	// Stop the filter summary logger first so it gets a final flush
	// before the pipeline tears down. Safe to call when nil.
	if p.syslogFilterStop != nil {
		p.syslogFilterStop()
	}
	p.tracer.Stop()

	p.log.Info("pipeline stop: cancelling context")
	p.cancel()

	p.ioWg.Wait()
	close(p.pl.RawCh)
	p.pl.Wait()

	closeInstances(p.instances, p.log)
	p.log.Info("pipeline stopped")
}

func (p *Pipeline) Probes() admin.Probes {
	return admin.Probes{
		Dispatch: p.dispatch,
		Dedup:    p.dedup,
		Tracker:  p.tracker,
	}
}

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

// Router returns the live router for read-only use by the analyzer.
// Lifetime ends when the pipeline stops.
func (p *Pipeline) Router() *router.Router {
	return p.router
}

// Suppressor returns the live suppressor for read-only use by the
// analyzer.
func (p *Pipeline) Suppressor() *suppress.Suppressor {
	return p.suppressor
}

// Dedup returns the live dedup for read-only use by the analyzer.
func (p *Pipeline) Dedup() *dedup.Deduplicator {
	return p.dedup
}
