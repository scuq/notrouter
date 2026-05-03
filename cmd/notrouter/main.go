package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/admin/creds"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/dedup"
	"github.com/scuq/notrouter/internal/dispatch"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/logging"
	"github.com/scuq/notrouter/internal/parser"
	"github.com/scuq/notrouter/internal/pipeline"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/receivers"
	"github.com/scuq/notrouter/internal/router"
	"github.com/scuq/notrouter/internal/suppress"
	"github.com/scuq/notrouter/internal/version"

	_ "github.com/scuq/notrouter/internal/plugins/failer"
	_ "github.com/scuq/notrouter/internal/plugins/file"
	_ "github.com/scuq/notrouter/internal/plugins/stdout"
	_ "github.com/scuq/notrouter/internal/plugins/webex"
	_ "github.com/scuq/notrouter/internal/plugins/webhook"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("notrouter %s (%s)\n", version.Version, version.Commit)
		return
	}

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// logging.New now also returns the in-memory ring buffer; the admin UI
	// reads from it via /admin/api/logs.
	log, logBuf := logging.New(cfg.Logging.Level)
	log.Info("notrouter starting",
		"version", version.Version,
		"commit", version.Commit,
		"config", configPath,
		"loaded_hash", cfg.LoadedHash(),
		"plugins", plugins.Types())

	credStore, err := creds.Open(cfg.Auth.Admin.CredsPath)
	if err != nil {
		return fmt.Errorf("open creds store: %w", err)
	}
	if credStore.MustChange() {
		log.Warn("admin password is the seed value - login will force a change",
			"creds_path", cfg.Auth.Admin.CredsPath)
	} else {
		log.Info("admin creds loaded", "updated_at", credStore.UpdatedAt())
	}

	instances, err := buildInstances(cfg)
	if err != nil {
		return fmt.Errorf("build plugin instances: %w", err)
	}
	defer closeInstances(instances, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
		return fmt.Errorf("build entity resolver: %w", err)
	}
	normalizer, err := parser.NewNormalizer(resolvedCh, pl.NormalCh, cfg.Profiles, cfg.Pipeline.NormalizerWorkers, log)
	if err != nil {
		return fmt.Errorf("build normalizer: %w", err)
	}
	deduper := dedup.New(pl.NormalCh, dedupedCh, cfg.Dedup.TTL, cfg.Dedup.KeyFields, log)
	suppr, err := suppress.New(dedupedCh, suppressedCh, cfg.Suppressors, cfg.Logging.SuppressorLogThrottle, log)
	if err != nil {
		return fmt.Errorf("build suppressor: %w", err)
	}
	rtr, err := router.New(suppressedCh, pl.DispatchCh, cfg.Routing, cfg.Groups, log)
	if err != nil {
		return fmt.Errorf("build router: %w", err)
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

	pl.Start(ctx)

	var ioWg sync.WaitGroup

	if err := startReceivers(ctx, &ioWg, cfg, pl.RawCh, log); err != nil {
		cancel()
		return fmt.Errorf("start receivers: %w", err)
	}

	probes := admin.Probes{
		Dispatch: dsp,
		Dedup:    deduper,
		Tracker:  tracker,
	}
	adm, err := admin.NewWithUI(
		cfg.Listen.Admin,
		cfg.Auth.Admin.Username,
		cfg.Auth.Admin.Password,
		credStore,
		cfg.Auth.Admin.SessionTTL,
		probes,
		log,
		cfg.Path(),
		cfg.LoadedHash(),
		cfg.Links,
		logBuf,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("build admin: %w", err)
	}
	if err := adm.Start(ctx, &ioWg); err != nil {
		cancel()
		return fmt.Errorf("start admin: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	log.Info("shutdown signal received", "signal", s.String())

	cancel()
	ioWg.Wait()
	close(pl.RawCh)
	pl.Wait()

	log.Info("shutdown complete")
	return nil
}

func buildInstances(cfg *config.Config) (map[string]plugins.Instance, error) {
	out := make(map[string]plugins.Instance, len(cfg.PluginInstances))
	for name, ic := range cfg.PluginInstances {
		p, ok := plugins.Get(ic.Type)
		if !ok {
			return nil, fmt.Errorf("plugin instance %q: unknown type %q", name, ic.Type)
		}
		inst, err := p.New(name, ic.Config)
		if err != nil {
			return nil, fmt.Errorf("plugin instance %q: %w", name, err)
		}
		out[name] = inst
	}
	return out, nil
}

func closeInstances(instances map[string]plugins.Instance, log *slog.Logger) {
	for name, inst := range instances {
		if err := inst.Close(); err != nil {
			log.Error("close plugin instance", "name", name, "err", err)
		}
	}
}

func startReceivers(ctx context.Context, wg *sync.WaitGroup, cfg *config.Config, rawCh chan<- *pipeline.RawEvent, log *slog.Logger) error {
	wh := receivers.NewWebhook(cfg.Listen.Webhook, cfg.Receivers.Webhook.Endpoints, rawCh, log)
	if err := wh.Start(ctx, wg); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	udp := receivers.NewSyslogUDP(cfg.Listen.SyslogUDP, rawCh, log)
	if err := udp.Start(ctx, wg); err != nil {
		return fmt.Errorf("syslog-udp: %w", err)
	}
	tcp := receivers.NewSyslogTCP(cfg.Listen.SyslogTCP, rawCh, log)
	if err := tcp.Start(ctx, wg); err != nil {
		return fmt.Errorf("syslog-tcp: %w", err)
	}
	return nil
}
