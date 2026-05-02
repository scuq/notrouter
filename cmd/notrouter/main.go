package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/metrics"
	"github.com/scuq/notrouter/internal/router"
	"github.com/scuq/notrouter/internal/silence"
	"github.com/scuq/notrouter/internal/sink"
	"github.com/scuq/notrouter/internal/source"
	"github.com/scuq/notrouter/internal/version"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("notrouter %s (%s)\n", version.Version, version.Commit)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	log.Info("notrouter starting", "version", version.Version, "commit", version.Commit)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	m := metrics.New()

	workers, workersByName, err := sink.BuildWorkers(cfg.Sinks, log, m)
	if err != nil {
		log.Error("build sinks", "err", err)
		os.Exit(1)
	}

	r, err := router.Build(log, m, cfg, workersByName)
	if err != nil {
		log.Error("build router", "err", err)
		os.Exit(1)
	}
	silences := silence.NewStore()
	r.SetSilences(silences)

	sources, err := source.Build(cfg.Sources, cfg.Listen, log, m)
	if err != nil {
		log.Error("build sources", "err", err)
		os.Exit(1)
	}
	if err := source.StartAll(sources); err != nil {
		log.Error("start sources", "err", err)
		os.Exit(1)
	}
	for _, sc := range cfg.Sources {
		log.Info("source started", "name", sc.Name, "type", sc.Type)
	}
	if len(cfg.Sources) == 0 {
		log.Info("source started", "name", "http", "type", "http", "addr", cfg.Listen)
	}

	var adminSrv *admin.Server
	if cfg.Admin.Listen != "" {
		probes := make([]admin.QueueProbe, 0, len(workers))
		for _, w := range workers {
			w := w
			probes = append(probes, admin.QueueProbe{
				Name:  w.Name(),
				Depth: w.QueueDepth,
			})
		}
		adminSrv = admin.New(cfg.Admin.Listen, m, silences, probes...)
		if err := adminSrv.Start(); err != nil {
			log.Error("start admin", "err", err)
			os.Exit(1)
		}
		log.Info("admin listening", "addr", cfg.Admin.Listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fanin := source.NewFanIn(sources)

	go func() {
		<-ctx.Done()
		log.Info("shutdown signal received, closing sources")
		for _, s := range sources {
			_ = s.Close()
		}
	}()

	if err := r.Run(ctx, fanin); err != nil {
		log.Error("run", "err", err)
		os.Exit(1)
	}

	log.Info("draining sink workers")
	for _, w := range workers {
		w.Stop()
	}
	if adminSrv != nil {
		_ = adminSrv.Close()
	}
	log.Info("notrouter stopped")
}
