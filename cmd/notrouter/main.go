package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/analyzer"
	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/admin/creds"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/logging"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/runtime"
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

	log, logBuf := logging.New(cfg.Logging.Level)
	log.Info("notrouter starting",
		"version", version.Version,
		"commit", version.Commit,
		"config", configPath,
		"loaded_hash", cfg.LoadedHash(),
		"plugins", plugins.Types())

	if cfg.DeprecatedPasswordSet() {
		log.Warn("auth.admin.password in config.yaml is DEPRECATED and IGNORED",
			"action", "remove this key from your YAML",
			"new_source", cfg.Auth.Admin.CredsPath,
			"how_to_change", "log in to the web UI and use 'change password'")
	}

	credStore, err := creds.Open(cfg.Auth.Admin.CredsPath)
	if err != nil {
		return fmt.Errorf("open creds store: %w", err)
	}
	if credStore.MustChange() {
		log.Warn("admin password is the seed value - login will force a change",
			"creds_path", cfg.Auth.Admin.CredsPath)
	} else {
		log.Info("admin creds loaded",
			"updated_at", credStore.UpdatedAt(),
			"schema_version", credStore.SchemaVersion())
	}

	// Background expired-token sweeper. Runs hourly, logs only when it
	// actually removes something so the log isn't noisy. The returned
	// stop fn is invoked at shutdown to halt the goroutine cleanly.
	stopSweeper := credStore.StartTokenSweeper(func(removed int) {
		if removed > 0 {
			log.Info("expired tokens swept", "count", removed)
		}
	})
	defer stopSweeper()

	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	initial, err := runtime.Build(cfg, log, credStore)
	if err != nil {
		return fmt.Errorf("build initial pipeline: %w", err)
	}
	if err := initial.Start(parentCtx); err != nil {
		return fmt.Errorf("start initial pipeline: %w", err)
	}

	reloader := runtime.NewReloader(parentCtx, log, initial, credStore)

	adm, err := admin.NewWithUI(
		cfg.Listen.Admin,
		cfg.Auth.Admin.Username,
		credStore,
		cfg.Auth.Admin.SessionTTL,
		log,
		reloader,
		cfg.Auth.Admin.CredsPath,
		logBuf,
	)
	if err != nil {
		initial.Stop()
		return fmt.Errorf("build admin: %w", err)
	}

	// v0.3.2: wire the analyzer + audit reader for the replay UI.
	// Audit path matches the file_audit plugin's default. The analyzer
	// is reloader-aware: each request resolves the live pipeline so
	// post-reload pipeline swaps are picked up automatically (same
	// pattern as Probes).
	auditPath := "/var/log/notrouter/audit.jsonl"
	ar := analyzer.NewAuditReader(auditPath)
	an := &liveAnalyzer{reloader: reloader}
	adm.SetAnalyzer(ar, an)

	var adminWg sync.WaitGroup
	if err := adm.Start(parentCtx, &adminWg); err != nil {
		initial.Stop()
		return fmt.Errorf("start admin: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	log.Info("shutdown signal received", "signal", s.String())

	cancelParent()
	adminWg.Wait()
	reloader.Current().Stop()

	log.Info("shutdown complete")
	return nil
}

// liveAnalyzer adapts the reloader to admin.analysisAccessor. Each
// Analyze() call resolves the current Pipeline so post-reload swaps
// are picked up. Lifetime matches the reloader's lifetime.
type liveAnalyzer struct {
	reloader *runtime.Reloader
}

func (l *liveAnalyzer) Analyze(ev *event.Event) analyzer.AnalysisResult {
	pl := l.reloader.Current()
	a := analyzer.New(pl.Router(), pl.Suppressor(), pl.Dedup())
	return a.Analyze(ev)
}
