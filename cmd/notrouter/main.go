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

	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	// Initial pipeline. Build+Start as one unit so a port conflict at
	// startup fails the binary immediately, like it always has.
	initial, err := runtime.Build(cfg, log)
	if err != nil {
		return fmt.Errorf("build initial pipeline: %w", err)
	}
	if err := initial.Start(parentCtx); err != nil {
		return fmt.Errorf("start initial pipeline: %w", err)
	}

	// Reloader manages all subsequent pipeline lifecycle. The admin
	// server holds a reference and uses it for both probes (which point
	// at the live pipeline) and for triggering reloads.
	reloader := runtime.NewReloader(parentCtx, log, initial)

	adm, err := admin.NewWithUI(
		cfg.Listen.Admin,
		cfg.Auth.Admin.Username,
		cfg.Auth.Admin.Password,
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

	// Admin server has its own goroutine accounting because it must
	// survive across pipeline reloads. Use a separate WaitGroup, not
	// the pipeline's.
	var adminWg sync.WaitGroup
	if err := adm.Start(parentCtx, &adminWg); err != nil {
		initial.Stop()
		return fmt.Errorf("start admin: %w", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	s := <-sig
	log.Info("shutdown signal received", "signal", s.String())

	// Shut down: cancel root context (cascades to admin), stop the
	// currently-running pipeline.
	cancelParent()
	adminWg.Wait()
	reloader.Current().Stop()

	log.Info("shutdown complete")
	return nil
}
