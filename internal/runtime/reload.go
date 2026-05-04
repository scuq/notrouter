package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/receivers"
)

type Reloader struct {
	mu sync.Mutex

	parent context.Context
	log    *slog.Logger

	currentMu sync.RWMutex
	current   *Pipeline

	lkgMu  sync.RWMutex
	lkgCfg *config.Config

	subscribers []func(*Pipeline)

	// webhookVerifier is held at the reloader level so every rebuild
	// (initial or post-edit) gets the same verifier reference. The
	// creds store lives outside the pipeline, so swapping the pipeline
	// underneath does not affect token/key lookup.
	webhookVerifier receivers.WebhookKeyVerifier
}

// NewReloader wires the initial pipeline as both "current" and LKG, and
// remembers the webhook verifier to pass into every subsequent Build()
// during reloads.
func NewReloader(parent context.Context, log *slog.Logger, initial *Pipeline, webhookVerifier receivers.WebhookKeyVerifier) *Reloader {
	return &Reloader{
		parent:          parent,
		log:             log,
		current:         initial,
		lkgCfg:          initial.Config(),
		webhookVerifier: webhookVerifier,
	}
}

func (r *Reloader) Subscribe(fn func(*Pipeline)) {
	r.subscribers = append(r.subscribers, fn)
}

func (r *Reloader) Current() *Pipeline {
	r.currentMu.RLock()
	defer r.currentMu.RUnlock()
	return r.current
}

func (r *Reloader) CurrentConfig() *config.Config {
	return r.Current().Config()
}

func (r *Reloader) Probes() admin.Probes {
	return r.Current().Probes()
}

func (r *Reloader) LKGConfig() *config.Config {
	r.lkgMu.RLock()
	defer r.lkgMu.RUnlock()
	return r.lkgCfg
}

type ReloadResult = admin.ReloadResult

func (r *Reloader) Apply(newCfg *config.Config) admin.ReloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.log.Info("reload: starting",
		"current_hash", r.CurrentConfig().LoadedHash(),
		"new_hash", newCfg.LoadedHash())

	r.lkgMu.Lock()
	r.lkgCfg = r.CurrentConfig()
	lkg := r.lkgCfg
	r.lkgMu.Unlock()

	r.log.Info("reload: stopping current pipeline")
	old := r.Current()
	old.Stop()

	if err := r.bringUp(newCfg); err == nil {
		r.lkgMu.Lock()
		r.lkgCfg = newCfg
		r.lkgMu.Unlock()

		r.log.Info("reload: applied", "hash", newCfg.LoadedHash())
		r.notifySubscribers()
		return admin.ReloadResult{OK: true, AppliedHash: newCfg.LoadedHash()}
	} else {
		r.log.Error("reload: new config failed to start, rolling back to LKG", "err", err)
		if lkgErr := r.bringUp(lkg); lkgErr != nil {
			r.log.Error("reload: LKG ALSO FAILED - pipeline is down",
				"new_err", err, "lkg_err", lkgErr)
			return admin.ReloadResult{
				OK:    false,
				Error: fmt.Sprintf("new config failed (%v) AND rollback failed (%v) - pipeline is down, container restart required", err, lkgErr),
			}
		}
		r.log.Warn("reload: rolled back to LKG successfully", "lkg_hash", lkg.LoadedHash())
		r.notifySubscribers()
		return admin.ReloadResult{
			OK:              false,
			Error:           err.Error(),
			RestoredFromLKG: true,
			LKGHash:         lkg.LoadedHash(),
		}
	}
}

func (r *Reloader) bringUp(cfg *config.Config) error {
	p, err := Build(cfg, r.log, r.webhookVerifier)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if err := p.Start(r.parent); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	r.currentMu.Lock()
	r.current = p
	r.currentMu.Unlock()
	return nil
}

func (r *Reloader) notifySubscribers() {
	cur := r.Current()
	for _, fn := range r.subscribers {
		fn(cur)
	}
}

var ErrPipelineDown = errors.New("pipeline is down (both new config and LKG failed) - container restart required")
