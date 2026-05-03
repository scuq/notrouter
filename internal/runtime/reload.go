package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/scuq/notrouter/internal/admin"
	"github.com/scuq/notrouter/internal/config"
)

// Reloader owns the currently-running Pipeline pointer and serializes
// reload operations. The admin server holds a *Reloader and calls
// Apply() when the operator clicks "reload".
//
// A reload is: validate -> snapshot LKG -> stop old -> build+start new.
// On any failure after stop, we rebuild from LKG. If LKG also fails,
// the process is in a bad state and we return that error to the caller;
// the operator can restart the container (next start will load whatever
// is on disk and try again).
type Reloader struct {
	mu sync.Mutex // serializes reloads

	parent context.Context
	log    *slog.Logger

	currentMu sync.RWMutex
	current   *Pipeline

	// Last-known-good in-memory copy. After a successful reload we
	// promote the new config into LKG. Initial value is the bootstrap
	// config from main().
	lkgMu  sync.RWMutex
	lkgCfg *config.Config

	// Notified after every successful Apply so the admin server can
	// refresh its probe pointers and the displayed loaded-hash.
	subscribers []func(*Pipeline)
}

// NewReloader wires the initial pipeline as both "current" and LKG.
func NewReloader(parent context.Context, log *slog.Logger, initial *Pipeline) *Reloader {
	return &Reloader{
		parent:  parent,
		log:     log,
		current: initial,
		lkgCfg:  initial.Config(),
	}
}

// Subscribe registers a callback that fires after every successful Apply.
// The admin server uses this to refresh its references to the new
// pipeline's probes.
func (r *Reloader) Subscribe(fn func(*Pipeline)) {
	r.subscribers = append(r.subscribers, fn)
}

// Current returns the currently-running pipeline. Cheap read (RWMutex).
func (r *Reloader) Current() *Pipeline {
	r.currentMu.RLock()
	defer r.currentMu.RUnlock()
	return r.current
}

// CurrentConfig returns the *config.Config that produced the current
// pipeline. Used by the admin UI for display.
func (r *Reloader) CurrentConfig() *config.Config {
	return r.Current().Config()
}

// Probes returns the admin probes for the currently-running pipeline.
// After a reload, the pointer the admin server holds is the *Reloader,
// not a *Pipeline - this delegation makes the admin endpoints always
// see the live probes, even immediately after a swap.
func (r *Reloader) Probes() admin.Probes {
	return r.Current().Probes()
}

// LKGConfig returns the last-known-good config. Same as CurrentConfig
// when the running pipeline is healthy; differs only briefly during a
// reload that's in flight.
func (r *Reloader) LKGConfig() *config.Config {
	r.lkgMu.RLock()
	defer r.lkgMu.RUnlock()
	return r.lkgCfg
}

// ReloadResult describes the outcome of an Apply call. Re-using
// admin.ReloadResult avoids two near-identical types.
type ReloadResult = admin.ReloadResult

// Apply tears down the current pipeline and starts a fresh one from
// newCfg. On any failure, rebuilds from LKG. Holds the reload mutex so
// concurrent reloads are serialized.
func (r *Reloader) Apply(newCfg *config.Config) admin.ReloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.log.Info("reload: starting",
		"current_hash", r.CurrentConfig().LoadedHash(),
		"new_hash", newCfg.LoadedHash())

	// Snapshot the current config as LKG before we start tearing things
	// down. This is the rollback target if the new config fails to start.
	r.lkgMu.Lock()
	r.lkgCfg = r.CurrentConfig()
	lkg := r.lkgCfg
	r.lkgMu.Unlock()

	// Stop the current pipeline. Does NOT release sockets that are
	// reload-immune (admin server is separate).
	r.log.Info("reload: stopping current pipeline")
	old := r.Current()
	old.Stop()

	// Build and start the new pipeline.
	if err := r.bringUp(newCfg); err == nil {
		// Success. Promote new config to LKG (already current).
		r.lkgMu.Lock()
		r.lkgCfg = newCfg
		r.lkgMu.Unlock()

		r.log.Info("reload: applied", "hash", newCfg.LoadedHash())
		r.notifySubscribers()
		return admin.ReloadResult{OK: true, AppliedHash: newCfg.LoadedHash()}
	} else {
		r.log.Error("reload: new config failed to start, rolling back to LKG", "err", err)
		// New config failed. Try to rebuild from LKG.
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

// bringUp builds and starts a new pipeline, swaps the current pointer.
// On any failure, returns the error WITHOUT swapping current - caller
// is responsible for retrying with LKG.
func (r *Reloader) bringUp(cfg *config.Config) error {
	p, err := Build(cfg, r.log)
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if err := p.Start(r.parent); err != nil {
		// Build succeeded but Start failed (port bind, etc). Build()
		// already cleaned up its allocations; nothing more to do.
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

// ErrPipelineDown is returned by handlers when the pipeline is in the
// failed-LKG state and operations should be refused.
var ErrPipelineDown = errors.New("pipeline is down (both new config and LKG failed) - container restart required")
