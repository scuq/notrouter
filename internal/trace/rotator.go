package trace

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// appendWriter is for receivers where many small messages append to the
// same file (syslog, webhook). Rotates on byte-count, keeps a fixed
// number of rotated files. Synchronized for cross-goroutine safety.
type appendWriter struct {
	dir          string
	prefix       string // e.g. "syslog_udp"
	maxBytes     int64
	maxFiles     int
	log          *slog.Logger
	mu           sync.Mutex
	current      *os.File
	currentBytes int64
}

func newAppendWriter(dir, prefix string, maxBytes int64, maxFiles int, log *slog.Logger) (*appendWriter, error) {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024 // 10 MiB
	}
	if maxFiles <= 0 {
		maxFiles = 3
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create dir %s: %w", dir, err)
	}
	w := &appendWriter{
		dir:      dir,
		prefix:   prefix,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		log:      log,
	}
	if err := w.openNew(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *appendWriter) writeJSONL(line []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentBytes+int64(len(line)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
	}

	n, err := w.current.Write(line)
	if err != nil {
		return err
	}
	w.currentBytes += int64(n)
	return nil
}

func (w *appendWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		err := w.current.Close()
		w.current = nil
		return err
	}
	return nil
}

// openNew creates a fresh active file with timestamp-based naming.
// Caller must hold w.mu.
func (w *appendWriter) openNew() error {
	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	name := fmt.Sprintf("%s-%s.jsonl", w.prefix, ts)
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	w.current = f
	w.currentBytes = 0
	return nil
}

// rotate closes the current file, opens a new one, and removes the
// oldest files in excess of maxFiles. Caller must hold w.mu.
func (w *appendWriter) rotate() error {
	if w.current != nil {
		_ = w.current.Close()
		w.current = nil
	}
	if err := w.openNew(); err != nil {
		return err
	}
	w.pruneOld()
	return nil
}

// pruneOld lists files in w.dir matching our prefix, sorts by name (which
// sorts by timestamp), and removes oldest until we have maxFiles total.
// Errors are logged but non-fatal - rotation succeeded, pruning is bonus.
func (w *appendWriter) pruneOld() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.log.Warn("trace prune readdir failed", "dir", w.dir, "err", err)
		return
	}

	matching := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, w.prefix+"-") && strings.HasSuffix(name, ".jsonl") {
			matching = append(matching, name)
		}
	}

	if len(matching) <= w.maxFiles {
		return
	}

	// Filenames sort lexically by timestamp since we use ISO format.
	sort.Strings(matching)
	excess := len(matching) - w.maxFiles
	for i := 0; i < excess; i++ {
		path := filepath.Join(w.dir, matching[i])
		if err := os.Remove(path); err != nil {
			w.log.Warn("trace prune remove failed", "path", path, "err", err)
		}
	}
}
