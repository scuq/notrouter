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

// perMessageWriter is for SMTP: one .eml file per accepted message.
// No rotation by byte count - rotation is "delete oldest when count
// exceeds maxFiles." Filename includes timestamp + sanitized from
// address so operators can find specific messages by inspection.
type perMessageWriter struct {
	dir      string
	maxFiles int
	log      *slog.Logger
	mu       sync.Mutex // serializes writes to keep filename uniqueness
	counter  int        // disambiguates messages within the same nanosecond
}

func newPerMessageWriter(dir string, maxFiles int, log *slog.Logger) *perMessageWriter {
	if maxFiles <= 0 {
		maxFiles = 50
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Warn("trace smtp dir create failed", "dir", dir, "err", err)
	}
	return &perMessageWriter{
		dir:      dir,
		maxFiles: maxFiles,
		log:      log,
	}
}

func (w *perMessageWriter) write(fromAddr string, body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Filename: 2026-05-05T03-15-22.124Z-from-<sanitized>.eml
	// The counter handles the rare case of two messages in the same
	// nanosecond from the same sender (test scripts can do that).
	w.counter++
	ts := time.Now().UTC().Format("2006-01-02T15-04-05.000Z")
	safeFrom := sanitizeForFilename(fromAddr)
	name := fmt.Sprintf("%s-%s-c%d.eml", ts, safeFrom, w.counter)
	path := filepath.Join(w.dir, name)

	if err := os.WriteFile(path, body, 0600); err != nil {
		return fmt.Errorf("smtp trace write %s: %w", path, err)
	}

	w.pruneOld()
	return nil
}

func (w *perMessageWriter) close() {
	// No-op - we don't keep open file handles per-message.
}

func (w *perMessageWriter) pruneOld() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		w.log.Warn("trace prune readdir failed", "dir", w.dir, "err", err)
		return
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".eml") {
			files = append(files, e.Name())
		}
	}

	if len(files) <= w.maxFiles {
		return
	}

	// Sort lexically. Since filenames start with ISO timestamps, oldest
	// sorts first.
	sort.Strings(files)
	excess := len(files) - w.maxFiles
	for i := 0; i < excess; i++ {
		path := filepath.Join(w.dir, files[i])
		if err := os.Remove(path); err != nil {
			w.log.Warn("trace prune remove failed", "path", path, "err", err)
		}
	}
}

// sanitizeForFilename replaces filesystem-unfriendly characters from an
// email address. Keeps the result roughly recognizable: foo@bar.com
// becomes foo_at_bar.com. Truncates at 64 chars to avoid pathological
// filenames from misconfigured senders.
func sanitizeForFilename(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '-', c == '_':
			out = append(out, c)
		case c == '@':
			out = append(out, '_', 'a', 't', '_')
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}
