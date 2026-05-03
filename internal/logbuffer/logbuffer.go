// Package logbuffer is an in-memory ring buffer of recent log lines that
// implements slog.Handler. Wrap your existing handler with NewTeeHandler
// to get the same on-stderr behavior PLUS a queryable buffer for the UI.
//
// The buffer is bounded - oldest entries are dropped silently when the
// ring fills. It's intended for "what just happened" debugging, not
// long-term log storage. Use a real log shipper for that.
package logbuffer

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Entry is a captured log record exposed via the admin API. Seq is a
// monotonically-increasing sequence number used by the UI to fetch only
// lines it hasn't seen yet (?since=<seq>). Time is RFC3339Nano-formatted
// so it serializes uniformly via JSON.
type Entry struct {
	Seq   uint64            `json:"seq"`
	Time  string            `json:"time"`
	Level string            `json:"level"`
	Msg   string            `json:"msg"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Buffer is a thread-safe ring of Entry. Capacity is fixed at construction.
type Buffer struct {
	mu      sync.RWMutex
	entries []Entry
	pos     int    // next-write index
	full    bool   // wrapped at least once
	nextSeq uint64 // never resets, lets clients tail across wraps
}

func New(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Buffer{entries: make([]Entry, capacity)}
}

// Add appends an entry, dropping the oldest if the ring is full. Cheap
// (lock + index update + slice assign).
func (b *Buffer) Add(e Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSeq++
	e.Seq = b.nextSeq
	b.entries[b.pos] = e
	b.pos++
	if b.pos >= len(b.entries) {
		b.pos = 0
		b.full = true
	}
}

// Since returns entries with Seq > since, optionally filtered by minimum
// level and case-insensitive substring search. Results are oldest-first
// so the UI can append in order without sorting.
//
// minLevel uses slog level numerics: "" or "debug" = no filter, "info" =
// info+warn+error, "warn" = warn+error, "error" = error only.
func (b *Buffer) Since(since uint64, minLevel, search string) []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Walk from oldest to newest. If wrapped, oldest is at b.pos; otherwise
	// it's at index 0. Newest is always (b.pos - 1) % len.
	n := len(b.entries)
	count := n
	start := b.pos
	if !b.full {
		count = b.pos
		start = 0
	}

	wantLvl := levelThreshold(minLevel)
	wantSearch := strings.ToLower(search)

	out := make([]Entry, 0, count)
	for i := 0; i < count; i++ {
		e := b.entries[(start+i)%n]
		if e.Seq <= since {
			continue
		}
		if levelOf(e.Level) < wantLvl {
			continue
		}
		if wantSearch != "" && !matches(e, wantSearch) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// HighWaterMark returns the most recent sequence number that has been
// written. The UI uses this to "snap to live" when resuming.
func (b *Buffer) HighWaterMark() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.nextSeq
}

func matches(e Entry, lower string) bool {
	if strings.Contains(strings.ToLower(e.Msg), lower) {
		return true
	}
	for k, v := range e.Attrs {
		if strings.Contains(strings.ToLower(k), lower) ||
			strings.Contains(strings.ToLower(v), lower) {
			return true
		}
	}
	return false
}

func levelOf(s string) int {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return 0
	case "INFO":
		return 1
	case "WARN", "WARNING":
		return 2
	case "ERROR":
		return 3
	}
	return 1 // unknown -> info-equivalent
}

func levelThreshold(s string) int {
	switch strings.ToLower(s) {
	case "", "debug":
		return 0
	case "info":
		return 1
	case "warn", "warning":
		return 2
	case "error":
		return 3
	}
	return 0
}

// TeeHandler implements slog.Handler. It forwards every record to the
// underlying handler (stderr/JSON/whatever) AND captures a copy in the
// ring buffer. We don't pre-filter on level here - the buffer keeps
// everything and filtering happens per-query in Since().
type TeeHandler struct {
	inner slog.Handler
	buf   *Buffer
	attrs []slog.Attr // accumulated WithAttrs context
	group string      // accumulated WithGroup context (rarely used)
}

func NewTeeHandler(inner slog.Handler, buf *Buffer) *TeeHandler {
	return &TeeHandler{inner: inner, buf: buf}
}

// Enabled is delegated entirely to the inner handler. We deliberately
// capture all levels regardless of inner's threshold - debug noise in
// the ring is fine, the UI filters on read.
func (t *TeeHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return true
}

func (t *TeeHandler) Handle(ctx context.Context, r slog.Record) error {
	// Build attrs map from the record's per-call attrs plus any accumulated
	// from WithAttrs(). We materialize values to strings for JSON safety.
	attrs := make(map[string]string, r.NumAttrs()+len(t.attrs))
	for _, a := range t.attrs {
		attrs[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	t.buf.Add(Entry{
		Time:  r.Time.UTC().Format(time.RFC3339Nano),
		Level: r.Level.String(),
		Msg:   r.Message,
		Attrs: attrs,
	})
	return t.inner.Handle(ctx, r)
}

func (t *TeeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(t.attrs)+len(attrs))
	merged = append(merged, t.attrs...)
	merged = append(merged, attrs...)
	return &TeeHandler{
		inner: t.inner.WithAttrs(attrs),
		buf:   t.buf,
		attrs: merged,
		group: t.group,
	}
}

func (t *TeeHandler) WithGroup(name string) slog.Handler {
	return &TeeHandler{
		inner: t.inner.WithGroup(name),
		buf:   t.buf,
		attrs: t.attrs,
		group: name,
	}
}
