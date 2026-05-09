package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// AuditReader reads recent events from an audit JSONL file by tailing
// from the end. Cheap even for large files because we only read enough
// bytes to satisfy the requested record count.
//
// Why tail instead of streaming the whole file: audit logs grow
// unbounded; loading a multi-GB file just to show the last 50 events
// is wasteful. Tail-from-end runs in constant memory regardless of
// total file size.
type AuditReader struct {
	path string
}

func NewAuditReader(path string) *AuditReader {
	return &AuditReader{path: path}
}

// AuditEntry is a parsed JSONL record. Kept loose-typed because the
// audit format may evolve and we don't want every change to break the
// reader. The analyzer's EventFromAuditEntry handles the conversion to
// a typed Event.
type AuditEntry map[string]interface{}

// ReadRecent returns up to maxEntries most recent records from the
// audit log, newest first. Returns ([], nil) if the file doesn't exist
// (audit might not be enabled).
//
// Implementation: open file, seek to end, read backwards in chunks,
// scan for newlines, parse each line, stop after maxEntries records.
// Bounded memory regardless of file size.
func (r *AuditReader) ReadRecent(maxEntries int) ([]AuditEntry, error) {
	if maxEntries <= 0 {
		maxEntries = 50
	}

	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	size := stat.Size()
	if size == 0 {
		return []AuditEntry{}, nil
	}

	// Read backwards in 8KB chunks, accumulating until we have
	// enough complete lines OR we hit the start of file.
	const chunkSize int64 = 8 * 1024
	var accumulator []byte
	pos := size
	lineCount := 0
	// Allow some over-read so we get the requested count even if the
	// last chunk has partial line at the start. Cap the read budget
	// to avoid pathological huge-line files.
	maxBytes := int64(maxEntries) * 4096 // assume <4KB avg line
	if maxBytes < 64*1024 {
		maxBytes = 64 * 1024
	}
	bytesRead := int64(0)

	for pos > 0 && lineCount <= maxEntries+5 && bytesRead < maxBytes {
		readSize := chunkSize
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, pos); err != nil && err != io.EOF {
			return nil, fmt.Errorf("read audit log: %w", err)
		}
		// Prepend to accumulator (we're reading backwards).
		accumulator = append(buf, accumulator...)
		bytesRead += readSize
		// Count lines in accumulator.
		lineCount = bytes.Count(accumulator, []byte{'\n'})
	}

	// Split into lines. Accumulator may have a partial first line if
	// we hit our chunk limit; we discard it.
	lines := bytes.Split(accumulator, []byte{'\n'})

	// If we didn't reach pos=0, the FIRST line in accumulator is
	// likely partial (we cut into the middle of a record). Drop it.
	if pos > 0 && len(lines) > 0 {
		lines = lines[1:]
	}

	// Take the LAST maxEntries lines.
	start := 0
	if len(lines) > maxEntries {
		start = len(lines) - maxEntries
	}
	lines = lines[start:]

	// Parse each line as JSON. Skip blanks and parse errors silently
	// (a malformed line shouldn't break the whole list).
	out := make([]AuditEntry, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip malformed line
		}
		out = append(out, entry)
	}

	// Reverse so newest is first - more useful for UI display.
	reversed := make([]AuditEntry, len(out))
	for i, e := range out {
		reversed[len(out)-1-i] = e
	}
	return reversed, nil
}

// FindByID looks up a specific audit entry by its ID. Used by the
// /admin/api/routing/analyze-from-audit endpoint. Reads forward through
// the file until it finds the matching ID. Returns nil if not found.
//
// For very recent IDs this is fast (we'd just hit it via ReadRecent).
// For older IDs this scans the whole file. Acceptable for an admin
// debug tool; if it becomes slow we'd add an index later.
func (r *AuditReader) FindByID(id string) (AuditEntry, error) {
	if id == "" {
		return nil, fmt.Errorf("audit ID required")
	}

	// Try recent first - covers the 90% case cheaply.
	recent, err := r.ReadRecent(200)
	if err != nil {
		return nil, err
	}
	for _, e := range recent {
		if eid, _ := e["id"].(string); eid == id {
			return e, nil
		}
	}

	// Fall back to full scan. For huge files this could be slow but
	// the admin tool doesn't need to be fast on edge cases.
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("audit log not found")
		}
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		var entry AuditEntry
		if err := dec.Decode(&entry); err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("audit ID %q not found", id)
			}
			// Skip malformed records.
			continue
		}
		if eid, _ := entry["id"].(string); eid == id {
			return entry, nil
		}
	}
}
