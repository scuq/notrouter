package logging

import (
	"log/slog"
	"os"
	"strings"

	"github.com/scuq/notrouter/internal/logbuffer"
)

// New returns a slog.Logger configured at the requested level, plus the
// in-memory ring buffer of recent entries. The buffer is always populated
// regardless of the logger's level threshold - the UI filters on read,
// not on capture, so debug events are still inspectable when the
// configured level is "info".
func New(level string) (*slog.Logger, *logbuffer.Buffer) {
	lvl := parseLevel(level)
	textHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	buf := logbuffer.New(1000)
	tee := logbuffer.NewTeeHandler(textHandler, buf)
	return slog.New(tee), buf
}

func parseLevel(s string) slog.Leveler {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
