package dispatch

import (
	"context"
	"time"

	"github.com/scuq/notrouter/internal/event"
	"github.com/scuq/notrouter/internal/plugins"
	"github.com/scuq/notrouter/internal/plugins/httpsink"
)

// sendWithRetry runs up to `attempts` Send() calls. The single retry budget
// (Option B from the design discussion) covers all failure causes: network
// errors, 5xx, and 429-with-Retry-After. Non-retryable errors (4xx other
// than 429, or template-render failures) abort immediately so we don't
// burn attempts on something that won't change.
//
// Backoff source per attempt:
//
//   - If the error carries a server-supplied delay (Retry-After), use that.
//   - Otherwise use backoff[attempt-1], or the last entry if past the end.
func sendWithRetry(
	ctx context.Context,
	inst plugins.Instance,
	ev *event.Event,
	attempts int,
	backoff []time.Duration,
) error {
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			delay := backoffFor(attempt-1, backoff)
			if hint, retryable := httpsink.IsRetryable(lastErr); retryable && hint > 0 {
				delay = hint
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := inst.Send(ctx, ev)
		if err == nil {
			return nil
		}

		lastErr = err

		if _, retryable := httpsink.IsRetryable(err); !retryable {
			// 4xx/template-render/etc. - permanent failure, no point retrying.
			return err
		}
	}
	return lastErr
}

func backoffFor(idx int, backoff []time.Duration) time.Duration {
	if len(backoff) == 0 {
		return time.Second
	}
	if idx >= len(backoff) {
		return backoff[len(backoff)-1]
	}
	return backoff[idx]
}
