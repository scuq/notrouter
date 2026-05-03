// Tokens API for the creds Store. Tokens are minted as
// "notr_<32 hex chars>" and stored as sha256(value)->TokenRecord in
// the creds.json "tokens" map. The plaintext value is returned to the
// caller exactly once at mint time and never persisted; we store only
// the hash, so leaking creds.json does not yield usable tokens.
//
// Lifecycle:
//   - Mint: 14 day expiry by default
//   - Refresh: extends expiry to now+14d, callable while still valid
//   - Use: bumps last_used_at (throttled persist, see throttle logic)
//   - Expire: rejected at validate time; swept by the periodic cleaner

package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenPrefix is what every minted token starts with - useful for
	// detecting accidentally-pasted tokens in logs/configs and for users
	// to recognize the format.
	TokenPrefix = "notr_"

	// tokenEntropyBytes is the random portion (hex-encoded -> 2x chars).
	// 16 bytes -> 32 hex -> ~128 bits of entropy. More than enough.
	tokenEntropyBytes = 16

	// TokenLifetime is the duration a freshly-minted (or refreshed) token
	// stays valid. Operators refresh within this window to extend.
	TokenLifetime = 14 * 24 * time.Hour

	// MinLabelLen and MaxLabelLen bound the user-supplied label.
	MinLabelLen = 3
	MaxLabelLen = 50

	// usePersistThreshold is how stale last_used_at can get in memory
	// before a Use() triggers a disk write. One minute keeps the file
	// reasonably current without writing on every API call.
	usePersistThreshold = time.Minute
)

// TokenView is the metadata-only shape returned by ListTokens. The hash
// is included so the UI can build refresh/revoke URLs against a stable
// identifier without exposing the token value.
type TokenView struct {
	Hash       string    `json:"hash"`
	User       string    `json:"user"`
	Label      string    `json:"label"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	Expired    bool      `json:"expired"`
}

// MintResult bundles what a fresh mint operation returns. The Token
// field is the plaintext value - this is the ONE TIME the caller will
// see it. The Hash matches what's now stored in tokens map.
type MintResult struct {
	Token string    `json:"token"`
	View  TokenView `json:"view"`
}

// Errors returned by token operations. Callers compare with errors.Is
// to map to HTTP statuses.
var (
	ErrTokenNotFound  = errors.New("token not found")
	ErrTokenExpired   = errors.New("token expired")
	ErrInvalidLabel   = errors.New("invalid label")
	ErrInvalidToken   = errors.New("invalid token format")
	ErrTokenForbidden = errors.New("token does not belong to user")
)

// MintToken creates a new token for user with the given label. Returns
// the plaintext (caller must show ONCE) plus the metadata view.
func (s *Store) MintToken(user, label string) (*MintResult, error) {
	label = strings.TrimSpace(label)
	if err := validateLabel(label); err != nil {
		return nil, err
	}
	if user == "" {
		return nil, errors.New("user is required")
	}

	plain, err := generateTokenValue()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	hash := hashToken(plain)

	rec := TokenRecord{
		User:      user,
		Label:     label,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(TokenLifetime),
	}

	s.mu.Lock()
	if s.data.Tokens == nil {
		s.data.Tokens = make(map[string]TokenRecord)
	}
	// Hash collision is astronomically unlikely (sha256 + 128b input).
	// Belt-and-suspenders: refuse instead of silently overwriting.
	if _, exists := s.data.Tokens[hash]; exists {
		s.mu.Unlock()
		return nil, errors.New("hash collision (retry)")
	}
	s.data.Tokens[hash] = rec
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return nil, fmt.Errorf("persist: %w", err)
	}

	return &MintResult{
		Token: plain,
		View:  recordToView(hash, rec),
	}, nil
}

// VerifyToken looks up the bearer token and returns the owner's username
// if the token is valid (exists and not expired). On success it also
// updates last_used_at, persisting iff the previous in-memory timestamp
// was older than usePersistThreshold (throttle). On expired it returns
// ErrTokenExpired (the caller should 401 the request).
func (s *Store) VerifyToken(plain string) (string, error) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return "", ErrInvalidToken
	}
	hash := hashToken(plain)
	now := time.Now().UTC()

	s.mu.Lock()
	rec, ok := s.data.Tokens[hash]
	if !ok {
		s.mu.Unlock()
		return "", ErrTokenNotFound
	}
	if now.After(rec.ExpiresAt) {
		s.mu.Unlock()
		return "", ErrTokenExpired
	}

	// Throttled persist: only write to disk if the in-memory last_used
	// drifts past the threshold. Otherwise just update memory.
	shouldPersist := now.Sub(rec.LastUsedAt) > usePersistThreshold
	rec.LastUsedAt = now
	s.data.Tokens[hash] = rec
	user := rec.User
	s.mu.Unlock()

	if shouldPersist {
		// Best-effort: a persist failure must not block valid auth, so
		// we log via stderr rather than returning the error. (The Store
		// doesn't carry a logger; main.go logs Open/SetPassword issues
		// since those are user-blocking.)
		_ = s.persist()
	}
	return user, nil
}

// RefreshTokenByHash extends a token's expiry to now+TokenLifetime.
// The token must currently be valid (not expired). Used by the UI's
// "refresh" button next to each token in the list - the UI knows the
// hash but never sees the plaintext.
func (s *Store) RefreshTokenByHash(hash, requestingUser string) (*TokenView, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	rec, ok := s.data.Tokens[hash]
	if !ok {
		s.mu.Unlock()
		return nil, ErrTokenNotFound
	}
	if requestingUser != "" && rec.User != requestingUser {
		s.mu.Unlock()
		return nil, ErrTokenForbidden
	}
	if now.After(rec.ExpiresAt) {
		s.mu.Unlock()
		return nil, ErrTokenExpired
	}
	rec.ExpiresAt = now.Add(TokenLifetime)
	s.data.Tokens[hash] = rec
	view := recordToView(hash, rec)
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return nil, fmt.Errorf("persist: %w", err)
	}
	return &view, nil
}

// RefreshTokenSelf is the script-friendly variant: caller authenticates
// with the token itself, server hashes it to find the record, extends.
// This is what /admin/api/tokens/refresh-self uses for monitoring scripts
// that need to keep themselves alive.
func (s *Store) RefreshTokenSelf(plain string) (*TokenView, error) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return nil, ErrInvalidToken
	}
	hash := hashToken(plain)
	// Refresh-self bypasses the user-match check because possessing the
	// token IS the proof of identity here.
	return s.RefreshTokenByHash(hash, "")
}

// RevokeTokenByHash deletes a token. Used by the UI's "revoke" button.
// Authorization: requestingUser must match (or be empty for "admin
// override"). For v0.2.2 only "admin" exists, so this is moot, but the
// scoping is in place for v0.3 OIDC.
func (s *Store) RevokeTokenByHash(hash, requestingUser string) error {
	s.mu.Lock()
	rec, ok := s.data.Tokens[hash]
	if !ok {
		s.mu.Unlock()
		return ErrTokenNotFound
	}
	if requestingUser != "" && rec.User != requestingUser {
		s.mu.Unlock()
		return ErrTokenForbidden
	}
	delete(s.data.Tokens, hash)
	s.mu.Unlock()

	return s.persist()
}

// ListTokens returns metadata-only views. If user is empty, returns all
// tokens (admin scope); otherwise filters to that user's tokens. Sorted
// by CreatedAt descending so newest are on top.
func (s *Store) ListTokens(user string) []TokenView {
	s.mu.RLock()
	out := make([]TokenView, 0, len(s.data.Tokens))
	now := time.Now().UTC()
	for hash, rec := range s.data.Tokens {
		if user != "" && rec.User != user {
			continue
		}
		v := recordToView(hash, rec)
		v.Expired = now.After(rec.ExpiresAt)
		out = append(out, v)
	}
	s.mu.RUnlock()

	// Newest first. We use a basic insertion-style sort because the
	// list is tiny (a few dozen at most) and we don't want to import
	// sort just for this.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CreatedAt.After(out[j-1].CreatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// SweepExpired removes tokens past their ExpiresAt. Returns the number
// removed. Persists if anything changed. Called by the background
// goroutine in StartTokenSweeper.
func (s *Store) SweepExpired() int {
	now := time.Now().UTC()
	s.mu.Lock()
	removed := 0
	for hash, rec := range s.data.Tokens {
		if now.After(rec.ExpiresAt) {
			delete(s.data.Tokens, hash)
			removed++
		}
	}
	s.mu.Unlock()

	if removed > 0 {
		_ = s.persist()
	}
	return removed
}

// StartTokenSweeper kicks off a background goroutine that calls
// SweepExpired periodically. Returns a stop function the caller invokes
// at shutdown. The interval is hard-coded to 1 hour - if you have so
// many tokens that hourly sweep matters, you have other problems.
//
// The optional onSweep callback fires after each sweep with the count
// removed; main() uses it to log non-zero sweeps. nil callback is fine.
func (s *Store) StartTokenSweeper(onSweep func(removed int)) func() {
	const interval = time.Hour
	stopCh := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				removed := s.SweepExpired()
				if onSweep != nil {
					onSweep(removed)
				}
			case <-stopCh:
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// generateTokenValue produces a "notr_<32 hex>" string from cryptographic
// randomness. crypto/rand failures are practically impossible on a
// healthy system but we propagate them anyway.
func generateTokenValue() (string, error) {
	b := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return TokenPrefix + hex.EncodeToString(b), nil
}

// hashToken returns the hex sha256 of the plaintext - this is the map
// key in the tokens table. Sha256 is fast (~100ns per call); we don't
// need bcrypt here because the token IS its own entropy.
func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func validateLabel(label string) error {
	if len(label) < MinLabelLen {
		return fmt.Errorf("%w: at least %d characters required", ErrInvalidLabel, MinLabelLen)
	}
	if len(label) > MaxLabelLen {
		return fmt.Errorf("%w: at most %d characters", ErrInvalidLabel, MaxLabelLen)
	}
	if strings.ContainsAny(label, "\n\r\t") {
		return fmt.Errorf("%w: no control characters", ErrInvalidLabel)
	}
	return nil
}

func recordToView(hash string, rec TokenRecord) TokenView {
	return TokenView{
		Hash:       hash,
		User:       rec.User,
		Label:      rec.Label,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		LastUsedAt: rec.LastUsedAt,
	}
}
