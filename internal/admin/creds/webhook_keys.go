// Webhook keys API for the creds Store. Webhook keys are minted as
// "notr_wh_<32 hex>" and stored as sha256(value)->WebhookKeyRecord in
// the creds.json "webhook_keys" map. Like API tokens, the plaintext is
// returned to the operator exactly once at mint time and never persisted.
//
// Differences from API tokens (creds/tokens.go):
//   - No expiry. Keys live until revoked.
//   - No refresh - they never expire.
//   - "wh_" discriminator in the prefix so the webhook receiver
//     and the admin API can't accidentally accept the wrong kind.
//   - LastUsedAt is the only mutating field, throttled-persisted on
//     verify so we don't write to disk on every webhook POST.
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
	// WebhookKeyPrefix has a "wh_" segment to distinguish from API tokens
	// at a glance. Receivers verifying webhook auth check ONLY this
	// namespace; the admin auth middleware checks ONLY the API token
	// namespace. A leaked webhook key cannot be used to access the
	// admin UI or vice versa.
	WebhookKeyPrefix = "notr_wh_"

	// webhookKeyEntropyBytes - 16 bytes hex-encoded = 32 chars = ~128 bits.
	webhookKeyEntropyBytes = 16
)

// WebhookKeyView is the metadata-only shape returned by listing.
type WebhookKeyView struct {
	Hash       string    `json:"hash"`
	Label      string    `json:"label"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// WebhookKeyMintResult is what mint returns - the plaintext is shown
// ONCE in the UI, then thrown away.
type WebhookKeyMintResult struct {
	Key  string         `json:"key"`
	View WebhookKeyView `json:"view"`
}

var (
	ErrWebhookKeyNotFound = errors.New("webhook key not found")
	ErrInvalidWebhookKey  = errors.New("invalid webhook key format")
)

// MintWebhookKey creates a new webhook key with a label. Caller is
// the user that minted it (for audit). Returns the plaintext (caller
// must show it ONCE) plus the metadata view.
func (s *Store) MintWebhookKey(createdBy, label string) (*WebhookKeyMintResult, error) {
	label = strings.TrimSpace(label)
	if err := validateLabel(label); err != nil {
		return nil, err
	}

	plain, err := generateWebhookKeyValue()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	hash := hashWebhookKey(plain)

	rec := WebhookKeyRecord{
		Label:     label,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}

	s.mu.Lock()
	if s.data.WebhookKeys == nil {
		s.data.WebhookKeys = make(map[string]WebhookKeyRecord)
	}
	if _, exists := s.data.WebhookKeys[hash]; exists {
		s.mu.Unlock()
		return nil, errors.New("hash collision (retry)")
	}
	s.data.WebhookKeys[hash] = rec
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return nil, fmt.Errorf("persist: %w", err)
	}

	return &WebhookKeyMintResult{
		Key:  plain,
		View: webhookKeyToView(hash, rec),
	}, nil
}

// VerifyWebhookKey is the hot-path called on every webhook POST. Returns
// nil if the key is valid (exists - no expiry to check). Updates
// LastUsedAt with the same throttled-persist as VerifyToken so we don't
// thrash the disk under high webhook traffic.
func (s *Store) VerifyWebhookKey(plain string) error {
	if !strings.HasPrefix(plain, WebhookKeyPrefix) {
		return ErrInvalidWebhookKey
	}
	hash := hashWebhookKey(plain)
	now := time.Now().UTC()

	s.mu.Lock()
	rec, ok := s.data.WebhookKeys[hash]
	if !ok {
		s.mu.Unlock()
		return ErrWebhookKeyNotFound
	}
	shouldPersist := now.Sub(rec.LastUsedAt) > usePersistThreshold
	rec.LastUsedAt = now
	s.data.WebhookKeys[hash] = rec
	s.mu.Unlock()

	if shouldPersist {
		_ = s.persist()
	}
	return nil
}

// HasAnyWebhookKey reports whether at least one key is configured.
// Used by the receiver to decide whether to enforce auth: if no keys
// exist, the receiver runs in legacy "no auth" mode for backwards
// compatibility. First minted key flips enforcement on.
func (s *Store) HasAnyWebhookKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.WebhookKeys) > 0
}

// ListWebhookKeys returns metadata-only views, sorted newest-first.
func (s *Store) ListWebhookKeys() []WebhookKeyView {
	s.mu.RLock()
	out := make([]WebhookKeyView, 0, len(s.data.WebhookKeys))
	for hash, rec := range s.data.WebhookKeys {
		out = append(out, webhookKeyToView(hash, rec))
	}
	s.mu.RUnlock()

	// Insertion sort by CreatedAt descending. List is small (a handful
	// of webhook keys at most), no need for a full sort import.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].CreatedAt.After(out[j-1].CreatedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// RevokeWebhookKeyByHash deletes a key. Caller is the user (for audit).
// Returns ErrWebhookKeyNotFound if the hash isn't in the map.
func (s *Store) RevokeWebhookKeyByHash(hash string) error {
	s.mu.Lock()
	if _, ok := s.data.WebhookKeys[hash]; !ok {
		s.mu.Unlock()
		return ErrWebhookKeyNotFound
	}
	delete(s.data.WebhookKeys, hash)
	s.mu.Unlock()
	return s.persist()
}

func generateWebhookKeyValue() (string, error) {
	b := make([]byte, webhookKeyEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return WebhookKeyPrefix + hex.EncodeToString(b), nil
}

// hashWebhookKey - same construction as hashToken but kept separate so
// future changes to one namespace don't accidentally affect the other.
func hashWebhookKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func webhookKeyToView(hash string, rec WebhookKeyRecord) WebhookKeyView {
	return WebhookKeyView{
		Hash:       hash,
		Label:      rec.Label,
		CreatedBy:  rec.CreatedBy,
		CreatedAt:  rec.CreatedAt,
		LastUsedAt: rec.LastUsedAt,
	}
}
