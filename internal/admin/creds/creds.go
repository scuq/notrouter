// Package creds manages admin credentials persisted outside of config.yaml.
// The store lives at a configurable path (default /var/lib/notrouter/creds.json)
// so it can be a separate writable volume from the read-only config bind mount.
//
// Schema v3 (current):
//
//	{
//	  "version": 3,
//	  "admin":        {"password_hash": "$2a$...", "must_change": false, "updated_at": "..."},
//	  "oidc":         null | { issuer, client_id, ... },
//	  "users":        {},                  // OIDC users (planned v0.3)
//	  "tokens":       {},                  // API tokens (v0.2.2)
//	  "webhook_keys": {}                   // webhook ingest keys (v0.2.3)
//	}
//
// Schema migrations are read-time and silent:
//   - v0/v1 (no version field) -> v3
//   - v2 (had no webhook_keys) -> v3
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost           = 10
	initialPasswordPlain = "admin"
	CurrentSchemaVersion = 3
)

type Store struct {
	path string
	mu   sync.RWMutex
	data fileShape
}

type fileShape struct {
	Version     int                         `json:"version"`
	Admin       AdminCreds                  `json:"admin"`
	OIDC        *OIDCCreds                  `json:"oidc,omitempty"`
	Users       map[string]UserRecord       `json:"users,omitempty"`
	Tokens      map[string]TokenRecord      `json:"tokens,omitempty"`
	WebhookKeys map[string]WebhookKeyRecord `json:"webhook_keys,omitempty"`
}

type AdminCreds struct {
	PasswordHash string    `json:"password_hash"`
	MustChange   bool      `json:"must_change"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type OIDCCreds struct {
	Issuer        string   `json:"issuer,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	ClientSecret  string   `json:"client_secret,omitempty"`
	RedirectURL   string   `json:"redirect_url,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	UsernameClaim string   `json:"username_claim,omitempty"`
	GroupsClaim   string   `json:"groups_claim,omitempty"`
	AdminGroups   []string `json:"admin_groups,omitempty"`
}

type UserRecord struct {
	Subject     string    `json:"subject"`
	Email       string    `json:"email,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type TokenRecord struct {
	User       string    `json:"user"`
	Label      string    `json:"label,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// WebhookKeyRecord is one minted webhook ingest key. No expiry - they
// live until revoked. CreatedBy is the username that minted it (audit).
type WebhookKeyRecord struct {
	Label      string    `json:"label"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.seedInitial(); err != nil {
			return nil, fmt.Errorf("seed initial creds: %w", err)
		}
		return s, nil
	}
	if s.migrateIfNeeded() {
		if err := s.persist(); err != nil {
			return nil, fmt.Errorf("persist migrated creds: %w", err)
		}
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal(b, &s.data)
}

// migrateIfNeeded handles all version transitions inline. Each version
// bump is a small additive step - we never remove fields from the JSON,
// and unknown fields in older readers just get ignored.
func (s *Store) migrateIfNeeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data.Version >= CurrentSchemaVersion {
		s.ensureMaps()
		return false
	}

	// Any older version -> CurrentSchemaVersion. Maps get ensured below;
	// admin block already has whatever it had before. Future versions
	// would add additional steps here.
	s.data.Version = CurrentSchemaVersion
	s.ensureMaps()
	return true
}

func (s *Store) ensureMaps() {
	if s.data.Users == nil {
		s.data.Users = make(map[string]UserRecord)
	}
	if s.data.Tokens == nil {
		s.data.Tokens = make(map[string]TokenRecord)
	}
	if s.data.WebhookKeys == nil {
		s.data.WebhookKeys = make(map[string]WebhookKeyRecord)
	}
}

func (s *Store) seedInitial() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPasswordPlain), bcryptCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.data = fileShape{
		Version: CurrentSchemaVersion,
		Admin: AdminCreds{
			PasswordHash: string(hash),
			MustChange:   true,
			UpdatedAt:    time.Now().UTC(),
		},
		Users:       make(map[string]UserRecord),
		Tokens:      make(map[string]TokenRecord),
		WebhookKeys: make(map[string]WebhookKeyRecord),
	}
	s.mu.Unlock()
	return s.persist()
}

func (s *Store) persist() error {
	s.mu.RLock()
	b, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".creds-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

func (s *Store) Verify(plain string) bool {
	s.mu.RLock()
	hash := s.data.Admin.PasswordHash
	s.mu.RUnlock()
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

func (s *Store) MustChange() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.MustChange
}

func (s *Store) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.UpdatedAt
}

func (s *Store) SetPassword(newPlain string) error {
	if len(newPlain) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPlain), bcryptCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.data.Admin.PasswordHash = string(hash)
	s.data.Admin.MustChange = false
	s.data.Admin.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()
	return s.persist()
}

func (s *Store) SchemaVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Version
}
