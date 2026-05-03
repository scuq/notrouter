// Package creds manages admin credentials persisted outside of config.yaml.
// The store lives at a configurable path (default /var/lib/notrouter/creds.json)
// so it can be a separate writable volume from the read-only config bind mount.
//
// Schema v2 (current):
//
//	{
//	  "version": 2,
//	  "admin": {"password_hash": "$2a$...", "must_change": false, "updated_at": "..."},
//	  "oidc":   null | { issuer, client_id, client_secret, ... },
//	  "users":  {},   // populated by OIDC logins (planned v0.3)
//	  "tokens": {}    // API tokens keyed by sha256(value) (planned v0.2.2)
//	}
//
// Schema v1 (legacy): no "version" field, only "admin" and "oidc".
// Read-time migration upgrades v1 -> v2 silently and writes back, preserving
// the admin entry untouched.
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
	// bcryptCost is the work factor. 10 = ~60ms verify, fine for login,
	// expensive enough vs brute force on a leaked file.
	bcryptCost = 10

	// initialPasswordPlain is what the file gets seeded with when missing.
	initialPasswordPlain = "admin"

	// CurrentSchemaVersion is the version we write. Reads accept v1 (no
	// "version" field) and migrate.
	CurrentSchemaVersion = 2
)

// Store is a thread-safe credentials accessor backed by a JSON file.
type Store struct {
	path string
	mu   sync.RWMutex
	data fileShape
}

// fileShape is the exact JSON layout. New fields are additive; renaming
// requires a schema bump.
type fileShape struct {
	Version int                    `json:"version"`
	Admin   AdminCreds             `json:"admin"`
	OIDC    *OIDCCreds             `json:"oidc,omitempty"`
	Users   map[string]UserRecord  `json:"users,omitempty"`
	Tokens  map[string]TokenRecord `json:"tokens,omitempty"`
}

type AdminCreds struct {
	PasswordHash string    `json:"password_hash"`
	MustChange   bool      `json:"must_change"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OIDCCreds is reserved for future use. Field shape is intentionally
// generic for now - the v0.3 OIDC pass may reshape it.
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

// UserRecord is bookkeeping for an OIDC user. Identity is the OIDC
// subject claim; everything else is informational.
type UserRecord struct {
	Subject     string    `json:"subject"`
	Email       string    `json:"email,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// TokenRecord describes one API token. Keyed in fileShape.Tokens by the
// SHA-256 of the token value (so leaking creds.json doesn't reveal usable
// tokens). Implementation lands in v0.2.2.
type TokenRecord struct {
	User       string    `json:"user"`
	Label      string    `json:"label,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// Open returns a Store, creating the file with default credentials if
// missing. Migrates legacy schemas in-place on first read.
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

	// Successful load. If we read an old-schema file, migrate and persist.
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

// migrateIfNeeded brings older schema versions up to CurrentSchemaVersion.
// Returns true if a migration happened and persist is needed.
//
// v1 (no version field) -> v2: just stamp version and ensure maps exist.
func (s *Store) migrateIfNeeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.data.Version >= CurrentSchemaVersion {
		// Already current. Still ensure maps are non-nil so callers can
		// write directly without nil-check; this isn't a "migration" per
		// se but cheap and harmless.
		s.ensureMaps()
		return false
	}

	// v0/v1 -> v2.
	s.data.Version = 2
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
		Users:  make(map[string]UserRecord),
		Tokens: make(map[string]TokenRecord),
	}
	s.mu.Unlock()
	return s.persist()
}

// persist writes atomically: write to temp + rename. Avoids a half-
// written file locking everyone out if the process is killed mid-write.
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
	defer os.Remove(tmpName) // no-op if rename succeeded

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

// Verify checks a plaintext password against the stored hash.
// Constant-time-equivalent via bcrypt internals.
func (s *Store) Verify(plain string) bool {
	s.mu.RLock()
	hash := s.data.Admin.PasswordHash
	s.mu.RUnlock()
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// MustChange returns whether the admin password is still the seed value.
func (s *Store) MustChange() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.MustChange
}

// UpdatedAt returns when the password was last changed.
func (s *Store) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.UpdatedAt
}

// SetPassword updates the admin password, clears MustChange, persists.
// Caller is responsible for verifying the OLD password first.
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

// SchemaVersion returns the current persisted schema version. Useful for
// tests and the about page.
func (s *Store) SchemaVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Version
}
