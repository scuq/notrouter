// Package creds manages admin credentials persisted outside of config.yaml.
// The store lives at a configurable path (default /var/lib/notrouter/creds.json)
// so it can be a separate writable volume from the read-only config bind mount.
//
// Schema:
//
//	{
//	  "admin": {
//	    "password_hash": "$2a$10$...",
//	    "must_change": true,
//	    "updated_at": "2026-05-03T12:00:00Z"
//	  },
//	  "oidc": null
//	}
//
// The OIDC slot is reserved for a future iteration. Today it stays nil and
// the file shape is fixed so we don't have to migrate later.
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
	// bcryptCost is the work factor. 10 is the bcrypt default and gives
	// ~60ms verify on modest hardware - fine for admin login frequency,
	// expensive enough to make brute-force attacks infeasible.
	bcryptCost = 10

	// initialPasswordPlain is what the file gets seeded with when missing.
	// MustChange is set so the first login forces a rotation.
	initialPasswordPlain = "admin"
)

// Store is a thread-safe credentials accessor backed by a JSON file.
// Reads are cheap (in-memory); writes acquire the lock and persist.
type Store struct {
	path string
	mu   sync.RWMutex
	data fileShape
}

// fileShape is the exact JSON layout. Keep field tags stable; adding
// fields is fine, renaming requires a migration plan.
type fileShape struct {
	Admin AdminCreds `json:"admin"`
	OIDC  *OIDCCreds `json:"oidc,omitempty"`
}

type AdminCreds struct {
	PasswordHash string    `json:"password_hash"`
	MustChange   bool      `json:"must_change"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OIDCCreds is reserved for future use. Field shape is intentionally
// generic - we'll fill it in once we know exactly what flow we want.
type OIDCCreds struct {
	Issuer       string `json:"issuer,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Open returns a Store, creating the file with default credentials if
// missing. On first run the admin password is "admin" with MustChange=true,
// matching the agreed first-run UX.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := s.load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.seedInitial(); err != nil {
			return nil, fmt.Errorf("seed initial creds: %w", err)
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

func (s *Store) seedInitial() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(initialPasswordPlain), bcryptCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.data = fileShape{
		Admin: AdminCreds{
			PasswordHash: string(hash),
			MustChange:   true,
			UpdatedAt:    time.Now().UTC(),
		},
	}
	s.mu.Unlock()
	return s.persist()
}

// persist writes atomically: write to a temp file in the same dir, then
// rename. This avoids a half-written creds.json if the process is killed
// mid-write, which would lock everyone out.
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
// Constant-time-equivalent via bcrypt's own internals.
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
// The UI uses this to force a redirect to the change-password page.
func (s *Store) MustChange() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.MustChange
}

// UpdatedAt returns when the password was last changed; surfaced on the
// dashboard so operators can spot stale credentials.
func (s *Store) UpdatedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Admin.UpdatedAt
}

// SetPassword updates the admin password, clears MustChange, and persists.
// Caller is responsible for verifying the OLD password first; this function
// trusts that the caller has the right.
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
