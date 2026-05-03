package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxBackups is how many timestamped backup files we retain in the
// config-backups/ directory. Older backups are deleted on each save.
const MaxBackups = 5

// LKGSuffix is appended to the config filename to produce the
// last-known-good copy path. Lives next to the active config.yaml.
const LKGSuffix = ".lkg"

// SaveResult describes the outcome of a Save() call. Returned to the
// UI so the user sees the new disk hash and can confirm what was kept.
type SaveResult struct {
	NewHash    string   `json:"new_hash"`
	BackupFile string   `json:"backup_file,omitempty"`
	Backups    []string `json:"backups"`
}

// Save validates new bytes, writes them atomically to configPath, and
// creates a timestamped backup of the previous version. Returns 409-
// equivalent error if expectedDiskHash doesn't match what's on disk
// (optimistic concurrency check).
//
// This function does NOT load or apply the new config to the pipeline.
// The runtime.Reloader handles that separately via Apply().
func Save(configPath string, newBytes []byte, expectedDiskHash string) (*SaveResult, error) {
	// 1) Optimistic concurrency: read what's on disk now, compare to what
	//    the user said they were editing. If someone else saved in the
	//    meantime, refuse.
	currentBytes, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read current config: %w", err)
	}
	currentHash := hashBytes(currentBytes)
	if expectedDiskHash != "" && expectedDiskHash != currentHash {
		return nil, &ConflictError{
			Expected: expectedDiskHash,
			Actual:   currentHash,
		}
	}

	// 2) Validate the new bytes by parsing them through the same Load()
	//    path we use at startup. This catches YAML errors, missing
	//    references, bad regex, etc. before we touch anything.
	if err := ValidateBytes(newBytes); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	// 3) Make backup of previous version, rotate.
	backupDir := filepath.Join(filepath.Dir(configPath), "config-backups")
	backupFile, err := saveBackup(backupDir, configPath, currentBytes)
	if err != nil {
		// Non-fatal - we'll still try to save, but log via the result.
		// Caller decides what to do.
		return nil, fmt.Errorf("backup: %w", err)
	}
	if err := rotateBackups(backupDir, MaxBackups); err != nil {
		// Also non-fatal.
		return nil, fmt.Errorf("rotate backups: %w", err)
	}

	// 4) Atomic write. Same temp-then-rename pattern as creds.go.
	if err := atomicWrite(configPath, newBytes); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	backups, _ := listBackups(backupDir)

	return &SaveResult{
		NewHash:    hashBytes(newBytes),
		BackupFile: filepath.Base(backupFile),
		Backups:    backups,
	}, nil
}

// ValidateBytes parses bytes as YAML, applies defaults, and runs
// cross-reference validation - the same gauntlet Load() puts the disk
// file through. Returns nil if the config would successfully bring up
// a pipeline (modulo runtime errors like port binding).
func ValidateBytes(b []byte) error {
	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return err
	}
	return nil
}

// LoadFromBytes is like Load() but takes bytes directly. Used by the
// reload handler to build a *Config from the user's submitted YAML
// without hitting disk.
func LoadFromBytes(b []byte, originPath string) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	cfg.path = originPath
	cfg.loadedHash = hashBytes(b)
	cfg.Links = filterLinks(cfg.Links)
	return cfg, nil
}

// ConflictError signals optimistic-concurrency violation on save.
// Admin handler maps this to HTTP 409.
type ConflictError struct {
	Expected string
	Actual   string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("disk hash changed since you started editing: expected %s, got %s", e.Expected, e.Actual)
}

// atomicWrite writes data to path via temp-file + rename. Preserves the
// caller's intended permissions on success (ok if path doesn't exist
// yet, in which case 0o644).
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// saveBackup writes currentBytes to a timestamped file in backupDir,
// returns the path. Created lazily; backup dir is mkdir'd if missing.
func saveBackup(backupDir, configPath string, currentBytes []byte) (string, error) {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", err
	}
	base := filepath.Base(configPath)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", base, stamp))
	return out, os.WriteFile(out, currentBytes, 0o644)
}

// listBackups returns sorted-newest-first basenames of .bak files in
// backupDir. Returns empty slice (no error) if the dir doesn't exist yet.
func listBackups(backupDir string) ([]string, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bak") {
			continue
		}
		out = append(out, e.Name())
	}
	// Filenames embed an ISO timestamp so lexical sort = chronological.
	// Reverse to get newest first.
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// rotateBackups deletes the oldest backups beyond keep. Quiet on
// missing dir - nothing to rotate is fine.
func rotateBackups(backupDir string, keep int) error {
	all, err := listBackups(backupDir)
	if err != nil {
		return err
	}
	if len(all) <= keep {
		return nil
	}
	for _, name := range all[keep:] {
		_ = os.Remove(filepath.Join(backupDir, name))
	}
	return nil
}
