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

const (
	MaxBackups = 5
	LKGSuffix  = ".lkg"
)

type SaveResult struct {
	NewHash    string   `json:"new_hash"`
	BackupFile string   `json:"backup_file,omitempty"`
	Backups    []string `json:"backups"`
}

// Save validates new bytes, writes them atomically to configPath, and
// creates a timestamped backup. Returns ConflictError if expectedDiskHash
// doesn't match what's on disk (optimistic concurrency).
func Save(configPath string, newBytes []byte, expectedDiskHash string) (*SaveResult, error) {
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
	if err := ValidateBytes(newBytes); err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	backupDir := filepath.Join(filepath.Dir(configPath), "config-backups")
	backupFile, err := saveBackup(backupDir, configPath, currentBytes)
	if err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	if err := rotateBackups(backupDir, MaxBackups); err != nil {
		return nil, fmt.Errorf("rotate backups: %w", err)
	}
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

// ValidateBytes parses bytes as YAML, applies defaults, runs cross-
// reference validation. Returns nil if the config would successfully
// bring up a pipeline (modulo runtime errors like port binding).
func ValidateBytes(b []byte) error {
	cfg := &Config{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	cfg.deprecatedPassword = cfg.Auth.Admin.Password
	cfg.Auth.Admin.Password = ""
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
	cfg.deprecatedPassword = cfg.Auth.Admin.Password
	cfg.Auth.Admin.Password = ""
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	cfg.path = originPath
	cfg.loadedHash = hashBytes(b)
	cfg.Links = filterLinks(cfg.Links)
	return cfg, nil
}

type ConflictError struct {
	Expected string
	Actual   string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("disk hash changed since you started editing: expected %s, got %s", e.Expected, e.Actual)
}

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

func saveBackup(backupDir, configPath string, currentBytes []byte) (string, error) {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", err
	}
	base := filepath.Base(configPath)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	out := filepath.Join(backupDir, fmt.Sprintf("%s.%s.bak", base, stamp))
	return out, os.WriteFile(out, currentBytes, 0o644)
}

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
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

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
