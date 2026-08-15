package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LedgerEntry records a submitted approval request so any later
// invocation can resume it (async recovery).
type LedgerEntry struct {
	Token       string `json:"token"`
	SecretName  string `json:"secret_name"`
	Vault       string `json:"vault,omitempty"`
	StatusURL   string `json:"status_url"`
	SubmittedAt string `json:"submitted_at"`
	State       string `json:"state"` // pending|approved|denied|expired|cancelled
}

type ledgerFile struct {
	SchemaVersion string        `json:"schema_version"`
	Requests      []LedgerEntry `json:"requests"`
}

// Ledger persists submitted requests as JSON under the state dir.
// Single-user, read-modify-write; tokens are the primary key.
type Ledger struct {
	path string
}

// OpenLedger ensures the state dir exists (0700) and returns the ledger.
func OpenLedger(dir string) (*Ledger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Ledger{path: filepath.Join(dir, "requests.json")}, nil
}

func (l *Ledger) load() (*ledgerFile, error) {
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return &ledgerFile{SchemaVersion: SchemaVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var f ledgerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (l *Ledger) save(f *ledgerFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.path, data, 0o600)
}

// Put inserts or replaces the entry with the same token.
func (l *Ledger) Put(e LedgerEntry) error {
	f, err := l.load()
	if err != nil {
		return err
	}
	replaced := false
	for i := range f.Requests {
		if f.Requests[i].Token == e.Token {
			f.Requests[i] = e
			replaced = true
			break
		}
	}
	if !replaced {
		f.Requests = append(f.Requests, e)
	}
	return l.save(f)
}

// Get returns the entry for a token.
func (l *Ledger) Get(token string) (*LedgerEntry, bool, error) {
	f, err := l.load()
	if err != nil {
		return nil, false, err
	}
	for i := range f.Requests {
		if f.Requests[i].Token == token {
			return &f.Requests[i], true, nil
		}
	}
	return nil, false, nil
}

// SetState updates the state of an existing entry.
func (l *Ledger) SetState(token, state string) error {
	f, err := l.load()
	if err != nil {
		return err
	}
	for i := range f.Requests {
		if f.Requests[i].Token == token {
			f.Requests[i].State = state
			return l.save(f)
		}
	}
	return fmt.Errorf("unknown token %q", token)
}

// List returns every recorded entry.
func (l *Ledger) List() ([]LedgerEntry, error) {
	f, err := l.load()
	if err != nil {
		return nil, err
	}
	return f.Requests, nil
}
