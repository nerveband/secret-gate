package requeststate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const SchemaVersion = "1.0"

type Entry struct {
	Token       string `json:"token"`
	SecretName  string `json:"secret_name"`
	Vault       string `json:"vault,omitempty"`
	StatusURL   string `json:"status_url"`
	SubmittedAt string `json:"submitted_at"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Operation   string `json:"operation,omitempty"`
	State       string `json:"state"`
}

type file struct {
	SchemaVersion string  `json:"schema_version"`
	Requests      []Entry `json:"requests"`
}

type Ledger struct {
	path     string
	lockPath string
	dir      string
}

func Open(dir string) (*Ledger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Ledger{path: filepath.Join(dir, "requests.json"), lockPath: filepath.Join(dir, "requests.lock"), dir: dir}, nil
}

func (l *Ledger) Dir() string { return l.dir }

func (l *Ledger) withLock(exclusive bool, fn func() error) error {
	lock, err := os.OpenFile(l.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	if err := unix.Flock(int(lock.Fd()), how); err != nil {
		return err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return fn()
}

func (l *Ledger) load() (*file, error) {
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return &file{SchemaVersion: SchemaVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (l *Ledger) save(f *file) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(l.dir, ".requests-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, l.path); err != nil {
		return err
	}
	dir, err := os.Open(l.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func terminal(state string) bool {
	switch state {
	case "approved", "completed", "denied", "expired", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func (l *Ledger) Put(entry Entry) error {
	return l.withLock(true, func() error {
		f, err := l.load()
		if err != nil {
			return err
		}
		for i := range f.Requests {
			if f.Requests[i].Token == entry.Token {
				if terminal(f.Requests[i].State) && f.Requests[i].State != entry.State {
					return nil
				}
				f.Requests[i] = entry
				return l.save(f)
			}
		}
		f.Requests = append(f.Requests, entry)
		return l.save(f)
	})
}

func (l *Ledger) Get(token string) (entry *Entry, ok bool, err error) {
	err = l.withLock(false, func() error {
		f, loadErr := l.load()
		if loadErr != nil {
			return loadErr
		}
		for i := range f.Requests {
			if f.Requests[i].Token == token {
				copy := f.Requests[i]
				entry, ok = &copy, true
				return nil
			}
		}
		return nil
	})
	return
}

func (l *Ledger) SetState(token, state string) error {
	return l.withLock(true, func() error {
		f, err := l.load()
		if err != nil {
			return err
		}
		for i := range f.Requests {
			if f.Requests[i].Token == token {
				if terminal(f.Requests[i].State) && f.Requests[i].State != state {
					return nil
				}
				f.Requests[i].State = state
				return l.save(f)
			}
		}
		return fmt.Errorf("unknown token %q", token)
	})
}

func (l *Ledger) List() (entries []Entry, err error) {
	err = l.withLock(false, func() error {
		f, loadErr := l.load()
		if loadErr != nil {
			return loadErr
		}
		entries = append([]Entry(nil), f.Requests...)
		return nil
	})
	return
}
