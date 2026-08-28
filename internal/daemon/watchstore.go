package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type watchStore struct {
	mu   sync.Mutex
	path string
}

type watchStoreFile struct {
	Watches []WatchSpec `json:"watches"`
}

func newWatchStore(path string) *watchStore { return &watchStore{path: path} }

func (s *watchStore) load() ([]WatchSpec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var file watchStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]WatchSpec, 0, len(file.Watches))
	for _, spec := range file.Watches {
		if spec.ExpiresAt != "" {
			expires, err := time.Parse(time.RFC3339, spec.ExpiresAt)
			if err == nil && !expires.After(now) {
				continue
			}
		}
		out = append(out, spec)
	}
	return out, nil
}

func (s *watchStore) save(specs []WatchSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(watchStoreFile{Watches: specs})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".secret-gate-watches-*")
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
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
