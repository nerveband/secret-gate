// Package audit records owner window and settings events. Every event goes
// to the structured server log; when a path is configured it is also appended
// to a JSON-lines file (mode 0600) that survives a container restart. Events
// carry names, ids, and counts, never secret values.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nerveband/secret-gate/internal/logger"
)

// Event names.
const (
	WindowOpenRequested = "window.open_requested"
	WindowOpened        = "window.opened"
	WindowRejected      = "window.rejected"
	WindowUsed          = "window.used"
	WindowNotCovered    = "window.not_covered"
	WindowClosed        = "window.closed"
	SettingsChanged     = "settings.changed"
	TelegramRejected    = "telegram.rejected"
)

// Log writes audit events.
type Log struct {
	mu   sync.Mutex
	path string
	log  *logger.Logger
	now  func() time.Time
}

// New returns a Log that appends to path when it is not empty.
func New(path string) *Log {
	return &Log{path: path, log: logger.New(), now: time.Now}
}

// Event records one event. Fields must not contain secret values.
func (l *Log) Event(name string, fields map[string]any) {
	if l == nil {
		return
	}
	l.log.Info("audit "+name, fields)
	if l.path == "" {
		return
	}
	entry := map[string]any{"ts": l.now().UTC().Format(time.RFC3339), "event": name}
	for k, v := range fields {
		entry[k] = v
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		l.log.Error("Failed to create audit log directory", logger.F("error", err.Error()))
		return
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		l.log.Error("Failed to open audit log", logger.F("error", err.Error()))
		return
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		l.log.Error("Failed to write audit log", logger.F("error", err.Error()))
	}
}
