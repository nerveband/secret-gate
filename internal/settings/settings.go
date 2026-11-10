// Package settings holds the few runtime switches the owner flips from
// Telegram with /settings and /set. Environment variables give the defaults;
// a change is an override that is saved to a small JSON file so it survives a
// restart. An override can be cleared with the value "default".
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nerveband/secret-gate/internal/tz"
)

// Setting names.
const (
	TelegramNotifications = "telegram_notifications" // on | silent | off
	OwnerWindows          = "owner_windows"          // on | off
	TapWindows            = "tap_windows"            // on | off
	Timezone              = "timezone"               // IANA name or alias, shown in every message
)

// Alert modes for TelegramNotifications.
const (
	NotifyOn     = "on"
	NotifySilent = "silent"
	NotifyOff    = "off"
)

// Defaults are the values used when no override is set.
type Defaults struct {
	TelegramNotifications string
	OwnerWindows          bool
	TapWindows            bool
	// Timezone is the zone times are shown in; empty means tz.Default.
	Timezone string
}

// Values are the effective settings.
type Values struct {
	TelegramNotifications string `json:"telegram_notifications"`
	OwnerWindows          bool   `json:"owner_windows"`
	TapWindows            bool   `json:"tap_windows"`
	Timezone              string `json:"timezone"`
}

// ErrNotSaved is returned with a successful in-memory change when the file
// could not be written. The change stays in effect until the next restart.
var ErrNotSaved = errors.New("setting applied but not saved")

// Store keeps overrides on top of defaults.
type Store struct {
	mu        sync.RWMutex
	path      string
	defaults  Defaults
	overrides map[string]string
}

// Open loads the overrides saved at path (a missing file means none). An
// empty path keeps everything in memory. The returned store is always
// usable: when the file cannot be read or parsed, it holds only the
// defaults and the error says why, so a damaged file never keeps the gate
// from starting.
func Open(path string, defaults Defaults) (*Store, error) {
	if defaults.TelegramNotifications == "" {
		defaults.TelegramNotifications = NotifyOn
	}
	s := &Store{path: path, defaults: defaults, overrides: map[string]string{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("reading settings: %w", err)
	}
	var saved map[string]string
	if err := json.Unmarshal(data, &saved); err != nil {
		return s, fmt.Errorf("parsing settings %s: %w", path, err)
	}
	for name, value := range saved {
		if normalized, err := normalize(name, value); err == nil {
			s.overrides[name] = normalized
		}
	}
	return s, nil
}

// Get returns the effective settings.
func (s *Store) Get() Values {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.valuesLocked()
}

func (s *Store) valuesLocked() Values {
	v := Values{
		TelegramNotifications: s.defaults.TelegramNotifications,
		OwnerWindows:          s.defaults.OwnerWindows,
		TapWindows:            s.defaults.TapWindows,
		Timezone:              s.defaults.Timezone,
	}
	if v.Timezone == "" {
		v.Timezone = tz.Default
	}
	if o, ok := s.overrides[Timezone]; ok {
		v.Timezone = o
	}
	if o, ok := s.overrides[TelegramNotifications]; ok {
		v.TelegramNotifications = o
	}
	if o, ok := s.overrides[OwnerWindows]; ok {
		v.OwnerWindows = o == "on"
	}
	if o, ok := s.overrides[TapWindows]; ok {
		v.TapWindows = o == "on"
	}
	return v
}

// Persistent reports whether changes are saved to a file.
func (s *Store) Persistent() bool { return s.path != "" }

// Canonical resolves an alias ("alerts", "windows") to a setting name.
func Canonical(name string) (string, bool) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "-", "_")) {
	case "telegram_notifications", "notifications", "alerts", "telegram":
		return TelegramNotifications, true
	case "owner_windows", "phone_windows", "windows":
		return OwnerWindows, true
	case "tap_windows", "taps", "tap":
		return TapWindows, true
	case "timezone", "time_zone", "tz", "zone":
		return Timezone, true
	}
	return "", false
}

// Names lists the settings in display order.
func Names() []string {
	return []string{TelegramNotifications, OwnerWindows, TapWindows, Timezone}
}

// Set changes one setting and returns the new effective values and the
// previous ones. The value "default" clears the override. If the change is
// applied but cannot be saved, the error wraps ErrNotSaved.
func (s *Store) Set(name, value string) (before, after Values, err error) {
	canonical, ok := Canonical(name)
	if !ok {
		return Values{}, Values{}, fmt.Errorf("unknown setting %q (try %s)", name, strings.Join(Names(), ", "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before = s.valuesLocked()
	if strings.EqualFold(strings.TrimSpace(value), "default") {
		delete(s.overrides, canonical)
	} else {
		normalized, err := normalize(canonical, value)
		if err != nil {
			return before, before, err
		}
		s.overrides[canonical] = normalized
	}
	after = s.valuesLocked()
	if err := s.saveLocked(); err != nil {
		return before, after, fmt.Errorf("%w: %v", ErrNotSaved, err)
	}
	return before, after, nil
}

func normalize(name, value string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	switch name {
	case TelegramNotifications:
		switch v {
		case NotifyOn, NotifySilent, NotifyOff:
			return v, nil
		case "true", "1":
			return NotifyOn, nil
		case "false", "0":
			return NotifyOff, nil
		}
		return "", fmt.Errorf("%s must be on, silent, or off", name)
	case OwnerWindows, TapWindows:
		switch v {
		case "on", "true", "1", "yes":
			return "on", nil
		case "off", "false", "0", "no":
			return "off", nil
		}
		return "", fmt.Errorf("%s must be on or off", name)
	case Timezone:
		_, canonical, err := tz.Resolve(value)
		if err != nil {
			return "", err
		}
		return canonical, nil
	}
	return "", fmt.Errorf("unknown setting %q", name)
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.overrides, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Overrides lists the names with an override, sorted, for display.
func (s *Store) Overrides() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.overrides))
	for name := range s.overrides {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
