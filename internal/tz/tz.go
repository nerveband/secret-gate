// Package tz holds the time zone used to show times to the owner in
// Telegram, PushWard, and the entry page. Servers usually run in UTC, which
// is hard to read on a phone; the owner picks a zone (TIMEZONE, or
// /set timezone) and every message shows its local time.
package tz

import (
	"fmt"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // zone data inside the binary: minimal container images have none
)

// Default is the zone used when none is configured.
const Default = "America/Los_Angeles"

// Preset is a zone offered as a button.
type Preset struct{ Label, Name string }

// Presets are the zones the settings panel offers as buttons. Any other IANA
// name works with /set timezone.
var Presets = []Preset{
	{"Pacific", "America/Los_Angeles"},
	{"Mountain", "America/Denver"},
	{"Central", "America/Chicago"},
	{"Eastern", "America/New_York"},
	{"UTC", "UTC"},
}

var aliases = map[string]string{
	"pst": "America/Los_Angeles", "pdt": "America/Los_Angeles", "pt": "America/Los_Angeles", "pacific": "America/Los_Angeles",
	"mst": "America/Denver", "mdt": "America/Denver", "mt": "America/Denver", "mountain": "America/Denver",
	"cst": "America/Chicago", "cdt": "America/Chicago", "ct": "America/Chicago", "central": "America/Chicago",
	"est": "America/New_York", "edt": "America/New_York", "et": "America/New_York", "eastern": "America/New_York",
	"utc": "UTC", "gmt": "UTC",
}

var (
	mu   sync.RWMutex
	loc  = time.UTC
	name = "UTC"
)

// Resolve turns a name or alias ("pst", "Eastern", "Europe/London") into a
// location and its canonical IANA name.
func Resolve(input string) (*time.Location, string, error) {
	key := strings.TrimSpace(input)
	if key == "" {
		return nil, "", fmt.Errorf("time zone is empty")
	}
	if canonical, ok := aliases[strings.ToLower(key)]; ok {
		key = canonical
	}
	l, err := time.LoadLocation(key)
	if err != nil {
		return nil, "", fmt.Errorf("unknown time zone %q (use a name like America/Los_Angeles, or pst, mst, cst, est, utc)", input)
	}
	return l, l.String(), nil
}

// Set makes name the zone every message uses.
func Set(input string) error {
	l, canonical, err := Resolve(input)
	if err != nil {
		return err
	}
	mu.Lock()
	loc, name = l, canonical
	mu.Unlock()
	return nil
}

// Name returns the IANA name of the zone in use.
func Name() string {
	mu.RLock()
	defer mu.RUnlock()
	return name
}

func location() *time.Location {
	mu.RLock()
	defer mu.RUnlock()
	return loc
}

// Clock formats t in the owner's zone on a 12-hour clock with the zone
// abbreviation: "2:35 PM PST".
func Clock(t time.Time) string { return t.In(location()).Format("3:04 PM MST") }

// HM formats t in the owner's zone on a 12-hour clock: "2:35 PM".
func HM(t time.Time) string { return t.In(location()).Format("3:04 PM") }

// Label returns a short human name for a canonical zone: "Pacific" for the
// presets, the IANA name otherwise.
func Label(canonical string) string {
	for _, p := range Presets {
		if p.Name == canonical {
			return p.Label
		}
	}
	return canonical
}
