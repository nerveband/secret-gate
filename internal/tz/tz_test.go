package tz

import (
	"testing"
	"time"
)

func reset(t *testing.T) {
	t.Helper()
	prev := Name()
	t.Cleanup(func() { _ = Set(prev) })
}

func TestTimesShowInTheChosenZoneWithItsAbbreviation(t *testing.T) {
	reset(t)
	winter := time.Date(2026, 11, 10, 22, 35, 0, 0, time.UTC) // PST
	summer := time.Date(2026, 7, 10, 22, 35, 0, 0, time.UTC)  // PDT
	if err := Set("pst"); err != nil {
		t.Fatal(err)
	}
	if got := Clock(winter); got != "2:35 PM PST" {
		t.Fatalf("winter = %q", got)
	}
	if got := Clock(summer); got != "3:35 PM PDT" {
		t.Fatalf("summer = %q", got)
	}
	if got := HM(winter); got != "2:35 PM" {
		t.Fatalf("HM = %q", got)
	}
	// Midnight and noon are 12 on a 12-hour clock, never 0.
	if got := Clock(time.Date(2026, 11, 10, 8, 5, 0, 0, time.UTC)); got != "12:05 AM PST" {
		t.Fatalf("midnight = %q", got)
	}
	if got := Clock(time.Date(2026, 11, 10, 20, 5, 0, 0, time.UTC)); got != "12:05 PM PST" {
		t.Fatalf("noon = %q", got)
	}
	if err := Set("America/New_York"); err != nil {
		t.Fatal(err)
	}
	if got := Clock(winter); got != "5:35 PM EST" {
		t.Fatalf("eastern = %q", got)
	}
}

func TestAliasesAndNamesResolveAndBadOnesAreRefused(t *testing.T) {
	reset(t)
	for input, want := range map[string]string{
		"PST": "America/Los_Angeles", "pacific": "America/Los_Angeles", "Eastern": "America/New_York",
		"utc": "UTC", "Europe/London": "Europe/London", "  cst ": "America/Chicago",
	} {
		_, got, err := Resolve(input)
		if err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if err := Set("pst"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "Mars/Base", "nowhere"} {
		if err := Set(bad); err == nil {
			t.Errorf("Set(%q) should fail", bad)
		}
	}
	if Name() != "America/Los_Angeles" {
		t.Fatal("a refused zone must not change the one in use")
	}
}

func TestPresetsAreValid(t *testing.T) {
	for _, p := range Presets {
		if _, canonical, err := Resolve(p.Name); err != nil || canonical != p.Name {
			t.Errorf("preset %s: %q, %v", p.Label, canonical, err)
		}
		if Label(p.Name) != p.Label {
			t.Errorf("label for %s", p.Name)
		}
	}
	if Label("Europe/London") != "Europe/London" {
		t.Fatal("non-preset zones label as their IANA name")
	}
}
