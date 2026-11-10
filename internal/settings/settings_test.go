package settings

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsApplyUntilAnOverrideIsSet(t *testing.T) {
	s, err := Open("", Defaults{TelegramNotifications: NotifySilent, OwnerWindows: true, TapWindows: true})
	if err != nil {
		t.Fatal(err)
	}
	if v := s.Get(); v.TelegramNotifications != NotifySilent || !v.OwnerWindows || !v.TapWindows {
		t.Fatalf("defaults = %+v", v)
	}
	if _, after, err := s.Set("notifications", "off"); err != nil || after.TelegramNotifications != NotifyOff {
		t.Fatalf("set off: %+v, %v", after, err)
	}
	if _, after, _ := s.Set("telegram_notifications", "default"); after.TelegramNotifications != NotifySilent {
		t.Fatalf("clearing the override should restore the default, got %q", after.TelegramNotifications)
	}
}

func TestOverridesSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "settings.json")
	s, _ := Open(path, Defaults{TapWindows: true})
	if _, _, err := s.Set("tap_windows", "off"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Set("alerts", "silent"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("settings file: %v, %v", info, err)
	}
	reopened, err := Open(path, Defaults{TapWindows: true})
	if err != nil {
		t.Fatal(err)
	}
	if v := reopened.Get(); v.TapWindows || v.TelegramNotifications != NotifySilent {
		t.Fatalf("after restart = %+v", v)
	}
}

func TestRejectsUnknownNamesAndValues(t *testing.T) {
	s, _ := Open("", Defaults{})
	for _, c := range [][2]string{{"colour", "red"}, {"alerts", "loud"}, {"windows", "maybe"}} {
		if _, _, err := s.Set(c[0], c[1]); err == nil {
			t.Errorf("Set(%q, %q) should fail", c[0], c[1])
		}
	}
	if v := s.Get(); v.TelegramNotifications != NotifyOn {
		t.Fatalf("a rejected value changed the setting: %+v", v)
	}
}

func TestUnwritableFileStillAppliesInMemory(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := Open(filepath.Join(blocker, "settings.json"), Defaults{})
	_, after, err := s.Set("windows", "on")
	if !errors.Is(err, ErrNotSaved) || !after.OwnerWindows {
		t.Fatalf("want applied but not saved, got %+v, %v", after, err)
	}
}

func TestDamagedFileGivesDefaultsAndAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, Defaults{TapWindows: true})
	if err == nil || s == nil {
		t.Fatalf("want a usable store and an error, got %v, %v", s, err)
	}
	if v := s.Get(); v.TelegramNotifications != NotifyOn || !v.TapWindows {
		t.Fatalf("defaults expected after a damaged file, got %+v", v)
	}
}
