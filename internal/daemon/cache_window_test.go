package daemon

import (
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/models"
)

func TestValuesReleasedUnderAWindowAreNotKeptPastItsEnd(t *testing.T) {
	c := NewCache()
	limit := func(d time.Duration) map[string]string {
		return map[string]string{"credential": "x", models.ExpiresAtKey: time.Now().Add(d).UTC().Format(time.RFC3339)}
	}

	c.Store("late read", "AI Agents", limit(8*time.Minute), 12*time.Hour)
	if entry, _ := c.Get("late read", "AI Agents"); entry.RemainingTTL() > 8*time.Minute+time.Second {
		t.Fatalf("kept %s, past the window end plus grace", entry.RemainingTTL())
	}

	c.Store("after the window", "AI Agents", limit(-time.Minute), 12*time.Hour)
	if entry, ok := c.Get("after the window", "AI Agents"); ok && entry.RemainingTTL() > 2*time.Second {
		t.Fatalf("a value released after its window ended was kept for %s", entry.RemainingTTL())
	}

	c.Store("ordinary", "AI Agents", map[string]string{"credential": "x"}, 12*time.Hour)
	if entry, _ := c.Get("ordinary", "AI Agents"); entry.RemainingTTL() < 11*time.Hour {
		t.Fatalf("ordinary approvals lost their TTL: %s", entry.RemainingTTL())
	}
}

func TestUnreadableWindowLimitKeepsTheValueAsShortAsPossible(t *testing.T) {
	c := NewCache()
	c.Store("odd", "V", map[string]string{"k": "x", models.ExpiresAtKey: "not a time"}, time.Hour)
	if entry, ok := c.Get("odd", "V"); ok && entry.RemainingTTL() > 2*time.Second {
		t.Fatalf("an unreadable limit must not lengthen the cache: %s", entry.RemainingTTL())
	}
}
