package daemon

import (
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestCardValuesAreCachedForAtMostFifteenMinutes(t *testing.T) {
	c := NewCache()
	c.Store("Visa travel", "AI Agents", map[string]string{"number": "4111111111111111", models.ProcessOnlyKey: "number"}, 12*time.Hour)
	c.Store("deploy key", "AI Agents", map[string]string{"private key": "k"}, 12*time.Hour)
	card, _ := c.Get("Visa travel", "AI Agents")
	other, _ := c.Get("deploy key", "AI Agents")
	if card.RemainingTTL() > models.SensitiveCacheTTL {
		t.Fatalf("card cached for %s", card.RemainingTTL())
	}
	if other.RemainingTTL() < 11*time.Hour {
		t.Fatalf("other items lost their TTL: %s", other.RemainingTTL())
	}
}
