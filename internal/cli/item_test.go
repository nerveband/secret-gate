package cli

import (
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/core"
)

func TestItemSearch(t *testing.T) {
	ta := newTestApp(t)
	ta.proxy.searchResults = []core.SearchResultItem{
		{SecretName: "deploy-key", VaultName: "Infra", Score: 0.9, MatchType: "prefix"},
	}
	if code := ta.app.Run([]string{"item", "search", "--query", "deploy"}); code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["count"].(float64) != 1 || env["command"] != "item search" {
		t.Fatalf("env = %v", env)
	}
}

func TestItemSearchMissingQuery(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"item", "search"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestItemFieldsNotFound(t *testing.T) {
	ta := newTestApp(t)
	ta.proxy.fieldsErr = core.E(core.ErrNotFound, "no such item", "")
	if code := ta.app.Run([]string{"item", "fields", "--item", "ghost"}); code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
	if env := ta.errEnvelope(t); env.Error.Code != "not_found" {
		t.Fatalf("error = %+v", env.Error)
	}
}

func TestItemReadRequiresReveal(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	if code := ta.app.Run([]string{"item", "read", "--item", "prod-api"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if ta.stdout.Len() != 0 {
		t.Fatalf("value leaked to stdout without --reveal: %q", ta.stdout.String())
	}
	env := ta.errEnvelope(t)
	if !strings.Contains(env.Error.Hint, "exec") {
		t.Fatalf("hint %q should point to exec", env.Error.Hint)
	}
}

func TestItemReadWithReveal(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	code := ta.app.Run([]string{"item", "read", "--item", "prod-api", "--fields", "credential", "--reveal"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	meta := env["meta"].(map[string]interface{})
	if meta["visibility"] != "model-visible" {
		t.Fatalf("visibility = %v", meta["visibility"])
	}
	fields := env["data"].(map[string]interface{})["fields"].(map[string]interface{})
	if fields["credential"] != "fake-api-key-123456" {
		t.Fatalf("fields = %v", fields)
	}
}

func TestItemReadNotCached(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"item", "read", "--item", "ghost", "--reveal"}); code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
	if !strings.Contains(ta.errEnvelope(t).Error.Hint, "request submit") {
		t.Fatal("hint should point to request submit")
	}
}
