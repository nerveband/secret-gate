package cli

import (
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/core"
)

func TestRequestSubmitNoWait(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"request", "submit", "--item", "deploy-key",
		"--reason", "deploy the service", "--no-wait"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["token"] != "tok123" || data["state"] != "pending" {
		t.Fatalf("data = %v", data)
	}
	// Token must be resumable from the ledger.
	l, _ := OpenLedger(ta.app.StateDir)
	if _, ok, _ := l.Get("tok123"); !ok {
		t.Fatal("token not recorded in ledger")
	}
}

func TestRequestSubmitMissingReason(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"request", "submit", "--item", "deploy-key"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestRequestSubmitDryRun(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"request", "submit", "--item", "deploy-key",
		"--reason", "deploy", "--dry-run"})
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	l, _ := OpenLedger(ta.app.StateDir)
	if entries, _ := l.List(); len(entries) != 0 {
		t.Fatal("--dry-run wrote to the ledger")
	}
}

func TestRequestSubmitCachedShortCircuit(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["deploy-key"] = map[string]string{"private key": fakeSSHKey}
	code := ta.app.Run([]string{"request", "submit", "--item", "deploy-key", "--reason", "deploy"})
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	data := ta.okEnvelope(t)["data"].(map[string]interface{})
	if data["cached"] != true {
		t.Fatalf("data = %v", data)
	}
}

func TestRequestWaitResumesAndCaches(t *testing.T) {
	ta := newTestApp(t)
	l, _ := OpenLedger(ta.app.StateDir)
	_ = l.Put(LedgerEntry{Token: "tok123", SecretName: "deploy-key", Vault: "Infra",
		StatusURL: "http://gate/status/tok123", State: "pending"})
	ta.proxy.statuses = []core.StatusResult{
		{Status: "pending"},
		{Status: "approved", SecretURL: "http://gate/secret/tok123"},
	}
	code := ta.app.Run([]string{"request", "wait", "tok123", "--timeout", "2s", "--poll-interval", "1ms"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	entry, _, _ := l.Get("tok123")
	if entry.State != "approved" {
		t.Fatalf("ledger state = %q", entry.State)
	}
}

func TestRequestWaitDeniedExitThree(t *testing.T) {
	ta := newTestApp(t)
	l, _ := OpenLedger(ta.app.StateDir)
	_ = l.Put(LedgerEntry{Token: "tok123", SecretName: "deploy-key",
		StatusURL: "http://gate/status/tok123", State: "pending"})
	ta.proxy.statuses = []core.StatusResult{{Status: "denied"}}
	code := ta.app.Run([]string{"request", "wait", "tok123", "--timeout", "1s", "--poll-interval", "1ms"})
	if code != ExitDenied {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestRequestWaitTimeoutExitFour(t *testing.T) {
	ta := newTestApp(t)
	l, _ := OpenLedger(ta.app.StateDir)
	_ = l.Put(LedgerEntry{Token: "tok123", SecretName: "deploy-key",
		StatusURL: "http://gate/status/tok123", State: "pending"})
	// fakeProxy defaults to pending forever
	code := ta.app.Run([]string{"request", "wait", "tok123", "--timeout", "20ms", "--poll-interval", "1ms"})
	if code != ExitExpired {
		t.Fatalf("exit = %d, want 4", code)
	}
	env := ta.errEnvelope(t)
	if !strings.Contains(env.Error.Hint, "request wait tok123") {
		t.Fatalf("hint %q should show the resume command", env.Error.Hint)
	}
}

func TestRequestStatusUnknownTokenExitSix(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"request", "status", "ghost-token"}); code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
}

func TestRequestCancel(t *testing.T) {
	ta := newTestApp(t)
	l, _ := OpenLedger(ta.app.StateDir)
	_ = l.Put(LedgerEntry{Token: "tok123", SecretName: "deploy-key", State: "pending"})
	if code := ta.app.Run([]string{"request", "cancel", "tok123"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	entry, _, _ := l.Get("tok123")
	if entry.State != "cancelled" {
		t.Fatalf("state = %q", entry.State)
	}
}
