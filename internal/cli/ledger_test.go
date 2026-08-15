package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerPutGetSetState(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLedger(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := LedgerEntry{Token: "tok123", SecretName: "deploy-key", Vault: "Infra",
		StatusURL: "http://gate/status/tok123", SubmittedAt: "2026-08-15T12:00:00Z", State: "pending"}
	if err := l.Put(e); err != nil {
		t.Fatal(err)
	}

	got, ok, err := l.Get("tok123")
	if err != nil || !ok || got.SecretName != "deploy-key" {
		t.Fatalf("Get = %+v, %v, %v", got, ok, err)
	}
	if err := l.SetState("tok123", "approved"); err != nil {
		t.Fatal(err)
	}
	got, _, _ = l.Get("tok123")
	if got.State != "approved" {
		t.Fatalf("State = %q", got.State)
	}
	if err := l.SetState("ghost", "cancelled"); err == nil {
		t.Fatal("SetState on unknown token should error")
	}

	info, err := os.Stat(filepath.Join(dir, "requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger perms = %v, want 0600", info.Mode().Perm())
	}
}

func TestLedgerPutReplacesByToken(t *testing.T) {
	l, _ := OpenLedger(t.TempDir())
	_ = l.Put(LedgerEntry{Token: "t1", State: "pending"})
	_ = l.Put(LedgerEntry{Token: "t1", State: "approved"})
	entries, err := l.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].State != "approved" {
		t.Fatalf("entries = %+v", entries)
	}
}
