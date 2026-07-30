package autosession

import (
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestStoreMatchesAllRequestsWithinTTL(t *testing.T) {
	store := NewStore()
	session := store.Create("ashraf", 30*time.Minute)

	matched, ok := store.Match()
	if !ok {
		t.Fatal("expected matching request to be auto-approved")
	}
	if matched.ID != session.ID {
		t.Fatalf("matched session ID = %q, want %q", matched.ID, session.ID)
	}
	if matched.Approver != "ashraf" {
		t.Fatalf("matched approver = %q, want ashraf", matched.Approver)
	}
}

func TestStoreWindowCoversDifferentMachineIPAndSecret(t *testing.T) {
	store := NewStore()
	store.Create("ashraf", 30*time.Minute)

	requests := []*models.ApprovalRequest{
		request("other-mac", "10.0.0.9", []models.SecretRequest{
			{SecretName: "other-key", Vault: "Other Vault", Fields: []string{"password"}},
		}),
		request("agent-mac", "10.0.0.5", []models.SecretRequest{
			{SecretName: "deploy-key", Vault: "AI Agents", Fields: []string{"private key"}},
		}),
	}

	for _, req := range requests {
		if _, ok := store.Match(); !ok {
			t.Fatalf("request from %s for %s should match the global window", req.RequesterMachine, req.SecretName)
		}
	}
}

func TestStoreExpiresSessions(t *testing.T) {
	store := NewStore()
	store.Create("ashraf", -time.Second)

	if _, ok := store.Match(); ok {
		t.Fatal("expired session should not match")
	}
}

func request(machine, ip string, secrets []models.SecretRequest) *models.ApprovalRequest {
	return &models.ApprovalRequest{
		SecretName:       secrets[0].SecretName,
		Vault:            secrets[0].Vault,
		Secrets:          secrets,
		RequesterMachine: machine,
		RequesterIP:      ip,
	}
}
