package autosession

import (
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestStoreMatchesExactRequesterAndSecretsWithinTTL(t *testing.T) {
	store := NewStore()
	req := request("agent-mac", "10.0.0.5", []models.SecretRequest{
		{SecretName: "deploy-key", Vault: "AI Agents", Fields: []string{"private key"}},
	})

	session := store.Create(req, "ashraf", 30*time.Minute)

	matched, ok := store.Match(req)
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

func TestStoreRejectsDifferentMachineIPOrSecret(t *testing.T) {
	store := NewStore()
	base := request("agent-mac", "10.0.0.5", []models.SecretRequest{
		{SecretName: "deploy-key", Vault: "AI Agents", Fields: []string{"private key"}},
	})
	store.Create(base, "ashraf", 30*time.Minute)

	tests := map[string]*models.ApprovalRequest{
		"machine": request("other-mac", "10.0.0.5", base.Secrets),
		"ip":      request("agent-mac", "10.0.0.9", base.Secrets),
		"secret": request("agent-mac", "10.0.0.5", []models.SecretRequest{
			{SecretName: "other-key", Vault: "AI Agents", Fields: []string{"private key"}},
		}),
		"field": request("agent-mac", "10.0.0.5", []models.SecretRequest{
			{SecretName: "deploy-key", Vault: "AI Agents", Fields: []string{"password"}},
		}),
	}

	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			if _, ok := store.Match(req); ok {
				t.Fatal("request should not match auto-approval session")
			}
		})
	}
}

func TestStoreExpiresSessions(t *testing.T) {
	store := NewStore()
	req := request("agent-mac", "10.0.0.5", []models.SecretRequest{
		{SecretName: "deploy-key", Vault: "AI Agents"},
	})

	store.Create(req, "ashraf", -time.Second)

	if _, ok := store.Match(req); ok {
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
