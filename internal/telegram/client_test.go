package telegram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestSendApprovalRequestIncludesAutoApproveButton(t *testing.T) {
	var sent SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sendMessage" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatalf("decode telegram request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"result":{"message_id":123,"chat":{"id":456},"date":1}}`))
	}))
	defer server.Close()

	client := New("token", 456)
	client.baseURL = server.URL
	req := &models.ApprovalRequest{
		ID:               "request-id",
		SecretName:       "deploy-key",
		Vault:            "AI Agents",
		RequesterMachine: "agent-mac",
		RequesterIP:      "10.0.0.5",
		ExpiresAt:        time.Now().Add(15 * time.Minute),
	}

	if _, err := client.SendApprovalRequest(req, "http://example.test", 30*time.Minute); err != nil {
		t.Fatalf("SendApprovalRequest: %v", err)
	}

	if len(sent.ReplyMarkup.InlineKeyboard) < 2 {
		t.Fatalf("expected two keyboard rows, got %#v", sent.ReplyMarkup.InlineKeyboard)
	}
	button := sent.ReplyMarkup.InlineKeyboard[0][1]
	if button.Text != "✅ Approve 30m" {
		t.Fatalf("auto-approve button text = %q, want approve duration", button.Text)
	}
	if button.CallbackData != "approve_window:request-id" {
		t.Fatalf("auto-approve callback = %q, want approve_window:request-id", button.CallbackData)
	}
}
