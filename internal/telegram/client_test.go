package telegram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		Action:           "read",
		Context:          models.RequestContext{Runtime: "Paseo", Provider: "Oh My Pi", Model: "gpt-5.6-sol", Think: "high", Project: "ts-project", Task: "test the deployment"},
		Secrets:          []models.SecretRequest{{SecretName: "deploy-key", Vault: "AI Agents", Fields: []string{"username", "password"}}},
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
	if sent.ParseMode != "HTML" {
		t.Fatalf("parse mode = %q, want HTML", sent.ParseMode)
	}
	for _, want := range []string{"🔐 1Password access request", "Reason:\n<b>test the deployment</b>", "Runtime: Paseo\nProvider: Oh My Pi\nModel: gpt-5.6-sol\nThinking: high\nProject: ts-project", "Read username, password", "Expires:", "Request: <code>request-id</code>"} {
		if !strings.Contains(sent.Text, want) {
			t.Errorf("message missing %q:\n%s", want, sent.Text)
		}
	}
}

func TestMutationApprovalHasNoWindowButton(t *testing.T) {
	var sent SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":123,"chat":{"id":456},"date":1}}`))
	}))
	defer server.Close()
	client := New("token", 456)
	client.baseURL = server.URL
	req := &models.ApprovalRequest{ID: "write-id", SecretName: "note", Vault: "vault", ExpiresAt: time.Now().Add(time.Minute), Mutation: &models.ItemMutation{Operation: "update", Fields: map[string]string{"notesPlain": "not shown"}}}
	if _, err := client.SendApprovalRequest(req, "", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(sent.ReplyMarkup.InlineKeyboard[0]) != 1 {
		t.Fatalf("write approval offered a window: %#v", sent.ReplyMarkup.InlineKeyboard[0])
	}
	if strings.Contains(sent.Text, "not shown") {
		t.Fatal("mutation value leaked into Telegram")
	}
}

func TestDecisionMessagesPreserveNarrativeAndReason(t *testing.T) {
	var edited EditMessageTextRequest
	var sent SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/editMessageText":
			_ = json.NewDecoder(r.Body).Decode(&edited)
		case "/sendMessage":
			_ = json.NewDecoder(r.Body).Decode(&sent)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":123,"chat":{"id":456},"date":1}}`))
	}))
	defer server.Close()
	client := New("token", 456)
	client.baseURL = server.URL
	req := &models.ApprovalRequest{ID: "id", SecretName: "account", Vault: "Agents", RequesterMachine: "devbox", Reason: "deploy the corrected server", Action: "read", Context: models.RequestContext{Runtime: "Paseo", Provider: "Oh My Pi", Model: "gpt-5.6", Project: "secret-gate"}, Secrets: []models.SecretRequest{{SecretName: "account", Vault: "Agents", Fields: []string{"password"}}}}
	if err := client.UpdateMessageApproved(123, req, "owner"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"✅ Approved: deploy the corrected server", "Oh My Pi may read password", "Reason:\n<b>deploy the corrected server</b>", "Approved by: @owner"} {
		if !strings.Contains(edited.Text, want) {
			t.Errorf("approved message missing %q: %s", want, edited.Text)
		}
	}
	if edited.ParseMode != "HTML" {
		t.Fatalf("approved parse mode = %q", edited.ParseMode)
	}
	if err := client.SendAutoApprovedNotification(req, "owner", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"✅ Approved: deploy the corrected server", "Oh My Pi may read password", "Reason:\n<b>deploy the corrected server</b>", "Approved by: @owner"} {
		if !strings.Contains(sent.Text, want) {
			t.Errorf("auto-approved message missing %q: %s", want, sent.Text)
		}
	}
	if sent.ParseMode != "HTML" {
		t.Fatalf("auto-approved parse mode = %q", sent.ParseMode)
	}
}

func TestMessagesBoldOnlyReasonAndKeepIdentityOrder(t *testing.T) {
	now := time.Date(2026, 8, 28, 15, 27, 0, 0, time.FixedZone("EDT", -4*60*60))
	reminded := now.Add(5 * time.Minute)
	req := &models.ApprovalRequest{
		ID: "request-id", SecretName: "Deploy key", Vault: "AI Agents",
		Reason: "Deploy <release> safely.", Action: "read",
		RequestedAt: now, ExpiresAt: now.Add(15 * time.Minute),
		LastRemindedAt: &reminded, ReminderCount: 2,
		Context: models.RequestContext{
			Runtime: "Paseo", Provider: "Oh My Pi", Model: "gpt-5.6-sol",
			Think: "high", Project: "secret-gate", Task: "Deploy Secret Gate.",
		},
		Secrets: []models.SecretRequest{{SecretName: "Deploy key", Vault: "AI Agents", Fields: []string{"password"}}},
	}
	message := approvalMessage(req)
	if strings.Count(message, "<b>") != 1 || !strings.Contains(message, "<b>Deploy &lt;release&gt; safely.</b>") {
		t.Fatalf("bold formatting = %q", message)
	}
	order := []string{"Runtime: Paseo", "Provider: Oh My Pi", "Model: gpt-5.6-sol", "Thinking: high", "Project: secret-gate"}
	last := -1
	for _, part := range order {
		index := strings.Index(message, part)
		if index <= last {
			t.Fatalf("identity order in %q", message)
		}
		last = index
	}
	if got := reminderMessage(req); !strings.HasPrefix(got, "⏰ Approval reminder") || strings.Count(got, "<b>") != 1 {
		t.Fatalf("reminder = %q", got)
	}
	if got := blockedWriteMessage(req, "The token has read-only access."); !strings.HasPrefix(got, "⛔ Write request blocked") || strings.Count(got, "<b>") != 1 {
		t.Fatalf("blocked = %q", got)
	}
}

func TestPurposeSuffixIsDeterministicAndUnicodeSafe(t *testing.T) {
	req := &models.ApprovalRequest{Context: models.RequestContext{Task: "  Déployer   le service.  "}}
	if got := purposeSuffix(req); got != "déployer le service" {
		t.Fatalf("purpose = %q", got)
	}
	req.Context.Task = strings.Repeat("界", 80)
	got := purposeSuffix(req)
	if runes := []rune(got); len(runes) != 72 || runes[71] != '…' {
		t.Fatalf("truncated purpose has %d runes: %q", len([]rune(got)), got)
	}
}
