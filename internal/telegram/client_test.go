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

func TestWriteApprovalOffersWriteWindowNotReadWindow(t *testing.T) {
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
	req := &models.ApprovalRequest{ID: "write-id", SecretName: "Play key", Vault: "AI Agents", ExpiresAt: time.Now().Add(time.Minute), Mutations: []models.ItemMutation{
		{Item: "Play key", Operation: "create", Fields: map[string]string{"json": "play-secret-value"}},
		{Item: "ASC key", Operation: "update", Fields: map[string]string{"p8": "asc-secret-value", "key_id": "asc-key-id-value"}},
	}}

	if _, err := client.SendApprovalRequest(req, "", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	row := sent.ReplyMarkup.InlineKeyboard[0]
	if len(row) != 2 || row[1].CallbackData != "approve_writes:write-id" || row[1].Text != "✅ Approve + writes 15m" {
		t.Fatalf("write approval row = %#v", row)
	}
	for _, want := range []string{"Write 2 items in the \"AI Agents\" vault", "• Create \"Play key\" (fields: json)", "• Update \"ASC key\" (fields: key_id, p8)"} {
		if !strings.Contains(sent.Text, want) {
			t.Errorf("message missing %q:\n%s", want, sent.Text)
		}
	}
	for _, value := range []string{"play-secret-value", "asc-secret-value", "asc-key-id-value"} {
		if strings.Contains(sent.Text, value) {
			t.Fatalf("mutation value %q leaked into Telegram", value)
		}
	}

	if _, err := client.SendApprovalRequest(req, "", 0); err != nil {
		t.Fatal(err)
	}
	if len(sent.ReplyMarkup.InlineKeyboard[0]) != 1 {
		t.Fatalf("disabled write window still offered: %#v", sent.ReplyMarkup.InlineKeyboard[0])
	}
}

func TestReminderRepliesToOriginalWithoutValues(t *testing.T) {
	var sent SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":124,"chat":{"id":456},"date":1}}`))
	}))
	defer server.Close()
	client := New("token", 456)
	client.baseURL = server.URL
	req := &models.ApprovalRequest{ID: "write-id", Vault: "AI Agents", TelegramMsgID: 77, ExpiresAt: time.Now().Add(10 * time.Minute),
		Mutations: []models.ItemMutation{{Item: "WordPress.org 2FA", Operation: "create", Fields: map[string]string{"otp": "JBSWY3DPEHPK3PXP"}}}}
	if err := client.SendReminder(req); err != nil {
		t.Fatal(err)
	}
	if sent.ReplyParameters == nil || sent.ReplyParameters.MessageID != 77 {
		t.Fatalf("reminder is not a reply to the request: %#v", sent.ReplyParameters)
	}
	if !strings.Contains(sent.Text, "Create \"WordPress.org 2FA\"") || !strings.Contains(sent.Text, "Fields: otp") || strings.Contains(sent.Text, "JBSWY3DPEHPK3PXP") {
		t.Fatalf("reminder text = %s", sent.Text)
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
	req := &models.ApprovalRequest{
		ID: "request-id", SecretName: "Deploy key", Vault: "AI Agents",
		Reason: "Deploy <release> safely.", Action: "read",
		RequestedAt: now, ExpiresAt: now.Add(15 * time.Minute),
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

func TestUpdateApprovalRequestTreatsNotModifiedAsSuccess(t *testing.T) {
	description := "Bad Request: message is not modified: specified new message content and reply markup are exactly the same as a current content and reply markup of the message"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"` + description + `"}`))
	}))
	defer server.Close()
	client := New("token", 456)
	client.baseURL = server.URL
	req := &models.ApprovalRequest{ID: "id", SecretName: "account", Vault: "Agents", Action: "read"}
	if err := client.UpdateApprovalRequest(123, req, time.Hour); err != nil {
		t.Fatalf("not-modified edit must succeed: %v", err)
	}
	description = "Bad Request: message to edit not found"
	if err := client.UpdateApprovalRequest(123, req, time.Hour); err == nil || !strings.Contains(err.Error(), "message to edit not found") {
		t.Fatalf("other Telegram errors must surface, got %v", err)
	}
}

func TestTransportErrorsDoNotLeakBotToken(t *testing.T) {
	const botToken = "123456:secret-bot-token"
	client := New(botToken, 456)
	client.baseURL = "http://127.0.0.1:1/bot" + botToken
	_, err := client.GetUpdates(0)
	if err == nil {
		t.Fatal("expected a transport error from a closed port")
	}
	if strings.Contains(err.Error(), botToken) {
		t.Fatalf("transport error leaked the bot token: %v", err)
	}
	if err := client.sendText("hello"); err == nil || strings.Contains(err.Error(), botToken) {
		t.Fatalf("sendText error = %v", err)
	}
}
