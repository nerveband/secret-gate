package telegram

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/models"
)

func TestSilentModeSendsWithoutAPush(t *testing.T) {
	var sent []SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m SendMessageRequest
		_ = json.NewDecoder(r.Body).Decode(&m)
		sent = append(sent, m)
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":9,"chat":{"id":456},"date":1}}`))
	}))
	defer server.Close()
	c := New("token", 456)
	c.baseURL = server.URL
	silent := false
	c.SetSilent(func() bool { return silent })

	req := &models.ApprovalRequest{ID: "r1", SecretName: "k", Vault: "V", ExpiresAt: time.Now().Add(time.Minute), Secrets: []models.SecretRequest{{SecretName: "k"}}}
	if _, err := c.SendApprovalRequest(req, "http://x", time.Minute); err != nil {
		t.Fatal(err)
	}
	silent = true
	if _, err := c.SendApprovalRequest(req, "http://x", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send("hello", nil); err != nil {
		t.Fatal(err)
	}
	if sent[0].DisableNotification {
		t.Fatal("alerts on: the message must push")
	}
	if !sent[1].DisableNotification || !sent[2].DisableNotification {
		t.Fatal("silent: approval cards and control messages must not push")
	}
}

func TestApprovalCardsHaveNoWindowButtonWhileTapWindowsAreOff(t *testing.T) {
	read := &models.ApprovalRequest{ID: "r", Secrets: []models.SecretRequest{{SecretName: "k"}}}
	write := &models.ApprovalRequest{ID: "w", Mutations: []models.ItemMutation{{Item: "k", Operation: "create"}}}
	for _, req := range []*models.ApprovalRequest{read, write} {
		if row := approvalKeyboard(req, 0).InlineKeyboard[0]; len(row) != 1 {
			t.Fatalf("%s: tap windows off must leave only Approve once, got %d buttons", req.ID, len(row))
		}
		if row := approvalKeyboard(req, 30*time.Minute).InlineKeyboard[0]; len(row) != 2 {
			t.Fatalf("%s: tap windows on must offer a window, got %d buttons", req.ID, len(row))
		}
	}
}

func TestDrainPendingDropsQueuedUpdatesAndAdvancesTheOffset(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":10,"callback_query":{"id":"c","from":{"id":1},"data":"ow_open:0"}}]}`))
	}))
	defer server.Close()
	c := New("token", 456)
	c.baseURL = server.URL

	n, err := c.DrainPending()
	if err != nil || n != 1 {
		t.Fatalf("drain = %d, %v", n, err)
	}
	if !strings.Contains(queries[0], "offset=-1") || !strings.Contains(queries[0], "timeout=0") {
		t.Fatalf("drain query = %s", queries[0])
	}
	if _, err := c.GetUpdates(0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(queries[1], "offset=11") {
		t.Fatalf("the update dropped at startup must be confirmed, next query = %s", queries[1])
	}
	for _, kind := range []string{"callback_query", "message"} {
		if !strings.Contains(queries[1], kind) {
			t.Fatalf("allowed_updates is missing %s: %s", kind, queries[1])
		}
	}
}

func TestMessagesParseSenderChatAndForwarding(t *testing.T) {
	raw := `{"update_id":1,"message":{"message_id":5,"from":{"id":42,"username":"owner"},"chat":{"id":42,"type":"private"},"date":100,"text":"/open 15","forward_origin":{"type":"user"}}}`
	var u Update
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		t.Fatal(err)
	}
	m := u.Message
	if m == nil || m.From.ID != 42 || m.Chat.Type != "private" || m.Text != "/open 15" || len(m.ForwardOrigin) == 0 {
		t.Fatalf("parsed message = %+v", m)
	}
}

func TestConfirmCardStatesTheScopeAndEnd(t *testing.T) {
	until := time.Date(2026, 11, 10, 14, 35, 0, 0, time.UTC)
	text, kb := WindowConfirmMessage(WindowConfirm{Vault: "AI Agents", Minutes: 30, Until: until, MaxRequests: 30, MaxItems: 10, Nonce: "abc"})
	for _, want := range []string{"AI Agents", "every item in it", "never to the model", "Not covered: cards, bank, passkeys, files, writes, or Secret Gate credentials", "Until <b>2:35 PM UTC</b>", "30 min", "Max 30 reads and 10 items"} {
		if !strings.Contains(text, want) {
			t.Errorf("confirm card missing %q:\n%s", want, text)
		}
	}
	if kb.InlineKeyboard[0][0].CallbackData != "ow_ok:abc" || kb.InlineKeyboard[0][1].CallbackData != "ow_no:abc" {
		t.Fatalf("confirm buttons = %+v", kb.InlineKeyboard)
	}
}

func TestConfirmCardNamesTheTagWhenOneIsConfigured(t *testing.T) {
	text, _ := WindowConfirmMessage(WindowConfirm{Vault: "AI Agents", Tag: "sg-window", Minutes: 30, Until: time.Now(), MaxRequests: 30, MaxItems: 10, Nonce: "abc"})
	if !strings.Contains(text, "tagged <code>sg-window</code> only") || strings.Contains(text, "every item") {
		t.Fatalf("narrowed window card:\n%s", text)
	}
}

func TestSettingsPanelMarksTheCurrentChoices(t *testing.T) {
	text, kb := SettingsMessage(SettingsView{Notifications: "silent", NotificationsEffective: "silent", OwnerWindows: true, OwnerWindowsAvailable: true, TapWindows: false, Timezone: "America/Los_Angeles", Saved: true})
	if !strings.Contains(text, "Telegram alerts</b>: silent") || strings.Contains(text, "restarts") {
		t.Fatalf("settings text:\n%s", text)
	}
	if !strings.Contains(text, "Time zone</b>: Pacific (America/Los_Angeles)") {
		t.Fatalf("the panel should show the zone:\n%s", text)
	}
	row := kb.InlineKeyboard[0]
	if !strings.HasPrefix(row[1].Text, "✅") || strings.HasPrefix(row[0].Text, "✅") || row[2].CallbackData != "set:telegram_notifications=off" {
		t.Fatalf("alert row = %+v", row)
	}
	phone, taps := kb.InlineKeyboard[1][0], kb.InlineKeyboard[2][0]
	if phone.Text != "✅ Phone windows: ON" || phone.CallbackData != "set:owner_windows=off" {
		t.Fatalf("phone windows switch = %+v", phone)
	}
	if taps.Text != "⬜ Tap windows: OFF" || taps.CallbackData != "set:tap_windows=on" {
		t.Fatalf("tap windows switch = %+v", taps)
	}
	if len(kb.InlineKeyboard[1]) != 1 || len(kb.InlineKeyboard[2]) != 1 {
		t.Fatal("each flip switch gets its own full-width row so the label is never cut off")
	}
	zones := append(append([]InlineKeyboardButton{}, kb.InlineKeyboard[3]...), kb.InlineKeyboard[4]...)
	if len(zones) != 5 || !strings.HasPrefix(zones[0].Text, "✅ Pacific") || zones[0].CallbackData != "set:timezone=America/Los_Angeles" || strings.HasPrefix(zones[3].Text, "✅") {
		t.Fatalf("zone buttons = %+v", zones)
	}
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			if len(b.CallbackData) > 64 {
				t.Fatalf("callback data %q is over Telegram's 64-byte limit", b.CallbackData)
			}
			// A row of three shares the screen width; keep those labels short.
			if len(row) == 3 && len([]rune(b.Text)) > 12 {
				t.Fatalf("label %q is too long for a row of three", b.Text)
			}
		}
	}
}

func TestCustomZoneIsShownByName(t *testing.T) {
	text, kb := SettingsMessage(SettingsView{Notifications: "on", Timezone: "Europe/London", Saved: true})
	if !strings.Contains(text, "Time zone</b>: Europe/London") || strings.Contains(text, "(Europe/London)") {
		t.Fatalf("custom zone text:\n%s", text)
	}
	for _, row := range kb.InlineKeyboard[3:5] {
		for _, b := range row {
			if strings.HasPrefix(b.Text, "✅") {
				t.Fatalf("no preset should be marked for a custom zone: %+v", b)
			}
		}
	}
}

func TestOffModeWithNoOtherChannelIsExplainedOnThePanel(t *testing.T) {
	text, _ := SettingsMessage(SettingsView{Notifications: "off", NotificationsEffective: "silent", Saved: true})
	if !strings.Contains(text, "acting as silent") {
		t.Fatalf("panel should say off is acting as silent:\n%s", text)
	}
}
