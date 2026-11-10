package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/telegram"
)

// fakeBotAPI is a Telegram Bot API that serves scripted updates and records
// every message the server sends.
type fakeBotAPI struct {
	mu       sync.Mutex
	polls    int
	script   [][]string // update JSON served by getUpdates call 1, 2, ...
	sends    []telegram.SendMessageRequest
	commands bool
	queries  []string
}

func (f *fakeBotAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/deleteWebhook", "/answerCallbackQuery", "/editMessageText":
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case "/setMyCommands":
			f.commands = true
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case "/getUpdates":
			f.queries = append(f.queries, r.URL.RawQuery)
			var updates []string
			if f.polls < len(f.script) {
				updates = f.script[f.polls]
			}
			f.polls++
			if len(updates) == 0 {
				f.mu.Unlock()
				time.Sleep(20 * time.Millisecond)
				f.mu.Lock()
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[` + strings.Join(updates, ",") + `]}`))
		case "/sendMessage":
			var m telegram.SendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&m)
			f.sends = append(f.sends, m)
			_, _ = fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"chat":{"id":%d},"date":1}}`, 200+len(f.sends), m.ChatID)
		default:
			t.Errorf("unexpected Bot API call %s", r.URL.Path)
		}
	})
}

func (f *fakeBotAPI) sentContaining(substr string) []telegram.SendMessageRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []telegram.SendMessageRequest
	for _, m := range f.sends {
		if strings.Contains(m.Text, substr) {
			out = append(out, m)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The real client against a fake Bot API: updates that queued up while the
// server was down are dropped, a stranger is ignored without an answer, the
// approver's command gets a confirm card, and alert modes decide whether
// that card pushes.
func TestPollingDropsQueuedUpdatesIgnoresStrangersAndHonoursAlertMode(t *testing.T) {
	oh := newOwnerHarness(t)
	date := oh.clock.now.Unix()
	message := func(id int64, from int64, text string) string {
		return fmt.Sprintf(`{"update_id":%d,"message":{"message_id":%d,"from":{"id":%d,"username":"u"},"chat":{"id":%d,"type":"private"},"date":%d,"text":%q}}`,
			id, id, from, from, date, text)
	}
	api := &fakeBotAPI{script: [][]string{
		{message(5, ownerID, "/open")},                           // queued during downtime: dropped
		{message(6, 999, "/open"), message(7, ownerID, "/open")}, // a stranger, then the approver
		{message(8, ownerID, "/set notifications silent")},       // changes the alert mode
		{message(9, ownerID, "/open")},                           // its confirm card must not push
	}}
	server := httptest.NewServer(api.handler(t))
	defer server.Close()

	client := telegram.New("token", ownerID)
	client.SetBaseURL(server.URL)
	oh.h.SetControl(client)
	client.SetSilent(oh.h.TelegramSilent)
	go func() { _ = client.SetCommands() }()
	go client.PollUpdates(oh.h.HandleTelegramCallback, oh.h.HandleTelegramMessage)

	waitFor(t, "two confirm cards", func() bool { return len(api.sentContaining("Open a read window?")) == 2 })
	cards := api.sentContaining("Open a read window?")
	api.mu.Lock()
	defer api.mu.Unlock()

	if !strings.Contains(api.queries[0], "offset=-1") {
		t.Fatalf("the first poll must drop what queued up, got %s", api.queries[0])
	}
	if !strings.Contains(api.queries[1], "offset=6") {
		t.Fatalf("after dropping update 5 the next poll must start at 6, got %s", api.queries[1])
	}
	if len(api.sends) != 3 { // two confirm cards and the "alerts silent" reply
		t.Fatalf("messages sent = %d: the dropped update and the stranger must get nothing", len(api.sends))
	}
	if cards[0].DisableNotification {
		t.Fatal("with alerts on the confirm card must push")
	}
	if !cards[1].DisableNotification {
		t.Fatal("after /set notifications silent the next card must arrive without a push")
	}
	if cards[0].ChatID != ownerID {
		t.Fatalf("card sent to chat %d", cards[0].ChatID)
	}
}
