package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/audit"
	"github.com/nerveband/secret-gate/internal/models"
	"github.com/nerveband/secret-gate/internal/opconnect"
	"github.com/nerveband/secret-gate/internal/ownerwindow"
	"github.com/nerveband/secret-gate/internal/settings"
	"github.com/nerveband/secret-gate/internal/telegram"
)

const ownerID = int64(4242)

type sentMessage struct {
	id   int
	text string
	kb   *telegram.InlineKeyboardMarkup
}

// fakeControl records what the owner would see in Telegram.
type fakeControl struct {
	mu       sync.Mutex
	sent     []sentMessage
	edits    map[int]string
	failSend bool
	failEdit bool
}

func (f *fakeControl) Send(text string, kb *telegram.InlineKeyboardMarkup) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSend {
		return 0, errors.New("telegram down")
	}
	id := 100 + len(f.sent)
	f.sent = append(f.sent, sentMessage{id, text, kb})
	return id, nil
}

func (f *fakeControl) Edit(id int, text string, kb *telegram.InlineKeyboardMarkup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failEdit {
		return errors.New("telegram down")
	}
	if f.edits == nil {
		f.edits = map[int]string{}
	}
	f.edits[id] = text
	return nil
}

func (f *fakeControl) last() sentMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return sentMessage{}
	}
	return f.sent[len(f.sent)-1]
}

func (f *fakeControl) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, m := range f.sent {
		if strings.Contains(m.text, substr) {
			n++
		}
	}
	return n
}

func (f *fakeControl) edited(id int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.edits[id]
}

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type ownerHarness struct {
	*writeHarness
	ctl   *fakeControl
	clock *testClock
}

func newOwnerHarness(t *testing.T) *ownerHarness {
	t.Helper()
	wh := newWriteHarness(t)
	clock := &testClock{now: time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)}
	cfg := wh.h.config
	cfg.TelegramChatID = ownerID
	cfg.OwnerWindowEnabled = true
	cfg.OwnerWindowVaults = []string{"AI Agents"}
	store, _ := settings.Open("", settingsDefaults(cfg))
	wh.h.SetSettings(store)
	wh.h.now = clock.Now
	wh.h.owner = ownerwindow.NewStoreWithClock(clock.Now)
	ctl := &fakeControl{}
	wh.h.SetControl(ctl)
	return &ownerHarness{writeHarness: wh, ctl: ctl, clock: clock}
}

func (oh *ownerHarness) addItem(title, category string, tags []string, fields map[string]string) {
	oh.connect.mu.Lock()
	defer oh.connect.mu.Unlock()
	item := opconnect.Item{ID: fmt.Sprintf("item-%d", len(oh.connect.items)), Title: title, Vault: opconnect.Vault{ID: "vid"}, Category: category, Tags: tags}
	for label, value := range fields {
		item.Fields = append(item.Fields, opconnect.Field{ID: label, Label: label, Type: "CONCEALED", Value: value})
	}
	oh.connect.items[item.ID] = item
}

func (oh *ownerHarness) from(userID int64, chatID int64, chatType, text string, mutate func(*telegram.Message)) {
	m := &telegram.Message{MessageID: 1, From: &telegram.User{ID: userID, Username: "owner"}, Chat: telegram.Chat{ID: chatID, Type: chatType}, Date: oh.clock.now.Unix(), Text: text}
	if mutate != nil {
		mutate(m)
	}
	oh.h.HandleTelegramMessage(m)
}

func (oh *ownerHarness) say(text string) { oh.from(ownerID, ownerID, "private", text, nil) }

func (oh *ownerHarness) press(data string, messageID int) {
	oh.pressAs(ownerID, ownerID, data, messageID)
}

func (oh *ownerHarness) pressAs(userID, chatID int64, data string, messageID int) {
	oh.h.HandleTelegramCallback(&telegram.CallbackQuery{
		ID: "cb", From: telegram.User{ID: userID, Username: "owner"}, Data: data,
		Message: &telegram.Message{MessageID: messageID, Chat: telegram.Chat{ID: chatID, Type: "private"}},
	})
}

// openWindow runs the whole owner flow: command, confirm card, second tap.
func (oh *ownerHarness) openWindow() ownerwindow.Window {
	oh.t.Helper()
	oh.say("/open")
	card := oh.ctl.last()
	if !strings.Contains(card.text, "Open a read window?") {
		oh.t.Fatalf("no confirm card, last message: %q", card.text)
	}
	oh.press(card.kb.InlineKeyboard[0][0].CallbackData, card.id)
	windows := oh.h.owner.List()
	if len(windows) != 1 {
		oh.t.Fatalf("windows open = %d", len(windows))
	}
	return windows[0]
}

func (oh *ownerHarness) read(title string, fields ...string) (int, RequestResponse) {
	oh.t.Helper()
	code, resp, _ := oh.submit(readBody(title, fields, ""), agentAddr)
	return code, resp
}

func (oh *ownerHarness) request(token string) *models.ApprovalRequest {
	oh.t.Helper()
	req, err := oh.store.GetByToken(token)
	if err != nil {
		oh.t.Fatal(err)
	}
	return req
}

func TestOwnerWindowNeedsAConfirmTapAndCoversTheWholeVault(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Deploy key", "API_CREDENTIAL", nil, map[string]string{"credential": "TOPSECRET"})
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "hunter2"})

	oh.say("/open")
	card := oh.ctl.last()
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("the command alone must not open a window")
	}
	oh.press(card.kb.InlineKeyboard[0][0].CallbackData, card.id)
	if text := oh.ctl.edited(card.id); !strings.Contains(text, "Reads open until 14:30") || !strings.Contains(text, "30 min") {
		t.Fatalf("the confirm card should become the window card, got %q", text)
	}

	code, resp := oh.read("Deploy key", "credential")
	if code != http.StatusAccepted || oh.tg.sends != 0 {
		t.Fatalf("tagged read: code=%d approval cards sent=%d", code, oh.tg.sends)
	}
	req := oh.request(resp.Token)
	if req.Status != models.StatusApproved || req.AutoApproved != models.AutoApprovedOwnerWindow {
		t.Fatalf("tagged read status=%s source=%s", req.Status, req.AutoApproved)
	}
	if !strings.Contains(resp.Message, "read window the owner opened") {
		t.Fatalf("message = %q", resp.Message)
	}
	if oh.ctl.count("Read via window") != 1 {
		t.Fatalf("first use of an item needs one audit message, got %d", oh.ctl.count("Read via window"))
	}

	code, body := oh.complete(resp.Token)
	if code != http.StatusOK {
		t.Fatalf("release code=%d body=%s", code, body)
	}
	var released BatchSecretResponse
	if err := json.Unmarshal([]byte(body), &released); err != nil {
		t.Fatal(err)
	}
	values := released.Secrets["Deploy key"]
	if !strings.Contains(values[models.ProcessOnlyKey], "credential") {
		t.Fatalf("window values must be process-only, marker = %q", values[models.ProcessOnlyKey])
	}
	until, ok := models.RemainingLife(values, oh.clock.now)
	if !ok || until > 36*time.Minute || until < 34*time.Minute {
		t.Fatalf("release must carry the window end plus grace, life = %s ok=%v", until, ok)
	}

	if _, again := oh.read("Deploy key", "credential"); oh.request(again.Token).Status != models.StatusApproved {
		t.Fatal("a second read of the same item should be covered")
	}
	if oh.ctl.count("Read via window") != 1 {
		t.Fatal("a repeat read of the same item must not send another audit message")
	}

	_, wifi := oh.read("Wifi", "password")
	if oh.request(wifi.Token).Status != models.StatusApproved || oh.tg.sends != 0 {
		t.Fatal("any other ordinary item in the vault is covered too, tagged or not")
	}
	if oh.ctl.count("Read via window") != 2 {
		t.Fatalf("each newly used item gets one audit message, got %d", oh.ctl.count("Read via window"))
	}
}

func TestOwnerWindowCanBeNarrowedToATag(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.policy, _ = ownerwindow.NewPolicy("sg-window", "")
	oh.addItem("Deploy key", "API_CREDENTIAL", []string{"sg-window"}, map[string]string{"credential": "x"})
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "y"})
	oh.openWindow()

	if _, resp := oh.read("Deploy key", "credential"); oh.request(resp.Token).Status != models.StatusApproved {
		t.Fatal("the tagged item should be covered")
	}
	_, resp := oh.read("Wifi", "password")
	req := oh.request(resp.Token)
	if req.Status != models.StatusPending || oh.tg.sends != 1 || !strings.Contains(req.WindowNote, "not tagged") {
		t.Fatalf("untagged item with a tag configured: status=%s cards=%d note=%q", req.Status, oh.tg.sends, req.WindowNote)
	}
}

func TestOwnerWindowNeverCoversGateCredentialsCardsOrPasskeys(t *testing.T) {
	oh := newOwnerHarness(t)
	tag := []string{"sg-window"}
	oh.addItem("Secret Gate Approver Token", "API_CREDENTIAL", tag, map[string]string{"credential": "x"})
	oh.addItem("Visa travel", "CREDIT_CARD", tag, map[string]string{"expiry": "202708"})
	oh.addItem("Site login", "LOGIN", tag, map[string]string{"username": "u", "Passkey Private Key": "k"})
	oh.openWindow()

	cases := []struct {
		item, field, want string
	}{
		{"Secret Gate Approver Token", "credential", "Secret Gate credentials"},
		{"Visa travel", "expiry", "item type"},
		{"Site login", "Passkey Private Key", "passkeys"},
		{"Site login", "", "passkeys"}, // an empty selection would release the passkey too
	}
	for _, c := range cases {
		var fields []string
		if c.field != "" {
			fields = []string{c.field}
		}
		_, resp := oh.read(c.item, fields...)
		req := oh.request(resp.Token)
		if req.Status != models.StatusPending || !strings.Contains(req.WindowNote, c.want) {
			t.Errorf("%s/%s: status=%s note=%q, want pending with %q", c.item, c.field, req.Status, req.WindowNote, c.want)
		}
	}
}

func TestWritesAndCardReadsNeverRideAnOwnerWindow(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Visa travel", "CREDIT_CARD", []string{"sg-window"}, map[string]string{"ccnum": "4111111111111111", "cvv": "123"})
	oh.openWindow()
	code, resp, _ := oh.submit(writeBody("m", "a", "New item", "create", `{"k":"v"}`), agentAddr)
	if code != http.StatusAccepted || oh.request(resp.Token).Status != models.StatusPending || oh.tg.sends != 1 {
		t.Fatalf("write under an owner window: code=%d status=%s cards=%d", code, oh.request(resp.Token).Status, oh.tg.sends)
	}
	_, card, _ := oh.submit(readBody("Visa travel", nil, "aa.com checkout"), agentAddr)
	if oh.request(card.Token).Status != models.StatusPending {
		t.Fatal("a read that releases a card number must keep needing its own tap")
	}
}

func TestOnlyTheApproverInThePrivateChatIsObeyed(t *testing.T) {
	oh := newOwnerHarness(t)
	code, resp, _ := oh.submit(writeBody("m", "a", "New item", "create", `{"k":"v"}`), agentAddr)
	if code != http.StatusAccepted {
		t.Fatalf("submit code=%d", code)
	}
	req := oh.request(resp.Token)

	oh.from(999, 999, "private", "/open", nil)       // a stranger messaging the bot
	oh.from(ownerID, ownerID, "group", "/open", nil) // the owner, but not in the private chat
	oh.from(ownerID, ownerID, "private", "/open", func(m *telegram.Message) { m.ForwardOrigin = json.RawMessage(`{"type":"user"}`) })
	oh.from(ownerID, ownerID, "private", "/open", func(m *telegram.Message) { m.ViaBot = &telegram.User{ID: 5} })
	oh.from(ownerID, ownerID, "private", "/open", func(m *telegram.Message) { m.Date = oh.clock.now.Add(-3 * time.Minute).Unix() })
	oh.from(ownerID, 777, "private", "/open", nil) // the right user in a different chat
	if len(oh.ctl.sent) != 0 || len(oh.h.confirms) != 0 {
		t.Fatalf("refused messages must not be answered or create confirm cards: %+v", oh.ctl.sent)
	}

	oh.pressAs(999, ownerID, "approve:"+req.ID, 55)
	oh.pressAs(999, ownerID, telegram.CBOpen+":0", 55)
	oh.pressAs(ownerID, 777, "approve:"+req.ID, 55)
	if oh.request(resp.Token).Status != models.StatusPending || len(oh.ctl.sent) != 0 {
		t.Fatal("taps from anyone but the approver in the configured chat must be ignored")
	}

	oh.press("approve:"+req.ID, 55)
	if oh.request(resp.Token).Status != models.StatusApproved {
		t.Fatal("the approver's own tap must still approve")
	}
}

func TestConfirmCardIsSingleUseBoundAndShortLived(t *testing.T) {
	oh := newOwnerHarness(t)

	oh.say("/open")
	card := oh.ctl.last()
	data := card.kb.InlineKeyboard[0][0].CallbackData
	oh.press(data, card.id+1) // right nonce, wrong message
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("a confirm tap from another message opened a window")
	}
	oh.press(data, card.id)
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("the nonce is single use, even when the first tap was refused")
	}

	oh.say("/open")
	card = oh.ctl.last()
	oh.clock.Advance(3 * time.Minute)
	oh.press(card.kb.InlineKeyboard[0][0].CallbackData, card.id)
	if len(oh.h.owner.List()) != 0 || !strings.Contains(oh.ctl.edited(card.id), "expired") {
		t.Fatalf("an old confirm card opened a window or was not marked: %q", oh.ctl.edited(card.id))
	}

	oh.say("/open")
	card = oh.ctl.last()
	data = card.kb.InlineKeyboard[0][0].CallbackData
	oh.press(data, card.id)
	oh.press(data, card.id) // replay of the same tap
	if len(oh.h.owner.List()) != 1 {
		t.Fatalf("windows = %d, a replayed confirm must not open a second one", len(oh.h.owner.List()))
	}
}

func TestOpenCommandChecksMinutesAndVault(t *testing.T) {
	oh := newOwnerHarness(t)
	for _, bad := range []string{"/open 3", "/open 90", "/open 30 Other Vault"} {
		before := len(oh.ctl.sent)
		oh.say(bad)
		if got := oh.ctl.last().text; len(oh.ctl.sent) != before+1 || !strings.HasPrefix(got, "🚫") || len(oh.h.confirms) != 0 {
			t.Errorf("%q should be refused with a short reason, got %q", bad, got)
		}
	}
	oh.say("/open 45m ai agents")
	if !strings.Contains(oh.ctl.last().text, "45 min") {
		t.Fatalf("minutes and vault should parse, got %q", oh.ctl.last().text)
	}
}

func TestWindowBudgetClosesItAndBlocksReleaseOfWhatItApproved(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OwnerWindowMaxRequests = 2
	oh.addItem("Deploy key", "API_CREDENTIAL", []string{"sg-window"}, map[string]string{"credential": "x"})
	win := oh.openWindow()

	oh.read("Deploy key", "credential")
	_, second := oh.read("Deploy key", "credential")
	_, third := oh.read("Deploy key", "credential")
	if oh.request(second.Token).Status != models.StatusApproved || oh.request(third.Token).Status != models.StatusPending {
		t.Fatal("the third read is over budget and needs a tap")
	}
	if len(oh.h.owner.List()) != 0 || !strings.Contains(oh.ctl.edited(win.MessageID), "Reads window closed") {
		t.Fatalf("an exhausted window must close and say so: %q", oh.ctl.edited(win.MessageID))
	}
	if code, _ := oh.complete(second.Token); code != http.StatusForbidden {
		t.Fatalf("a read approved by a window that closed early must not be released, code=%d", code)
	}
}

func TestRevokeStopsReleaseAndFurtherCoverage(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Deploy key", "API_CREDENTIAL", []string{"sg-window"}, map[string]string{"credential": "x"})
	win := oh.openWindow()
	_, approved := oh.read("Deploy key", "credential")

	oh.press(telegram.CBClose+":"+win.ID, win.MessageID)
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("close button did not close the window")
	}
	if code, _ := oh.complete(approved.Token); code != http.StatusForbidden {
		t.Fatalf("release after revoke, code=%d", code)
	}
	if _, next := oh.read("Deploy key", "credential"); oh.request(next.Token).Status != models.StatusPending {
		t.Fatal("reads after a close need a tap again")
	}
	oh.say("/close")
	if !strings.Contains(oh.ctl.last().text, "Closed 0") {
		t.Fatalf("/close with nothing open: %q", oh.ctl.last().text)
	}
}

func TestWindowExpiryIsAnnouncedOnTheSweep(t *testing.T) {
	oh := newOwnerHarness(t)
	win := oh.openWindow()
	oh.clock.Advance(31 * time.Minute)
	oh.h.SweepPending(oh.clock.now)
	if !strings.Contains(oh.ctl.edited(win.MessageID), "Reads window closed") || !strings.Contains(oh.ctl.edited(win.MessageID), "ran out of time") {
		t.Fatalf("expiry message = %q", oh.ctl.edited(win.MessageID))
	}
}

func TestCountersAreEditedInPlaceNotSentPerRead(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Deploy key", "API_CREDENTIAL", []string{"sg-window"}, map[string]string{"credential": "x"})
	win := oh.openWindow()
	for range 3 {
		oh.read("Deploy key", "credential")
	}
	oh.clock.Advance(15 * time.Second)
	oh.h.SweepPending(oh.clock.now)
	if text := oh.ctl.edited(win.MessageID); !strings.Contains(text, "3 of 30 reads") {
		t.Fatalf("window card counter = %q", text)
	}
	if oh.ctl.count("Read via window") != 1 {
		t.Fatalf("audit messages = %d, want 1 for the first use only", oh.ctl.count("Read via window"))
	}
}

func TestNoWindowWithoutAnAuditChannelAndNoCoverageWhenTheAuditFails(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Deploy key", "API_CREDENTIAL", []string{"sg-window"}, map[string]string{"credential": "x"})

	oh.ctl.failEdit = true // the card cannot be shown, and there is no other channel
	oh.say("/open")
	card := oh.ctl.last()
	oh.press(card.kb.InlineKeyboard[0][0].CallbackData, card.id)
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("a window must not stay open when nothing could announce it")
	}

	oh.ctl.failEdit = false
	oh.openWindow()
	oh.ctl.failSend = true // the first-use audit cannot be delivered
	_, resp := oh.read("Deploy key", "credential")
	req := oh.request(resp.Token)
	if req.Status != models.StatusPending || !strings.Contains(req.WindowNote, "audit message") {
		t.Fatalf("read with a failing audit: status=%s note=%q", req.Status, req.WindowNote)
	}
	if got := oh.h.owner.List()[0]; got.Requests != 0 || len(got.Items) != 0 {
		t.Fatalf("a refused audit must give back the budget it used: %+v", got)
	}
}

func TestAlertsOffSendsCardsToPushWardOnlyButTelegramStillApproves(t *testing.T) {
	oh := newOwnerHarness(t)
	pw := &fakePushWard{}
	oh.h.SetPushWardClient(pw)
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "x"})

	oh.say("/set notifications off")
	if !oh.h.TelegramSilent() || oh.h.telegramMode() != settings.NotifyOff {
		t.Fatalf("mode = %s", oh.h.telegramMode())
	}
	_, resp := oh.read("Wifi", "password")
	if oh.tg.sends != 0 || len(pw.sent) != 1 {
		t.Fatalf("with alerts off the card goes to PushWard only: telegram=%d pushward=%d", oh.tg.sends, len(pw.sent))
	}

	oh.say("/pending")
	req := oh.request(resp.Token)
	if oh.tg.sends != 1 || req.TelegramMsgID == 0 {
		t.Fatalf("/pending should put the card in the chat on demand: sends=%d msg=%d", oh.tg.sends, req.TelegramMsgID)
	}
	oh.say("/pending")
	if oh.tg.sends != 1 || !strings.Contains(oh.ctl.last().text, "already in this chat") {
		t.Fatal("/pending must not send a card twice")
	}

	oh.press("approve:"+req.ID, req.TelegramMsgID)
	if oh.request(resp.Token).Status != models.StatusApproved {
		t.Fatal("approving from Telegram must keep working while alerts are off")
	}
	if len(pw.audits) == 0 || !strings.Contains(pw.audits[len(pw.audits)-1], "setting changed") {
		t.Fatalf("a settings change must be announced on the other channel: %v", pw.audits)
	}
}

func TestAlertsOffActsAsSilentWhenNoOtherChannelExists(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "x"})
	oh.say("/set notifications off")
	if oh.h.telegramMode() != settings.NotifySilent {
		t.Fatalf("mode = %s, want silent without PushWard", oh.h.telegramMode())
	}
	oh.read("Wifi", "password")
	if oh.tg.sends != 1 {
		t.Fatalf("a request must never go unannounced, telegram cards = %d", oh.tg.sends)
	}
}

func TestAlertsOffFallsBackToTelegramWhenPushWardFails(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.SetPushWardClient(&failingPushWard{})
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "x"})
	oh.say("/set notifications off")
	oh.read("Wifi", "password")
	if oh.tg.sends != 1 {
		t.Fatal("when PushWard cannot take the request, Telegram must post it rather than drop it")
	}
}

type failingPushWard struct{ fakePushWard }

func (f *failingPushWard) SendApprovalRequest(*models.ApprovalRequest, time.Duration) (string, error) {
	return "", errors.New("pushward down")
}

func TestTapWindowsOffHidesTheButtonsAndRefusesTheActions(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "x"})
	oh.h.sessions.Create("owner", 30*time.Minute)

	oh.say("/set tap_windows off")
	if _, ok := oh.h.sessions.Match(); ok {
		t.Fatal("turning tap windows off must end any open tap window")
	}
	_, resp := oh.read("Wifi", "password")
	if oh.tg.sentWindow != 0 {
		t.Fatalf("approval card still offers a window of %s", oh.tg.sentWindow)
	}
	req := oh.request(resp.Token)
	oh.press("approve_window:"+req.ID, 55)
	if oh.request(resp.Token).Status != models.StatusPending {
		t.Fatal("approve_window must be refused while tap windows are off")
	}
	oh.h.HandleTelegramAction("cb", "approve_window:"+req.ID, "pushward")
	if oh.request(resp.Token).Status != models.StatusPending {
		t.Fatal("a window action arriving from another channel must be refused too")
	}
}

func TestSettingsRejectBadInputAndNeedAVaultForPhoneWindows(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OwnerWindowVaults = nil
	oh.say("/set windows on")
	if !strings.Contains(oh.ctl.last().text, "no vault") {
		t.Fatalf("turning windows on without a vault: %q", oh.ctl.last().text)
	}
	oh.say("/set colour red")
	if !strings.Contains(oh.ctl.last().text, "unknown setting") {
		t.Fatalf("unknown setting: %q", oh.ctl.last().text)
	}
	oh.say("/set notifications loud")
	if !strings.HasPrefix(oh.ctl.last().text, "🚫") || oh.h.settingsValues().TelegramNotifications != settings.NotifyOn {
		t.Fatalf("bad value: %q", oh.ctl.last().text)
	}
	oh.say("/set")
	if !strings.Contains(oh.ctl.last().text, "Usage") {
		t.Fatalf("usage: %q", oh.ctl.last().text)
	}
}

func TestSettingsPanelButtonsChangeSettingsInPlace(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.say("/settings")
	panel := oh.ctl.last()
	if !strings.Contains(panel.text, "Telegram alerts</b>: on") {
		t.Fatalf("panel = %q", panel.text)
	}
	oh.press("set:telegram_notifications=silent", panel.id)
	if got := oh.ctl.edited(panel.id); !strings.Contains(got, "Telegram alerts</b>: silent") {
		t.Fatalf("panel was not redrawn: %q", got)
	}
	if oh.h.settingsValues().TelegramNotifications != settings.NotifySilent {
		t.Fatal("setting not applied")
	}
}

func TestTurningPhoneWindowsOffClosesOpenWindows(t *testing.T) {
	oh := newOwnerHarness(t)
	win := oh.openWindow()
	oh.say("/set windows off")
	if len(oh.h.owner.List()) != 0 || !strings.Contains(oh.ctl.edited(win.MessageID), "Reads window closed") {
		t.Fatal("switching the feature off must end open windows and say so")
	}
	oh.say("/open")
	if !strings.Contains(oh.ctl.last().text, "off") {
		t.Fatalf("/open while off: %q", oh.ctl.last().text)
	}
}

func TestOlderTapWindowStillExcludesGateCredentials(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OwnerWindowVaults = nil // owner windows unused; only the older window is open
	oh.addItem("Wifi", "PASSWORD", nil, map[string]string{"password": "x"})
	oh.addItem("PushWard Integration Key", "API_CREDENTIAL", nil, map[string]string{"credential": "k"})
	oh.h.sessions.Create("owner", 30*time.Minute)

	_, wifi := oh.read("Wifi", "password")
	if oh.request(wifi.Token).Status != models.StatusApproved {
		t.Fatal("the older window should keep covering ordinary reads")
	}
	_, key := oh.read("PushWard Integration Key", "credential")
	req := oh.request(key.Token)
	if req.Status != models.StatusPending || !strings.Contains(req.WindowNote, "Secret Gate credentials") {
		t.Fatalf("the older window handed out a gate credential: status=%s note=%q", req.Status, req.WindowNote)
	}
}

func digestOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (oh *ownerHarness) api(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	oh.h.HandleApprovals(rec, req)
	return rec
}

func TestOpenerTokenCanOnlyOpenListAndCloseWindows(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OpenerTokenSHA256 = digestOf("opener-secret")
	oh.h.config.ApproverTokenSHA256 = digestOf("approver-secret")

	rec := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{"minutes":30,"approver":"voice-workspace (control)"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open = %d %s", rec.Code, rec.Body.String())
	}
	var opened struct {
		Window WindowInfo `json:"window"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &opened)
	if opened.Window.Source != "api" || opened.Window.Opener != "voice-workspace (control)" || opened.Window.MaxRequests != 30 {
		t.Fatalf("window = %+v", opened.Window)
	}
	if oh.ctl.count("Reads open until") != 1 {
		t.Fatalf("an API-opened window must alert the owner loudly, alerts = %d", oh.ctl.count("Reads open until"))
	}

	if rec := oh.api(http.MethodGet, "/approvals/windows", "opener-secret", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), opened.Window.ID) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	dup := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{"minutes":60}`)
	if dup.Code != http.StatusConflict || !strings.Contains(dup.Body.String(), opened.Window.ExpiresAt) {
		t.Fatalf("second open = %d %s (must report the existing window unchanged)", dup.Code, dup.Body.String())
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/approvals"}, {http.MethodGet, "/approvals/events"}, {http.MethodPost, "/approvals/abc/decide"},
	} {
		if rec := oh.api(c.method, c.path, "opener-secret", `{"action":"approve"}`); rec.Code != http.StatusForbidden {
			t.Errorf("opener token on %s %s = %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if rec := oh.api(http.MethodPost, "/approvals/windows", "wrong", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d", rec.Code)
	}
	if rec := oh.api(http.MethodGet, "/approvals", "approver-secret", ""); rec.Code != http.StatusOK {
		t.Fatalf("a digest-stored approver token must work, got %d", rec.Code)
	}

	if rec := oh.api(http.MethodPost, "/approvals/windows/"+opened.Window.ID+"/revoke", "opener-secret", `{"approver":"watch"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	if len(oh.h.owner.List()) != 0 {
		t.Fatal("revoke did not close the window")
	}
	for _, minutes := range []string{"3", "500"} {
		if rec := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{"minutes":`+minutes+`}`); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("minutes %s = %d, want 422", minutes, rec.Code)
		}
	}
}

func TestAPIOpenFailsClosedWhenNoChannelCanAnnounceIt(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OpenerTokenSHA256 = digestOf("opener-secret")
	oh.ctl.failSend = true
	rec := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{"minutes":30}`)
	if rec.Code != http.StatusServiceUnavailable || len(oh.h.owner.List()) != 0 {
		t.Fatalf("code=%d windows=%d body=%s", rec.Code, len(oh.h.owner.List()), rec.Body.String())
	}

	oh.h.SetPushWardClient(&fakePushWard{}) // another channel can carry the alert
	if rec := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{"minutes":30}`); rec.Code != http.StatusCreated {
		t.Fatalf("PushWard alone should be enough, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAPIOpenIsRefusedWhileThePhoneFeatureIsOff(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.h.config.OpenerTokenSHA256 = digestOf("opener-secret")
	oh.say("/set windows off")
	if rec := oh.api(http.MethodPost, "/approvals/windows", "opener-secret", `{}`); rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d", rec.Code)
	}
}

func TestPanelOffersOpenSettingsAndPending(t *testing.T) {
	oh := newOwnerHarness(t)
	oh.say("/panel")
	panel := oh.ctl.last()
	var data []string
	for _, row := range panel.kb.InlineKeyboard {
		for _, b := range row {
			data = append(data, b.CallbackData)
		}
	}
	for _, want := range []string{"ow_open:0", "ow_closeall:x", "pending:x", "settings:x"} {
		found := false
		for _, d := range data {
			found = found || d == want
		}
		if !found {
			t.Errorf("panel is missing %s: %v", want, data)
		}
	}
	oh.press("ow_open:0", panel.id)
	if !strings.Contains(oh.ctl.last().text, "Open a read window?") {
		t.Fatalf("the panel button must lead to the confirm card, got %q", oh.ctl.last().text)
	}
}

func TestAuditFileRecordsTheWindowLifecycleWithoutValues(t *testing.T) {
	oh := newOwnerHarness(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	oh.h.SetAudit(audit.New(path))
	oh.addItem("Deploy key", "API_CREDENTIAL", nil, map[string]string{"credential": "TOPSECRET-VALUE"})
	oh.addItem("Secret Gate Approver Token", "API_CREDENTIAL", nil, map[string]string{"credential": "hunter2"})

	win := oh.openWindow()
	_, resp := oh.read("Deploy key", "credential")
	oh.complete(resp.Token)
	oh.read("Secret Gate Approver Token", "credential")
	oh.press(telegram.CBClose+":"+win.ID, win.MessageID)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, event := range []string{audit.WindowOpenRequested, audit.WindowOpened, audit.WindowUsed, audit.WindowNotCovered, audit.WindowClosed} {
		if !strings.Contains(text, `"event":"`+event+`"`) {
			t.Errorf("audit file has no %s line:\n%s", event, text)
		}
	}
	for _, leaked := range []string{"TOPSECRET-VALUE", "hunter2"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("a secret value reached the audit file: %s", leaked)
		}
	}
}
