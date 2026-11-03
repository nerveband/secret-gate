package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/autosession"
	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/writegrant"
)

func (f *fakeTelegram) AnswerCallbackQuery(_, text string) error {
	f.answers = append(f.answers, text)
	return nil
}
func (f *fakeTelegram) UpdateMessageApproved(int, *models.ApprovalRequest, string) error { return nil }
func (f *fakeTelegram) UpdateMessageDenied(int, *models.ApprovalRequest, string) error   { return nil }
func (f *fakeTelegram) UpdateMessageApprovedWriteWindow(int, *models.ApprovalRequest, string, writegrant.Window) error {
	f.windowEdits++
	return nil
}
func (f *fakeTelegram) UpdateMessageExpired(int, *models.ApprovalRequest) error {
	f.expiredEdits++
	return nil
}
func (f *fakeTelegram) SendWriteAutoApproved(_ *models.ApprovalRequest, match writegrant.Match) error {
	if f.failAudit {
		return errors.New("telegram down")
	}
	f.autoWrites = append(f.autoWrites, match)
	return nil
}
func (f *fakeTelegram) SendReminder(*models.ApprovalRequest) error {
	f.reminders++
	return nil
}
func (f *fakeTelegram) SendWindowRevoked(writegrant.Window, string, int) error {
	f.revoked++
	return nil
}

// fakeConnect is a minimal in-memory 1Password Connect for one vault.
type fakeConnect struct {
	mu      sync.Mutex
	items   map[string]opconnect.Item // by ID
	writes  []string                  // "create:title" / "update:title"
	failOn  string                    // title whose write returns 500
	content map[string][]byte         // attachment content by file ID
}

var titleFilter = regexp.MustCompile(`title eq "(.*)"`)

func newFakeConnect(t *testing.T, existing ...string) (*fakeConnect, *httptest.Server) {
	fc := &fakeConnect{items: map[string]opconnect.Item{}, content: map[string][]byte{}}
	for _, title := range existing {
		id := fmt.Sprintf("item-%d", len(fc.items))
		fc.items[id] = opconnect.Item{ID: id, Title: title, Vault: opconnect.Vault{ID: "vid"}, Category: "SECURE_NOTE"}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fc.mu.Lock()
		defer fc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]opconnect.Vault{{ID: "vid", Name: "AI Agents"}})
		case r.URL.Path == "/v1/vaults/vid/items" && r.Method == http.MethodGet:
			var out []opconnect.Item
			m := titleFilter.FindStringSubmatch(r.URL.Query().Get("filter"))
			for _, item := range fc.items {
				if m != nil && item.Title == m[1] {
					out = append(out, opconnect.Item{ID: item.ID, Title: item.Title, Category: item.Category})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.URL.Path == "/v1/vaults/vid/items" && r.Method == http.MethodPost:
			var item opconnect.Item
			_ = json.NewDecoder(r.Body).Decode(&item)
			if item.Title == "" { // write-capability probe
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if item.Title == fc.failOn {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			item.ID = fmt.Sprintf("item-%d", len(fc.items))
			fc.items[item.ID] = item
			fc.writes = append(fc.writes, "create:"+item.Title)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(item)
		case strings.HasSuffix(r.URL.Path, "/content") && strings.Contains(r.URL.Path, "/files/"):
			parts := strings.Split(r.URL.Path, "/")
			data, ok := fc.content[parts[len(parts)-2]]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(data)
		case strings.HasPrefix(r.URL.Path, "/v1/vaults/vid/items/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vaults/vid/items/")
			item, ok := fc.items[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == http.MethodPut {
				_ = json.NewDecoder(r.Body).Decode(&item)
				fc.items[id] = item
				fc.writes = append(fc.writes, "update:"+item.Title)
			}
			_ = json.NewEncoder(w).Encode(item)
		default:
			t.Errorf("unexpected Connect call %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return fc, server
}

func (fc *fakeConnect) writeLog() []string {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return append([]string(nil), fc.writes...)
}

type writeHarness struct {
	t       *testing.T
	h       *Handler
	tg      *fakeTelegram
	store   *store.Store
	connect *fakeConnect
}

func newWriteHarness(t *testing.T, existing ...string) *writeHarness {
	fc, server := newFakeConnect(t, existing...)
	tg := &fakeTelegram{}
	requests := store.New()
	cfg := &config.Config{
		WebhookBaseURL: "http://gate", RequestTTL: 15 * time.Minute, AutoApproveTTL: 30 * time.Minute,
		WriteRequestTTL: time.Hour, WriteWindowTTL: 15 * time.Minute, WriteFollowUpTTL: 15 * time.Minute, WriteReminderBefore: 10 * time.Minute,
	}
	h := New(requests, opconnect.New(server.URL, "token"), tg, cfg, autosession.NewStore())
	return &writeHarness{t: t, h: h, tg: tg, store: requests, connect: fc}
}

// submit posts a request body from a requester and returns the response.
func (wh *writeHarness) submit(body, remoteAddr string) (int, RequestResponse, string) {
	wh.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/request", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	wh.h.HandleRequest(rec, req)
	var resp RequestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp, rec.Body.String()
}

// complete performs the approved write the way the client does.
func (wh *writeHarness) complete(token string) (int, string) {
	wh.t.Helper()
	rec := httptest.NewRecorder()
	wh.h.HandleSecret(rec, httptest.NewRequest(http.MethodGet, "/secret/"+token, nil))
	return rec.Code, rec.Body.String()
}

func (wh *writeHarness) tap(action, token string) {
	wh.t.Helper()
	req, err := wh.store.GetByToken(token)
	if err != nil {
		wh.t.Fatal(err)
	}
	wh.h.HandleTelegramAction("cb", action+":"+req.ID, "nerveband")
}

func (wh *writeHarness) status(token string) models.RequestStatus {
	wh.t.Helper()
	req, err := wh.store.GetByToken(token)
	if err != nil {
		wh.t.Fatal(err)
	}
	return req.Status
}

func writeBody(machine, agent, item, op, fields string) string {
	return fmt.Sprintf(`{"secret_name":%q,"vault":"AI Agents","machine":%q,"reason":"publish plugin","context":{"paseo_agent_id":%q},"mutation":{"operation":%q,"fields":%s}}`,
		item, machine, agent, op, fields)
}

const agentAddr = "100.64.0.3:5000"

// The WordPress.org scenario from 2026-10-25: 2FA seed create, recovery codes
// update to the same item, then the SVN password create. Before this change
// each write needed its own tap; with "Approve + writes" only the first does.
func TestWordPressScenarioNeedsOneTapWithWriteWindow(t *testing.T) {
	wh := newWriteHarness(t)

	code, seed, body := wh.submit(writeBody("mac-server", "agent-1", "WordPress.org 2FA (nerveband)", "create", `{"otp":"JBSWY3DPEHPK3PXP"}`), agentAddr)
	if code != http.StatusAccepted || wh.tg.sends != 1 || wh.tg.sentWindow != 15*time.Minute {
		t.Fatalf("seed submit code=%d sends=%d window=%s body=%s", code, wh.tg.sends, wh.tg.sentWindow, body)
	}
	wh.tap("approve_writes", seed.Token) // the only tap
	if wh.tg.windowEdits != 1 || wh.status(seed.Token) != models.StatusApproved {
		t.Fatalf("window edits=%d status=%s", wh.tg.windowEdits, wh.status(seed.Token))
	}
	if code, body := wh.complete(seed.Token); code != http.StatusOK {
		t.Fatalf("seed write code=%d body=%s", code, body)
	}

	_, codes, _ := wh.submit(writeBody("mac-server", "agent-1", "WordPress.org 2FA (nerveband)", "update", `{"recovery codes":"aaaa-bbbb"}`), agentAddr)
	if wh.status(codes.Token) != models.StatusApproved {
		t.Fatal("recovery-code update to the item just written was not covered")
	}
	if code, body := wh.complete(codes.Token); code != http.StatusOK {
		t.Fatalf("codes write code=%d body=%s", code, body)
	}

	_, svn, _ := wh.submit(writeBody("mac-server", "agent-1", "WordPress.org SVN password (nerveband)", "create", `{"password":"svn-pass"}`), agentAddr)
	if wh.status(svn.Token) != models.StatusApproved {
		t.Fatal("new item inside the write window was not covered")
	}
	if code, body := wh.complete(svn.Token); code != http.StatusOK {
		t.Fatalf("svn write code=%d body=%s", code, body)
	}

	if wh.tg.sends != 1 || len(wh.tg.autoWrites) != 2 {
		t.Fatalf("approval messages=%d audit messages=%d, want 1 and 2", wh.tg.sends, len(wh.tg.autoWrites))
	}
	if wh.tg.autoWrites[0].Kind != models.AutoApprovedFollowUp || wh.tg.autoWrites[1].Kind != models.AutoApprovedWriteWindow {
		t.Fatalf("audit kinds = %#v", wh.tg.autoWrites)
	}
	want := []string{"create:WordPress.org 2FA (nerveband)", "update:WordPress.org 2FA (nerveband)", "create:WordPress.org SVN password (nerveband)"}
	if got := wh.connect.writeLog(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("Connect writes = %v", got)
	}
}

func TestWriteWindowStaysInsideItsScope(t *testing.T) {
	wh := newWriteHarness(t, "Existing prod key")
	_, first, _ := wh.submit(writeBody("mac-server", "agent-1", "New item", "create", `{"token":"v1"}`), agentAddr)
	wh.tap("approve_writes", first.Token)

	cases := []struct {
		name, machine, agent, addr, item, op string
	}{
		{"other agent on the same machine", "mac-server", "agent-2", agentAddr, "Other new item", "create"},
		{"other machine", "mac-laptop", "agent-1", "100.64.0.4:5000", "Other new item", "create"},
		{"update to an item the window did not write", "mac-server", "agent-1", agentAddr, "Existing prod key", "update"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sendsBefore := wh.tg.sends
			code, resp, body := wh.submit(writeBody(tc.machine, tc.agent, tc.item, tc.op, `{"token":"v2"}`), tc.addr)
			if code != http.StatusAccepted {
				t.Fatalf("code=%d body=%s", code, body)
			}
			if wh.status(resp.Token) != models.StatusPending || wh.tg.sends != sendsBefore+1 {
				t.Fatalf("status=%s sends=%d: write outside the window scope was auto-approved", wh.status(resp.Token), wh.tg.sends)
			}
		})
	}
}

func TestApproveOnceGrantsOnlySameItemFollowUp(t *testing.T) {
	wh := newWriteHarness(t, "Unrelated item")
	_, created, _ := wh.submit(writeBody("mac-server", "agent-1", "Play key", "create", `{"json":"{}"}`), agentAddr)
	wh.tap("approve", created.Token)
	if code, body := wh.complete(created.Token); code != http.StatusOK {
		t.Fatalf("create code=%d body=%s", code, body)
	}

	_, followUp, _ := wh.submit(writeBody("mac-server", "agent-1", "Play key", "update", `{"note":"rotated"}`), agentAddr)
	if wh.status(followUp.Token) != models.StatusApproved {
		t.Fatal("same-item follow-up was not approved")
	}
	_, other, _ := wh.submit(writeBody("mac-server", "agent-1", "Unrelated item", "update", `{"note":"x"}`), agentAddr)
	if wh.status(other.Token) != models.StatusPending {
		t.Fatal("update to a different item rode on the follow-up grant")
	}
	_, create, _ := wh.submit(writeBody("mac-server", "agent-1", "Expo token", "create", `{"token":"x"}`), agentAddr)
	if wh.status(create.Token) != models.StatusPending {
		t.Fatal("approve once opened a write window")
	}
}

func TestFollowUpApprovalsDoNotExtendThemselves(t *testing.T) {
	wh := newWriteHarness(t)
	wh.h.config.WriteFollowUpTTL = 50 * time.Millisecond
	_, created, _ := wh.submit(writeBody("m", "a", "Item", "create", `{"k":"v"}`), agentAddr)
	wh.tap("approve", created.Token)
	wh.complete(created.Token)
	_, first, _ := wh.submit(writeBody("m", "a", "Item", "update", `{"k":"v2"}`), agentAddr)
	if wh.status(first.Token) != models.StatusApproved {
		t.Fatal("first follow-up not covered")
	}
	wh.complete(first.Token)
	time.Sleep(80 * time.Millisecond)
	_, late, _ := wh.submit(writeBody("m", "a", "Item", "update", `{"k":"v3"}`), agentAddr)
	if wh.status(late.Token) != models.StatusPending {
		t.Fatal("a follow-up write renewed the follow-up grant")
	}
}

func TestRevokeClosesWindowAndItsFollowUps(t *testing.T) {
	wh := newWriteHarness(t)
	_, first, _ := wh.submit(writeBody("m", "a", "Item one", "create", `{"k":"v"}`), agentAddr)
	wh.tap("approve_writes", first.Token)
	wh.complete(first.Token)
	approved, _ := wh.store.GetByToken(first.Token)

	wh.h.HandleTelegramAction("cb", "revoke_window:"+approved.WriteWindowID, "nerveband")
	if wh.tg.revoked != 1 {
		t.Fatalf("revocation confirmations = %d", wh.tg.revoked)
	}
	_, create, _ := wh.submit(writeBody("m", "a", "Item two", "create", `{"k":"v"}`), agentAddr)
	_, update, _ := wh.submit(writeBody("m", "a", "Item one", "update", `{"k":"v2"}`), agentAddr)
	if wh.status(create.Token) != models.StatusPending || wh.status(update.Token) != models.StatusPending {
		t.Fatal("writes were auto-approved after the window was revoked")
	}
	wh.h.HandleTelegramAction("cb", "revoke_window:"+approved.WriteWindowID, "nerveband")
	if last := wh.tg.answers[len(wh.tg.answers)-1]; last != "Write window already closed" {
		t.Fatalf("second revoke answer = %q", last)
	}
}

func TestAutoApprovalFallsBackToTapWhenAuditFails(t *testing.T) {
	wh := newWriteHarness(t)
	_, first, _ := wh.submit(writeBody("m", "a", "Item one", "create", `{"k":"v"}`), agentAddr)
	wh.tap("approve_writes", first.Token)
	wh.tg.failAudit = true
	_, second, _ := wh.submit(writeBody("m", "a", "Item two", "create", `{"k":"v"}`), agentAddr)
	if wh.status(second.Token) != models.StatusPending || wh.tg.sends != 2 {
		t.Fatalf("status=%s sends=%d: write was auto-approved without an audit message", wh.status(second.Token), wh.tg.sends)
	}
}

func TestBatchWriteIsOneApprovalAndWritesEveryItem(t *testing.T) {
	wh := newWriteHarness(t, "ASC key")
	body := `{"vault":"AI Agents","machine":"m","reason":"store release credentials","mutations":[
		{"item":"Play service account","operation":"create","category":"API_CREDENTIAL","fields":{"credential":"play-json"}},
		{"item":"Expo token","operation":"create","fields":{"token":"expo"}},
		{"item":"ASC key","operation":"update","fields":{"p8":"asc"}}]}`
	code, resp, raw := wh.submit(body, agentAddr)
	if code != http.StatusAccepted || wh.tg.sends != 1 {
		t.Fatalf("code=%d sends=%d body=%s", code, wh.tg.sends, raw)
	}
	stored, _ := wh.store.GetByToken(resp.Token)
	if len(stored.Mutations) != 3 || stored.Action != "write" || stored.ExpiresAt.Sub(stored.RequestedAt) != time.Hour {
		t.Fatalf("stored batch = %+v", stored)
	}
	wh.tap("approve", resp.Token)
	code, out := wh.complete(resp.Token)
	if code != http.StatusOK || !strings.Contains(out, `"mutations"`) {
		t.Fatalf("batch completion code=%d body=%s", code, out)
	}
	for _, value := range []string{"play-json", "expo", `"asc"`} {
		if strings.Contains(out, value) {
			t.Fatalf("completion response leaked %s", value)
		}
	}
	want := "create:Play service account|create:Expo token|update:ASC key"
	if got := strings.Join(wh.connect.writeLog(), "|"); got != want {
		t.Fatalf("Connect writes = %s", got)
	}
	done, _ := wh.store.GetByToken(resp.Token)
	for _, m := range done.Mutations {
		for label, value := range m.Fields {
			if value != "" {
				t.Fatalf("value for %s kept in memory after completion", label)
			}
		}
	}
}

func TestBatchRetryAfterPartialFailureDoesNotDuplicate(t *testing.T) {
	wh := newWriteHarness(t)
	body := `{"vault":"AI Agents","machine":"m","reason":"store","mutations":[
		{"item":"First","operation":"create","fields":{"k":"1"}},
		{"item":"Second","operation":"create","fields":{"k":"2"}}]}`
	_, resp, _ := wh.submit(body, agentAddr)
	wh.tap("approve", resp.Token)
	wh.connect.failOn = "Second"
	code, out := wh.complete(resp.Token)
	if code != http.StatusInternalServerError || !strings.Contains(out, "Wrote 1 of 2 items") {
		t.Fatalf("partial failure code=%d body=%s", code, out)
	}
	wh.connect.failOn = ""
	if code, out := wh.complete(resp.Token); code != http.StatusOK {
		t.Fatalf("retry code=%d body=%s", code, out)
	}
	if got := strings.Join(wh.connect.writeLog(), "|"); got != "create:First|create:Second" {
		t.Fatalf("Connect writes = %s", got)
	}
}

func TestBatchValidation(t *testing.T) {
	wh := newWriteHarness(t)
	cases := map[string]string{
		"duplicate item":  `{"vault":"AI Agents","machine":"m","reason":"r","mutations":[{"item":"A","operation":"create","fields":{"k":"v"}},{"item":"A","operation":"create","fields":{"j":"v"}}]}`,
		"no vault":        `{"machine":"m","reason":"r","mutations":[{"item":"A","operation":"create","fields":{"k":"v"}}]}`,
		"both shapes":     `{"secret_name":"A","vault":"AI Agents","machine":"m","reason":"r","mutation":{"operation":"create","fields":{"k":"v"}},"mutations":[{"item":"B","operation":"create","fields":{"k":"v"}}]}`,
		"bad operation":   `{"vault":"AI Agents","machine":"m","reason":"r","mutations":[{"item":"A","operation":"delete","fields":{"k":"v"}}]}`,
		"secrets present": `{"vault":"AI Agents","machine":"m","reason":"r","secrets":[{"secret_name":"A"}],"mutations":[{"item":"A","operation":"create","fields":{"k":"v"}}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if code, _, raw := wh.submit(body, agentAddr); code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s", code, raw)
			}
		})
	}
	if wh.tg.sends != 0 {
		t.Fatalf("invalid batches reached Telegram: %d", wh.tg.sends)
	}
}

func TestTapOnExpiredWriteDoesNotApprove(t *testing.T) {
	wh := newWriteHarness(t)
	_, resp, _ := wh.submit(writeBody("m", "a", "Item", "create", `{"k":"secret"}`), agentAddr)
	req, _ := wh.store.GetByToken(resp.Token)
	req.ExpiresAt = time.Now().Add(-time.Second)
	if err := wh.store.Update(req); err != nil {
		t.Fatal(err)
	}
	wh.h.HandleTelegramAction("cb", "approve:"+req.ID, "nerveband")
	if wh.status(resp.Token) != models.StatusExpired || wh.tg.expiredEdits != 1 {
		t.Fatalf("status=%s expired edits=%d", wh.status(resp.Token), wh.tg.expiredEdits)
	}
	if !strings.Contains(wh.tg.answers[0], "expired") {
		t.Fatalf("answer = %q", wh.tg.answers[0])
	}
}

func TestSweepRemindsOnceThenClosesExpiredWrite(t *testing.T) {
	wh := newWriteHarness(t)
	_, resp, _ := wh.submit(writeBody("m", "a", "Item", "create", `{"k":"secret"}`), agentAddr)
	req, _ := wh.store.GetByToken(resp.Token)

	wh.h.SweepPending(req.ExpiresAt.Add(-11 * time.Minute))
	if wh.tg.reminders != 0 {
		t.Fatal("reminder sent too early")
	}
	wh.h.SweepPending(req.ExpiresAt.Add(-9 * time.Minute))
	wh.h.SweepPending(req.ExpiresAt.Add(-8 * time.Minute))
	if wh.tg.reminders != 1 {
		t.Fatalf("reminders = %d, want exactly 1", wh.tg.reminders)
	}
	wh.h.SweepPending(req.ExpiresAt.Add(time.Second))
	wh.h.SweepPending(req.ExpiresAt.Add(2 * time.Second))
	if wh.tg.expiredEdits != 1 {
		t.Fatalf("expired edits = %d, want 1", wh.tg.expiredEdits)
	}
	expired, _ := wh.store.GetByToken(resp.Token)
	if expired.Status != models.StatusExpired || expired.Mutations[0].Fields["k"] != "" {
		t.Fatalf("expired request status=%s value kept=%v", expired.Status, expired.Mutations[0].Fields["k"] != "")
	}
}

type fakePushWard struct {
	sent     []string
	resolved []string
	onAnswer func(data, approver string)
}

func (f *fakePushWard) SendApprovalRequest(req *models.ApprovalRequest, _ time.Duration) (string, error) {
	slug := "sg-" + req.ID
	f.sent = append(f.sent, slug)
	return slug, nil
}
func (f *fakePushWard) UpdateApprovalRequest(string, *models.ApprovalRequest, time.Duration) error {
	return nil
}
func (f *fakePushWard) WatchApproval(_ *models.ApprovalRequest, _ string, onAnswer func(data, approver string)) {
	f.onAnswer = onAnswer
}
func (f *fakePushWard) ResolveActivity(_ string, slug string) error {
	f.resolved = append(f.resolved, slug)
	return nil
}
func (f *fakePushWard) SendAutoApprovedNotification(*models.ApprovalRequest, string, time.Time) error {
	return nil
}
func (f *fakePushWard) SendWriteAutoApproved(*models.ApprovalRequest, writegrant.Match) error {
	return nil
}
func (f *fakePushWard) SendReminder(*models.ApprovalRequest) error { return nil }
func (f *fakePushWard) SendWindowRevoked(writegrant.Window, string, int) error {
	return nil
}
func (f *fakePushWard) SendWriteBlocked(*models.ApprovalRequest, string) error { return nil }

func TestPushWardAnswerUpdatesTelegramAndTelegramTapResolvesPushWard(t *testing.T) {
	wh := newWriteHarness(t)
	pw := &fakePushWard{}
	wh.h.SetPushWardClient(pw)

	code, r1, _ := wh.submit(writeBody("m", "a", "Item1", "create", `{"k":"v1"}`), agentAddr)
	if code != http.StatusAccepted || len(pw.sent) != 1 || pw.onAnswer == nil {
		t.Fatalf("r1 code=%d pw.sent=%v", code, pw.sent)
	}
	req1, _ := wh.store.GetByToken(r1.Token)
	pw.onAnswer("approve:"+req1.ID, "pushward")
	if wh.status(r1.Token) != models.StatusApproved {
		t.Fatalf("r1 status=%s, want approved", wh.status(r1.Token))
	}
	if len(pw.resolved) != 0 {
		t.Fatalf("PushWard-originated tap should not re-delete activity: %v", pw.resolved)
	}

	_, r2, _ := wh.submit(writeBody("m", "a", "Item2", "create", `{"k":"v2"}`), agentAddr)
	wh.tap("approve", r2.Token)
	req2, _ := wh.store.GetByToken(r2.Token)
	if len(pw.resolved) != 1 || pw.resolved[0] != "sg-"+req2.ID {
		t.Fatalf("Telegram tap did not resolve PushWard activity: %v", pw.resolved)
	}
}
