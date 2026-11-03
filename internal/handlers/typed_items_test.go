package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
)

// Test card values: a public Visa test number and made-up codes.
const (
	testCardNumber = "4111111111111111"
	testCVV        = "7319"
	testNewCVV     = "4682"
)

// captureLogs collects everything the handler logs while fn runs.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

func addCard(wh *writeHarness, title string) {
	wh.connect.mu.Lock()
	defer wh.connect.mu.Unlock()
	wh.connect.items["card-1"] = opconnect.Item{
		ID: "card-1", Title: title, Vault: opconnect.Vault{ID: "vid"}, Category: "CREDIT_CARD",
		Fields: []opconnect.Field{
			{ID: "cardholder", Label: "cardholder name", Type: "STRING", Value: "Test Holder"},
			{ID: "type", Label: "type", Type: "CREDIT_CARD_TYPE", Value: "visa"},
			{ID: "ccnum", Label: "number", Type: "CREDIT_CARD_NUMBER", Value: testCardNumber},
			{ID: "cvv", Label: "verification number", Type: "CONCEALED", Value: testCVV},
			{ID: "expiry", Label: "expiry date", Type: "MONTH_YEAR", Value: "202708"},
		},
	}
}

func readBody(item string, fields []string, purpose string) string {
	f, _ := json.Marshal(fields)
	return `{"secret_name":"` + item + `","vault":"AI Agents","machine":"m","reason":"pay for the flight","context":{"purpose":"` + purpose + `"},"secrets":[{"secret_name":"` + item + `","vault":"AI Agents","fields":` + string(f) + `}]}`
}

func assertNoValues(t *testing.T, where, text string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(text, v) {
			t.Errorf("%s contains a secret value", where)
		}
	}
}

func TestCardFieldsShowAMaskedViewWithoutApproval(t *testing.T) {
	wh := newWriteHarness(t)
	addCard(wh, "Visa travel")
	rec := httptest.NewRecorder()
	wh.h.HandleFields(rec, httptest.NewRequest(http.MethodPost, "/fields", strings.NewReader(`{"secret_name":"Visa travel","vault":"AI Agents"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("fields code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp FieldsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Category != "CREDIT_CARD" || resp.Card == nil || *resp.Card != (opconnect.CardSummary{Type: "Visa", Last4: "1111", Expiry: "08/2027"}) {
		t.Fatalf("masked view = %+v %+v", resp.Category, resp.Card)
	}
	processOnly := map[string]bool{}
	for _, f := range resp.Fields {
		processOnly[f.ID] = f.ProcessOnly
	}
	if !processOnly["ccnum"] || !processOnly["cvv"] || processOnly["expiry"] || processOnly["cardholder"] {
		t.Fatalf("process-only flags = %v", processOnly)
	}
	assertNoValues(t, "fields response", rec.Body.String(), testCardNumber, testCVV)
	if wh.tg.sends != 0 {
		t.Fatal("the masked view must not need approval")
	}
}

func TestCardReadNeedsPurposeAndItsOwnTap(t *testing.T) {
	wh := newWriteHarness(t)
	addCard(wh, "Visa travel")
	wh.h.sessions.Create("nerveband", 30*time.Minute) // an open read window

	logs := captureLogs(t, func() {
		code, _, body := wh.submit(readBody("Visa travel", []string{"number", "cvv"}, ""), agentAddr)
		if code != http.StatusUnprocessableEntity || wh.tg.sends != 0 || !strings.Contains(body, "purpose") {
			t.Fatalf("no purpose: code=%d sends=%d body=%s", code, wh.tg.sends, body)
		}

		code, resp, body := wh.submit(readBody("Visa travel", []string{"number", "cvv"}, "aa.com checkout"), agentAddr)
		if code != http.StatusAccepted || wh.tg.sends != 1 {
			t.Fatalf("with purpose: code=%d sends=%d body=%s", code, wh.tg.sends, body)
		}
		req, _ := wh.store.GetByToken(resp.Token)
		if req.Status != models.StatusPending {
			t.Fatal("the read window must not cover a card number or CVV")
		}
		if !req.Sensitive || req.Secrets[0].Summary != "Visa ending 1111, expires 08/2027" || req.Context.Purpose != "aa.com checkout" {
			t.Fatalf("request = sensitive %v summary %q purpose %q", req.Sensitive, req.Secrets[0].Summary, req.Context.Purpose)
		}
		view := wh.h.toApprovalView(req)
		for _, o := range view.Options {
			if o.ID == "approve_window" {
				t.Fatal("card reads must not offer a read window")
			}
		}
		if !strings.Contains(view.Summary, "Visa ending 1111") || !strings.Contains(view.Summary, "aa.com checkout") {
			t.Fatalf("approver summary = %q", view.Summary)
		}

		wh.tap("approve_window", resp.Token)
		if wh.status(resp.Token) != models.StatusPending {
			t.Fatal("approve_window approved a card read")
		}
		wh.tap("approve", resp.Token)
		code, secret := wh.complete(resp.Token)
		if code != http.StatusOK {
			t.Fatalf("secret code=%d", code)
		}
		var out BatchSecretResponse
		_ = json.Unmarshal([]byte(secret), &out)
		fields := out.Secrets["Visa travel"]
		if fields["number"] != testCardNumber || !strings.Contains(fields[models.ProcessOnlyKey], "number") || !strings.Contains(fields[models.ProcessOnlyKey], "cvv") {
			t.Fatalf("released keys = %v, marker %q", len(fields), fields[models.ProcessOnlyKey])
		}

		// Expiry alone is not process-only: no purpose needed, the window covers it.
		code, resp, _ = wh.submit(readBody("Visa travel", []string{"expiry"}, ""), agentAddr)
		if code != http.StatusAccepted || wh.status(resp.Token) != models.StatusApproved {
			t.Fatalf("expiry read code=%d", code)
		}
	})
	assertNoValues(t, "server log", logs, testCardNumber, testCVV)
}

func cardWriteBody(item, op, fields, owner string) string {
	return `{"secret_name":"` + item + `","vault":"AI Agents","machine":"mac-server","reason":"store the travel card","context":{"paseo_agent_id":"agent-1"},"mutation":{"operation":"` + op + `","category":"card","fields":` + fields + `,"owner_fields":` + owner + `}}`
}

func TestCardWritesUseNativeFieldsAndNeverRideWindows(t *testing.T) {
	wh := newWriteHarness(t)
	logs := captureLogs(t, func() {
		_, first, _ := wh.submit(writeBody("mac-server", "agent-1", "Plain token", "create", `{"token":"v1"}`), agentAddr)
		wh.tap("approve_writes", first.Token) // opens a write window
		wh.complete(first.Token)

		code, card, body := wh.submit(cardWriteBody("Visa travel", "create",
			`{"number":"4111 1111 1111 1111","cvv":"`+testCVV+`","expiry":"08/27","cardholder":"Test Holder","zip":"02139"}`, `[]`), agentAddr)
		if code != http.StatusAccepted || wh.status(card.Token) != models.StatusPending {
			t.Fatalf("card create code=%d body=%s: the write window must not cover card writes", code, body)
		}
		wh.tap("approve_writes", card.Token)
		if wh.status(card.Token) != models.StatusPending {
			t.Fatal("approve_writes approved a card write")
		}
		wh.tap("approve", card.Token)
		if code, body := wh.complete(card.Token); code != http.StatusOK {
			t.Fatalf("card write code=%d body=%s", code, body)
		}

		// A same-item follow-up would normally ride on the approval above.
		_, update, _ := wh.submit(cardWriteBody("Visa travel", "update", `{"cvv":"`+testNewCVV+`"}`, `[]`), agentAddr)
		if wh.status(update.Token) != models.StatusPending {
			t.Fatal("a follow-up grant covered a card update")
		}
		wh.tap("approve", update.Token)
		if code, body := wh.complete(update.Token); code != http.StatusOK {
			t.Fatalf("card update code=%d body=%s", code, body)
		}
	})
	assertNoValues(t, "server log", logs, testCardNumber, testCVV, testNewCVV)

	var saved opconnect.Item
	for _, it := range wh.connect.items {
		if it.Title == "Visa travel" {
			saved = it
		}
	}
	if saved.Category != "CREDIT_CARD" {
		t.Fatalf("category = %q", saved.Category)
	}
	byID := map[string]opconnect.Field{}
	for _, f := range saved.Fields {
		if _, dup := byID[f.ID]; dup {
			t.Fatalf("field %s appears twice", f.ID)
		}
		byID[f.ID] = f
	}
	checks := []struct{ id, typ, value string }{
		{"ccnum", "CREDIT_CARD_NUMBER", testCardNumber},
		{"cvv", "CONCEALED", testNewCVV},
		{"expiry", "MONTH_YEAR", "202708"},
		{"type", "CREDIT_CARD_TYPE", "visa"},
		{"cardholder", "STRING", "Test Holder"},
		{"zip", "STRING", "02139"},
	}
	for _, c := range checks {
		if f := byID[c.id]; f.Type != c.typ || f.Value != c.value {
			t.Errorf("%s = type %s, value ok %v", c.id, f.Type, f.Value == c.value)
		}
	}
	if f := byID["zip"]; f.Section == nil || f.Section.ID != "billing" {
		t.Fatalf("zip section = %+v", f.Section)
	}
}

func TestOwnerEntryApprovesTheWriteAndTheAgentNeverSeesTheValue(t *testing.T) {
	wh := newWriteHarness(t)
	addCard(wh, "Visa travel")
	var entryBodies []string
	logs := captureLogs(t, func() {
		code, resp, body := wh.submit(cardWriteBody("Visa travel", "update", `{}`, `["cvv"]`), agentAddr)
		if code != http.StatusAccepted {
			t.Fatalf("submit code=%d body=%s", code, body)
		}
		req, _ := wh.store.GetByToken(resp.Token)
		if !req.AwaitingOwner() || !req.Sensitive || !strings.HasPrefix(req.EntryURL, "http://gate/entry/") {
			t.Fatalf("entry request = awaiting %v sensitive %v url %q", req.AwaitingOwner(), req.Sensitive, req.EntryURL)
		}
		if strings.Contains(body, req.EntryToken) {
			t.Fatal("the entry link must not be returned to the agent")
		}
		view := wh.h.toApprovalView(req)
		if view.EntryURL != req.EntryURL || len(view.Options) != 1 || view.Options[0].ID != "deny" {
			t.Fatalf("approver view = url %q options %+v", view.EntryURL, view.Options)
		}

		wh.tap("approve", resp.Token)
		if wh.status(resp.Token) != models.StatusPending {
			t.Fatal("a tap approved a write that still needs owner values")
		}

		path := strings.TrimPrefix(req.EntryURL, "http://gate")
		get := httptest.NewRecorder()
		wh.h.HandleEntry(get, httptest.NewRequest(http.MethodGet, path, nil))
		if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `type="password"`) || !strings.Contains(get.Body.String(), "f_0_0") {
			t.Fatalf("entry page code=%d", get.Code)
		}
		if get.Header().Get("Cache-Control") != "no-store" || !strings.Contains(get.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatal("entry page must not be cached or framed")
		}

		post := func(value string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"f_0_0": {value}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			wh.h.HandleEntry(rec, r)
			entryBodies = append(entryBodies, rec.Body.String())
			return rec
		}
		if rec := post("46x2"); rec.Code != http.StatusUnprocessableEntity || wh.status(resp.Token) != models.StatusPending {
			t.Fatalf("bad CVV code=%d", rec.Code)
		}
		if rec := post(testNewCVV); rec.Code != http.StatusOK || wh.status(resp.Token) != models.StatusApproved {
			t.Fatalf("good CVV code=%d", rec.Code)
		}
		approved, _ := wh.store.GetByToken(resp.Token)
		if approved.Approver != EntryApprover {
			t.Fatalf("approver = %q", approved.Approver)
		}
		if code, body := wh.complete(resp.Token); code != http.StatusOK || strings.Contains(body, testNewCVV) {
			t.Fatalf("write code=%d (value in response: %v)", code, strings.Contains(body, testNewCVV))
		}
		again := httptest.NewRecorder()
		wh.h.HandleEntry(again, httptest.NewRequest(http.MethodGet, path, nil))
		if again.Code != http.StatusNotFound {
			t.Fatalf("used entry link code=%d", again.Code)
		}
	})
	assertNoValues(t, "server log", logs, testNewCVV, "46x2", testCardNumber)
	for _, b := range entryBodies {
		assertNoValues(t, "entry page", b, testNewCVV, "46x2")
	}
	for _, f := range wh.connect.items["card-1"].Fields {
		if f.ID == "cvv" && f.Value != testNewCVV {
			t.Fatal("the owner-entered CVV was not written")
		}
	}
	if n := len(wh.connect.items["card-1"].Fields); n != 5 {
		t.Fatalf("card has %d fields after the update, want 5 (no duplicate CVV)", n)
	}
}

func TestEntryPageRejectsUnknownTokens(t *testing.T) {
	wh := newWriteHarness(t)
	rec := httptest.NewRecorder()
	wh.h.HandleEntry(rec, httptest.NewRequest(http.MethodPost, "/entry/"+strings.Repeat("a", 64), strings.NewReader("f_0_0=1234")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code=%d", rec.Code)
	}
}
