package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/autosession"
	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
)

type fakeTelegram struct {
	sends       int
	edits       int
	reminders   int
	blocked     int
	blockedText string
}

func (f *fakeTelegram) SendApprovalRequest(*models.ApprovalRequest, string, time.Duration) (int, error) {
	f.sends++
	return 123, nil
}

func (f *fakeTelegram) SendAutoApprovedNotification(*models.ApprovalRequest, string, time.Time) error {
	return nil
}

func (f *fakeTelegram) UpdateApprovalRequest(int, *models.ApprovalRequest, time.Duration) error {
	f.edits++
	return nil
}

func (f *fakeTelegram) SendApprovalReminder(*models.ApprovalRequest) error {
	f.reminders++
	return nil
}

func (f *fakeTelegram) SendWriteBlocked(_ *models.ApprovalRequest, detail string) error {
	f.blocked++
	f.blockedText = detail
	return nil
}

func TestNormalizeRequesterIP(t *testing.T) {
	tests := map[string]string{
		"172.18.0.1:60562":          "172.18.0.1",
		"10.0.0.5":                  "10.0.0.5",
		"10.0.0.5, 192.168.1.10":    "10.0.0.5",
		"[2001:db8::1]:443":         "2001:db8::1",
		"2001:db8::1":               "2001:db8::1",
		" 10.0.0.5 , 192.168.1.10 ": "10.0.0.5",
	}

	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := normalizeRequesterIP(input); got != want {
				t.Fatalf("normalizeRequesterIP(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestHandleSecretAppliesApprovedMutation(t *testing.T) {
	connectWrites := 0
	connect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]opconnect.Vault{{ID: "vault-id", Name: "Agents"}})
		case "/v1/vaults/vault-id/items":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			connectWrites++
			var item opconnect.Item
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(item)
		default:
			t.Fatalf("unexpected Connect path %s", r.URL.Path)
		}
	}))
	defer connect.Close()
	requests := store.New()
	req, err := models.NewApprovalRequest("Release context", "Agents", "devbox", "127.0.0.1", "store context", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req.Secrets = []models.SecretRequest{{SecretName: "Release context", Vault: "Agents"}}
	req.Mutation = &models.ItemMutation{Operation: "create", Fields: map[string]string{"notes": "context"}}
	req.Approve()
	if err := requests.Save(req); err != nil {
		t.Fatal(err)
	}
	h := New(requests, opconnect.New(connect.URL, "test-token"), nil, &config.Config{}, autosession.NewStore())
	httpReq := httptest.NewRequest(http.MethodGet, "/secret/"+req.Token, nil)
	recorder := httptest.NewRecorder()
	h.HandleSecret(recorder, httpReq)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	stored, err := requests.GetByToken(req.Token)
	if err != nil || stored.MutationState != "completed" {
		t.Fatalf("stored mutation = %+v, err=%v", stored, err)
	}
	replay := httptest.NewRecorder()
	h.HandleSecret(replay, httptest.NewRequest(http.MethodGet, "/secret/"+req.Token, nil))
	if replay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, body = %s", replay.Code, replay.Body.String())
	}
	if connectWrites != 1 {
		t.Fatalf("Connect writes = %d, want 1", connectWrites)
	}
}

func TestOpenAPISpecDescribesMutationsAndFieldSelectors(t *testing.T) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(OpenAPISpec()), &spec); err != nil {
		t.Fatalf("OpenAPI is invalid JSON: %v", err)
	}
	info := spec["info"].(map[string]any)
	if info["version"] != "0.5.0" {
		t.Fatalf("version = %v", info["version"])
	}
	paths := spec["paths"].(map[string]any)
	requestPost := paths["/request"].(map[string]any)["post"].(map[string]any)
	content := requestPost["requestBody"].(map[string]any)["content"].(map[string]any)
	properties := content["application/json"].(map[string]any)["schema"].(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"context", "mutation"} {
		if _, ok := properties[name]; !ok {
			t.Errorf("request schema missing %s", name)
		}
	}
}

func TestHandleStatusImmediate(t *testing.T) {
	requests := store.New()
	req, err := models.NewApprovalRequest("MySecret", "Personal", "devbox", "127.0.0.1", "read", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := requests.Save(req); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{WebhookBaseURL: "http://127.0.0.1:8080"}
	h := New(requests, nil, nil, cfg, autosession.NewStore())

	httpReq := httptest.NewRequest(http.MethodGet, "/status/"+req.Token, nil)
	recorder := httptest.NewRecorder()
	h.HandleStatus(recorder, httpReq)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var resp StatusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "pending" {
		t.Fatalf("expected pending, got %s", resp.Status)
	}
}

func TestHandleStatusLongPollApproval(t *testing.T) {
	requests := store.New()
	req, err := models.NewApprovalRequest("MySecret", "Personal", "devbox", "127.0.0.1", "read", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := requests.Save(req); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{WebhookBaseURL: "http://127.0.0.1:8080", LongPollMaxWait: 5 * time.Second}
	h := New(requests, nil, nil, cfg, autosession.NewStore())

	// Start long-poll in background
	done := make(chan struct{})
	var recorder *httptest.ResponseRecorder
	go func() {
		defer close(done)
		httpReq := httptest.NewRequest(http.MethodGet, "/status/"+req.Token+"?wait=4", nil)
		recorder = httptest.NewRecorder()
		h.HandleStatus(recorder, httpReq)
	}()

	// Simulate approval after 50ms
	time.Sleep(50 * time.Millisecond)
	req.Approve()
	if err := requests.Update(req); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		var resp StatusResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Status != "approved" {
			t.Fatalf("expected approved, got %s", resp.Status)
		}
		if resp.SecretURL == "" {
			t.Fatal("expected non-empty SecretURL on approval")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for long-poll response on approval")
	}
}

func TestHandleStatusLongPollTimeout(t *testing.T) {
	requests := store.New()
	req, err := models.NewApprovalRequest("MySecret", "Personal", "devbox", "127.0.0.1", "read", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := requests.Save(req); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{WebhookBaseURL: "http://127.0.0.1:8080", LongPollMaxWait: 5 * time.Second}
	h := New(requests, nil, nil, cfg, autosession.NewStore())

	start := time.Now()
	httpReq := httptest.NewRequest(http.MethodGet, "/status/"+req.Token+"?wait=1", nil)
	recorder := httptest.NewRecorder()
	h.HandleStatus(recorder, httpReq)

	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("expected elapsed ~1s, got %v", elapsed)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var resp StatusResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "pending" {
		t.Fatalf("expected pending on timeout, got %s", resp.Status)
	}
}

func TestHandleRequestRenewsEquivalentPendingRequest(t *testing.T) {
	connect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]opconnect.Vault{{ID: "vault-id", Name: "AI Agents"}})
		case "/v1/vaults/vault-id/items":
			_ = json.NewEncoder(w).Encode([]opconnect.Item{{ID: "item-id", Title: "Deploy key"}})
		case "/v1/vaults/vault-id/items/item-id":
			_ = json.NewEncoder(w).Encode(opconnect.Item{ID: "item-id", Title: "Deploy key", Vault: opconnect.Vault{ID: "vault-id"}, Fields: []opconnect.Field{{ID: "password", Label: "password", Type: "CONCEALED"}}})
		default:
			t.Fatalf("unexpected Connect path %s", r.URL.Path)
		}
	}))
	defer connect.Close()

	tg := &fakeTelegram{}

	requests := store.New()
	cfg := &config.Config{WebhookBaseURL: "http://gate", RequestTTL: 15 * time.Minute, AutoApproveTTL: 30 * time.Minute}
	h := New(requests, opconnect.New(connect.URL, "token"), tg, cfg, autosession.NewStore())
	body := `{"secret_name":"Deploy key","vault":"AI Agents","machine":"devbox","reason":"deploy release","context":{"runtime":"Paseo","provider":"Oh My Pi","model":"gpt-5.6-sol","think":"high","project":"secret-gate"},"secrets":[{"secret_name":"Deploy key","vault":"AI Agents","fields":["password"]}]}`

	var responses []RequestResponse
	for range 2 {
		recorder := httptest.NewRecorder()
		h.HandleRequest(recorder, httptest.NewRequest(http.MethodPost, "/request", bytes.NewBufferString(body)))
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
		}
		var response RequestResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	if responses[0].Token != responses[1].Token || responses[0].RequestReused || !responses[1].RequestReused {
		t.Fatalf("responses = %#v", responses)
	}
	if requests.Count() != 1 || tg.sends != 1 || tg.edits != 1 || tg.reminders != 1 {
		t.Fatalf("count=%d sends=%d edits=%d reminders=%d", requests.Count(), tg.sends, tg.edits, tg.reminders)
	}
}

func TestHandleRequestBlocksReadOnlyWriteBeforeApproval(t *testing.T) {
	connect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]opconnect.Vault{{ID: "vault-id", Name: "AI Agents"}})
		case "/v1/vaults/vault-id/items":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Fatalf("unexpected Connect path %s", r.URL.Path)
		}
	}))
	defer connect.Close()
	tg := &fakeTelegram{}
	requests := store.New()
	h := New(requests, opconnect.New(connect.URL, "token"), tg, &config.Config{WebhookBaseURL: "http://gate", RequestTTL: time.Minute}, autosession.NewStore())
	body := `{"secret_name":"Release context","vault":"AI Agents","machine":"devbox","reason":"store release","mutation":{"operation":"update","fields":{"notes":"secret value"}}}`
	recorder := httptest.NewRecorder()
	h.HandleRequest(recorder, httptest.NewRequest(http.MethodPost, "/request", strings.NewReader(body)))
	if recorder.Code != http.StatusForbidden || requests.Count() != 0 {
		t.Fatalf("status=%d count=%d body=%s", recorder.Code, requests.Count(), recorder.Body.String())
	}
	if tg.blocked != 1 || !strings.Contains(tg.blockedText, "read-only") {
		t.Fatalf("blocked notification count=%d text=%q", tg.blocked, tg.blockedText)
	}
}
