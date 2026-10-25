package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/johnuopini/secret-gate/internal/requeststate"
)

// newApprovalServer scripts a submit → pending → approved → secret flow.
func newApprovalServer(t *testing.T, approveAfter int32) *httptest.Server {
	t.Helper()
	var polls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{
			"token": "tok123", "status_url": "http://" + r.Host + "/status/tok123",
			"expires_at": "2026-08-15T13:00:00Z", "message": "pending",
		})
	})
	mux.HandleFunc("/status/tok123", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&polls, 1) <= approveAfter {
			json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status": "approved", "secret_url": "http://" + r.Host + "/secret/tok123",
		})
	})
	mux.HandleFunc("/secret/tok123", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"credential": "fake-api-key-123456"},
		})
	})
	mux.HandleFunc("/fields", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not_found", "message": "no such item"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type memDaemon struct {
	running bool
	data    map[string]map[string]string
	watches []daemon.WatchSpec
}

func newMemDaemon() *memDaemon {
	return &memDaemon{running: true, data: map[string]map[string]string{}}
}

func (m *memDaemon) IsRunning() bool { return m.running }
func (m *memDaemon) StatusInfo() (*DaemonStatusResult, error) {
	return &DaemonStatusResult{Running: m.running, EntryCount: len(m.data)}, nil
}
func (m *memDaemon) Get(name, vault string) (map[string]string, error) {
	if f, ok := m.data[name]; ok {
		return f, nil
	}
	return nil, E(ErrNotFound, "not cached", "")
}
func (m *memDaemon) Store(name, vault string, fields map[string]string, ttl int) error {
	m.data[name] = fields
	return nil
}
func (m *memDaemon) EnsureRunning() error { m.running = true; return nil }
func (m *memDaemon) Watch(spec daemon.WatchSpec) error {
	m.watches = append(m.watches, spec)
	return nil
}
func (m *memDaemon) Unwatch(token string) error { return nil }
func TestProxySubmitReturnsPendingRequest(t *testing.T) {
	srv := newApprovalServer(t, 1000)
	pc := NewHTTPProxyClient(srv.URL, newMemDaemon(), 3600)
	async := pc.(AsyncProxyClient)

	pending, err := async.Submit(context.Background(), "deploy-key", "Infra", "deploy the service", nil, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Token != "tok123" || pending.StatusURL == "" || pending.ExpiresAt == "" {
		t.Fatalf("pending = %+v", pending)
	}
}

func TestProxyStatusAndRetrieve(t *testing.T) {
	srv := newApprovalServer(t, 0)
	dc := newMemDaemon()
	pc := NewHTTPProxyClient(srv.URL, dc, 3600)
	async := pc.(AsyncProxyClient)

	st, err := async.Status(context.Background(), srv.URL+"/status/tok123")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "approved" || st.SecretURL == "" {
		t.Fatalf("status = %+v", st)
	}

	result, err := async.Retrieve(context.Background(), st.SecretURL, "deploy-key", "Infra")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "approved" || !result.Cached {
		t.Fatalf("result = %+v", result)
	}
	if _, err := dc.Get("deploy-key", "Infra"); err != nil {
		t.Fatal("approved secret was not cached in daemon")
	}
}

func TestProxyRequestFullFlow(t *testing.T) {
	srv := newApprovalServer(t, 2)
	pc := NewHTTPProxyClient(srv.URL, newMemDaemon(), 3600).(*httpProxyClient)
	pc.pollInterval = 10 * time.Millisecond
	pc.pollTimeout = 5 * time.Second

	result, err := pc.Request(context.Background(), "deploy-key", "Infra", "deploy", nil, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "approved" {
		t.Fatalf("status = %q, want approved", result.Status)
	}
}

func TestProxyErrorCodes(t *testing.T) {
	srv := newApprovalServer(t, 0)
	pc := NewHTTPProxyClient(srv.URL, newMemDaemon(), 3600)

	if _, err := pc.GetFields("ghost", ""); CodeOf(err) != ErrNotFound {
		t.Fatalf("404 GetFields: CodeOf = %v, want not_found", CodeOf(err))
	}

	dead := NewHTTPProxyClient("http://127.0.0.1:1", newMemDaemon(), 3600)
	if _, err := dead.Search("x", 5); CodeOf(err) != ErrNetwork {
		t.Fatalf("connection refused: CodeOf = %v, want network", CodeOf(err))
	}
}

func TestProxyStatusWaitLongPoll(t *testing.T) {
	mux := http.NewServeMux()
	var waitReceived string
	mux.HandleFunc("/status/tok-wait", func(w http.ResponseWriter, r *http.Request) {
		waitReceived = r.URL.Query().Get("wait")
		json.NewEncoder(w).Encode(map[string]string{"status": "pending", "message": "waiting"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pc := NewHTTPProxyClient(srv.URL, newMemDaemon(), 3600)
	async := pc.(AsyncProxyClient)

	st, err := async.StatusWait(context.Background(), srv.URL+"/status/tok-wait", 20)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "pending" {
		t.Fatalf("status = %v", st.Status)
	}
	if waitReceived != "20" {
		t.Fatalf("expected wait=20 query param, got %q", waitReceived)
	}
}

func TestProxyHybridWaitRegistersReadWatcher(t *testing.T) {
	t.Setenv("PASEO_AGENT_ID", "agent-test")
	srv := newApprovalServer(t, 1_000_000_000)
	dc := newMemDaemon()
	stateDir := t.TempDir()
	pc := NewHTTPProxyClient(srv.URL, dc, 3600, stateDir).(*httpProxyClient)
	pc.syncWait = 50 * time.Millisecond
	pc.pollInterval = 10 * time.Millisecond
	pc.pollTimeout = 5 * time.Second

	result, err := pc.Request(context.Background(), "deploy-key", "Infra", "deploy", nil, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" {
		t.Fatalf("expected pending status on hybrid yield, got %q", result.Status)
	}
	if result.Token != "tok123" {
		t.Fatalf("expected token tok123, got %q", result.Token)
	}
	if result.Resume == "" {
		t.Fatal("pending request did not expose a recorded resume command")
	}
	ledger, err := requeststate.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok, err := ledger.Get("tok123")
	if err != nil || !ok || entry.Operation != "read" {
		t.Fatalf("ledger entry = %+v, ok=%v, err=%v", entry, ok, err)
	}
	if len(dc.watches) != 1 {
		t.Fatalf("watch count = %d, want 1", len(dc.watches))
	}
	if dc.watches[0].Token != "tok123" || dc.watches[0].IsMutation {
		t.Fatalf("read watch = %+v", dc.watches[0])
	}
	if activation := dc.watches[0].Activation; activation == nil || activation.PaseoAgentID != "agent-test" {
		t.Fatalf("read activation = %+v", activation)
	}
}

func TestProxyHybridWaitRegistersMutationWatcher(t *testing.T) {
	t.Setenv("PASEO_AGENT_ID", "agent-test")
	srv := newApprovalServer(t, 1_000_000_000)
	dc := newMemDaemon()
	pc := NewHTTPProxyClient(srv.URL, dc, 3600).(*httpProxyClient)
	pc.syncWait = 50 * time.Millisecond
	pc.pollTimeout = 5 * time.Second

	result, err := pc.Write(context.Background(), "ci-token", "Infra", "rotate", "update", "", map[string]string{"credential": "replacement"}, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" {
		t.Fatalf("status = %q, want pending", result.Status)
	}
	if len(dc.watches) != 1 {
		t.Fatalf("watch count = %d, want 1", len(dc.watches))
	}
	if watch := dc.watches[0]; watch.Token != "tok123" || !watch.IsMutation {
		t.Fatalf("mutation watch = %+v", watch)
	}
	if activation := dc.watches[0].Activation; activation == nil || activation.PaseoAgentID != "agent-test" {
		t.Fatalf("mutation activation = %+v", activation)
	}
}

func TestEnrichRequestContextUsesPaseoIdentityWithoutCodexFallback(t *testing.T) {
	t.Setenv("PASEO_AGENT_ID", "agent-test")
	t.Setenv("PASEO_AGENT_PROVIDER", "Oh My Pi")
	got := enrichRequestContext(RequestContext{}, "devbox", "deploy release")
	if got.Runtime != "Paseo" || got.Provider != "Oh My Pi" || got.PaseoAgentID != "agent-test" {
		t.Fatalf("context = %#v", got)
	}
	if got.Task != "deploy release" || got.Project == "" {
		t.Fatalf("context defaults = %#v", got)
	}
}

func TestEnrichRequestContextPreservesExplicitIdentity(t *testing.T) {
	t.Setenv("PASEO_AGENT_ID", "agent-env")
	t.Setenv("PASEO_AGENT_PROVIDER", "env-provider")
	input := RequestContext{Runtime: "custom-runtime", Provider: "custom-provider", PaseoAgentID: "agent-explicit"}
	got := enrichRequestContext(input, "devbox", "task")
	if got.Runtime != input.Runtime || got.Provider != input.Provider || got.PaseoAgentID != input.PaseoAgentID {
		t.Fatalf("context = %#v", got)
	}
}

func TestSubmitWritePayloadShapes(t *testing.T) {
	var got []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, body)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok", "status_url": "http://gate/status/tok"})
	}))
	defer server.Close()
	pc := NewHTTPProxyClient(server.URL, nil, 0).(WriteClient)

	single := []ItemWrite{{Item: "Expo token", Operation: "create", Fields: map[string]string{"token": "v"}}}
	if _, err := pc.SubmitWrite(context.Background(), "AI Agents", "store", single, RequestContext{}); err != nil {
		t.Fatal(err)
	}
	batch := append(single, ItemWrite{Item: "ASC key", Operation: "update", Fields: map[string]string{"p8": "v"}})
	if _, err := pc.SubmitWrite(context.Background(), "AI Agents", "store", batch, RequestContext{}); err != nil {
		t.Fatal(err)
	}
	// Single writes keep the original wire shape for older servers.
	if got[0]["secret_name"] != "Expo token" || got[0]["mutation"] == nil || got[0]["mutations"] != nil {
		t.Fatalf("single payload = %v", got[0])
	}
	// Batches carry no secret_name or secrets, so a server without batch
	// support rejects them instead of treating them as a read.
	if got[1]["secret_name"] != "" || got[1]["secrets"] != nil || got[1]["mutation"] != nil || len(got[1]["mutations"].([]any)) != 2 {
		t.Fatalf("batch payload = %v", got[1])
	}
}
