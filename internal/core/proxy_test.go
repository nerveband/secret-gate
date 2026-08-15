package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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
}

func newMemDaemon() *memDaemon { return &memDaemon{running: true, data: map[string]map[string]string{}} }

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
