package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/requeststate"
)

func TestMutationWatcherRetriesCompletionUntilSuccess(t *testing.T) {
	var attempts atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/status/tok", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "secret_url": server.URL + "/secret/tok"})
	})
	mux.HandleFunc("/secret/tok", func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			http.Error(w, "temporary", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"mutation": map[string]string{"status": "completed"}})
	})

	watcher := NewWatcher(NewCache(), time.Hour)
	if registered, err := watcher.Register(WatchSpec{Token: "tok", StatusURL: server.URL + "/status/tok", SecretName: "item", IsMutation: true, ExpiresAt: time.Now().Add(15 * time.Second).Format(time.RFC3339)}); err != nil || !registered {
		t.Fatalf("register watch: registered=%v err=%v", registered, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for watcher.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if watcher.Count() != 0 {
		t.Fatal("watcher did not finish")
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("completion attempts = %d, want 3", got)
	}
}

func TestApprovedCompletionFailureEndsFailed(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/status/tok-fail", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved", "secret_url": server.URL + "/secret/tok-fail"})
	})
	mux.HandleFunc("/secret/tok-fail", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "temporary", http.StatusInternalServerError)
	})
	stateDir := t.TempDir()
	ledger, err := requeststate.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Put(requeststate.Entry{Token: "tok-fail", SecretName: "item", State: "pending"}); err != nil {
		t.Fatal(err)
	}
	watcher := NewWatcher(NewCache(), time.Hour)
	expires := time.Now().Add(1500 * time.Millisecond).Format(time.RFC3339Nano)
	registered, err := watcher.Register(WatchSpec{Token: "tok-fail", StatusURL: server.URL + "/status/tok-fail", SecretName: "item", IsMutation: true, StateDir: stateDir, ExpiresAt: expires})
	if err != nil || !registered {
		t.Fatalf("register: registered=%v err=%v", registered, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for watcher.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	entry, ok, err := ledger.Get("tok-fail")
	if err != nil || !ok || entry.State != "failed" {
		t.Fatalf("ledger entry = %+v, ok=%v, err=%v", entry, ok, err)
	}
}
