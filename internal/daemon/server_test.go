package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func sendRequest(t *testing.T, conn net.Conn, req Request) Response {
	t.Helper()
	data, _ := json.Marshal(req)
	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write request: %v", err)
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		t.Fatalf("unmarshal response: %v (raw: %s)", err, string(buf[:n]))
	}
	return resp
}

func TestServerStoreAndGet(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp := sendRequest(t, conn, Request{
		Command:    CmdStore,
		SecretName: "my-secret",
		Vault:      "vault1",
		Fields:     map[string]string{"password": "abc123"},
		TTLSeconds: 3600,
	})
	if !resp.OK {
		t.Fatalf("store failed: %s", resp.Error)
	}

	conn2, _ := net.Dial("unix", sockPath)
	defer conn2.Close()

	resp = sendRequest(t, conn2, Request{
		Command:    CmdGet,
		SecretName: "my-secret",
		Vault:      "vault1",
	})
	if !resp.OK {
		t.Fatalf("get failed: %s", resp.Error)
	}
	if resp.Fields["password"] != "abc123" {
		t.Errorf("password = %q, want abc123", resp.Fields["password"])
	}
}

func TestServerCacheMiss(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	defer conn.Close()

	resp := sendRequest(t, conn, Request{
		Command:    CmdGet,
		SecretName: "nonexistent",
		Vault:      "vault1",
	})
	if resp.OK {
		t.Error("expected cache miss to return ok=false")
	}
}

func TestServerStatus(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	defer conn.Close()

	resp := sendRequest(t, conn, Request{Command: CmdStatus})
	if !resp.OK {
		t.Fatalf("status failed: %s", resp.Error)
	}
	if resp.Status == nil {
		t.Fatal("status response is nil")
	}
	if resp.Status.SocketPath != sockPath {
		t.Errorf("socket path = %q, want %q", resp.Status.SocketPath, sockPath)
	}
}

func TestServerFlush(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)

	go srv.Run()
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	sendRequest(t, conn, Request{
		Command:    CmdStore,
		SecretName: "s1",
		Vault:      "v1",
		Fields:     map[string]string{"a": "1"},
		TTLSeconds: 3600,
	})
	conn.Close()

	conn2, _ := net.Dial("unix", sockPath)
	resp := sendRequest(t, conn2, Request{Command: CmdFlush})
	conn2.Close()

	if !resp.OK {
		t.Fatalf("flush failed: %s", resp.Error)
	}

	conn3, _ := net.Dial("unix", sockPath)
	defer conn3.Close()

	resp = sendRequest(t, conn3, Request{Command: CmdStatus})
	if resp.Status.EntryCount != 0 {
		t.Errorf("entry count after flush = %d, want 0", resp.Status.EntryCount)
	}
}

func TestServerStopDuringStartup(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, time.Hour)

	done := make(chan error, 1)
	go func() { done <- srv.Run() }()
	srv.Stop()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() after immediate Stop() = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not exit after immediate Stop()")
	}
}

func TestServerWatchAndAutoCache(t *testing.T) {
	var approved atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/status/tok-w1", func(w http.ResponseWriter, r *http.Request) {
		if !approved.Load() {
			json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "approved",
			"secret_url": "http://" + r.Host + "/secret/tok-w1",
		})
	})
	mux.HandleFunc("/secret/tok-w1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"api_key": "secret-val-999"},
		})
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()

	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)
	err := client.Watch(WatchSpec{
		Token:       "tok-w1",
		StatusURL:   mockServer.URL + "/status/tok-w1",
		SecretName:  "watched-api",
		Vault:       "Production",
		CacheTTLSec: 3600,
	})
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Verify it shows up in status/list
	status, err := client.Status()
	if err != nil || status.WatchCount != 1 {
		t.Fatalf("expected 1 active watch, got %v (err: %v)", status.WatchCount, err)
	}

	// Trigger approval on mock server
	approved.Store(true)

	// Wait for watcher to poll, retrieve, and cache
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fields, err := client.Get("watched-api", "Production")
		if err == nil && fields["api_key"] == "secret-val-999" {
			return // Success!
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for watcher to cache secret")
}

func TestServerWatchActivationCommand(t *testing.T) {
	sentinelFile := filepath.Join(t.TempDir(), "activated.txt")
	mux := http.NewServeMux()
	mux.HandleFunc("/status/tok-act", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"status":     "approved",
			"secret_url": "http://" + r.Host + "/secret/tok-act",
		})
	})
	mux.HandleFunc("/secret/tok-act", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"secret": map[string]string{"key": "val"},
		})
	})
	mockServer := httptest.NewServer(mux)
	defer mockServer.Close()

	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)
	err := client.Watch(WatchSpec{
		Token:       "tok-act",
		StatusURL:   mockServer.URL + "/status/tok-act",
		SecretName:  "act-secret",
		Vault:       "Personal",
		CacheTTLSec: 3600,
		Activation: &ActivationSpec{
			Kind: "command",
			Argv: []string{"touch", sentinelFile},
		},
	})
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sentinelFile); err == nil {
			return // Sentinel file touched by activation!
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sentinel file was not created by activation command")
}

func TestServerUnwatch(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	srv := NewServer(sockPath, 1*time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)
	err := client.Watch(WatchSpec{
		Token:      "tok-unwatch",
		StatusURL:  "http://127.0.0.1:9999/status/tok-unwatch",
		SecretName: "unwatch-me",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Unwatch("tok-unwatch"); err != nil {
		t.Fatalf("Unwatch failed: %v", err)
	}

	status, err := client.Status()
	if err != nil || status.WatchCount != 0 {
		t.Fatalf("expected 0 watches after unwatch, got %d", status.WatchCount)
	}
}
