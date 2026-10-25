package daemon

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Approved attachments are cached as base64 field values, far larger than
// bufio.Scanner's 64 KiB default line limit.
func TestClientRoundTripsAttachmentSizedValues(t *testing.T) {
	sockPath := shortSocketPath(t)
	srv := NewServer(sockPath, time.Hour)
	go srv.Run()
	defer srv.Stop()
	time.Sleep(50 * time.Millisecond)

	value := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 3<<20)))
	client := NewClient(sockPath)
	if err := client.Store("Release keys", "AI Agents", map[string]string{"file:app.aab": value}, 60); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := client.Get("Release keys", "AI Agents")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got["file:app.aab"] != value {
		t.Fatalf("cached value length %d, want %d", len(got["file:app.aab"]), len(value))
	}
}
