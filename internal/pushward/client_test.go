package pushward

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestSealMatchesOfficialVectors(t *testing.T) {
	cases := []struct {
		name      string
		keyHex    string
		kid       string
		nonceHex  string
		plaintext string
		want      string
	}{
		{
			name:      "ascii_minimal",
			keyHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			kid:       "767c0806",
			nonceHex:  "a0a1a2a3a4a5a6a7a8a9aaab",
			plaintext: `{"title":"Disk full","body":"/var is at 97% on db01"}`,
			want:      "pw1.767c0806.oKGio6Slpqeoqaqr-DhDOK4k53I0XIqFXerStl8L5wgFH2EUp_HSYIhOtPQU6R9X6oBtcwaIVw6kyen5OK3Vm_WWiP9w4ooFbGhar_XGOj1J",
		},
		{
			name:      "all_fields",
			keyHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			kid:       "767c0806",
			nonceHex:  "b0b1b2b3b4b5b6b7b8b9babb",
			plaintext: `{"title":"Deploy failed","subtitle":"api / production","body":"Step 3 of 5: migrate","url":"https://ci.example.com/runs/42"}`,
			want:      "pw1.767c0806.sLGys7S1tre4ubq7IhPh2HTPPvERsgGYoC27nIBiuO1n26jrA8xe-tEjxm4TqS9Bvjvlk7iT6F2P5KlCpkPa2mhWw7jIM4ciWI-eOZX_y7gChNKTT5z0-Z3C4pvgrf51_B3c1EJd7-XCRvbzoYGXOg8lnpZ3E2khX_u-3A3DhSdDBl8xhacaTBCmoJCqY0n7LCxNegxPpiY",
		},
		{
			name:      "padded_to_64",
			keyHex:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			kid:       "767c0806",
			nonceHex:  "c0c1c2c3c4c5c6c7c8c9cacb",
			plaintext: "{\"title\":\"Padded\",\"body\":\"Trailing spaces pad the JSON to a multiple of 64 bytes\"}                                              ",
			want:      "pw1.767c0806.wMHCw8TFxsfIycrLIL1jgUniu_wlWES3R3GvrSURsiEs_B4jsQoxp0EscCyRO_CBFuKjKv1ykj5XyYw4a7-JpimC9ZeiCaYeyIE_ZVUbdgUKT341KKyE31GzM6HP5-c7qZ65f7Hww1pN4GsFwto4NdlMhHzOwz0rAbk-51gD4ugWs8T47DuXkhEaA9BJLLyegzqFXi6uvxY_rA1J",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kid, err := KeyID(tc.keyHex)
			if err != nil {
				t.Fatal(err)
			}
			if kid != tc.kid {
				t.Fatalf("KeyID = %q, want %q", kid, tc.kid)
			}
			nonce, err := hex.DecodeString(tc.nonceHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := sealPlaintextWithNonce(tc.keyHex, nonce, []byte(tc.plaintext))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("sealPlaintextWithNonce = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSendApprovalAndWatchAnswer(t *testing.T) {
	var mu sync.Mutex
	var created activityCreateRequest
	var patched activityPatchRequest
	var deleted string
	pollCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hlk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/activities":
			_ = json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"slug":"` + created.Slug + `","state":"ended"}`))
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/activities/"):
			_ = json.NewDecoder(r.Body).Decode(&patched)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"slug":"` + created.Slug + `","state":"ongoing"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/activities/"):
			pollCount++
			w.WriteHeader(http.StatusOK)
			if pollCount == 1 {
				_, _ = w.Write([]byte(`{"slug":"sg-req1","state":"ongoing","content":{"template":"approval"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"slug":"sg-req1","state":"ended","content":{"template":"approval","answer":{"option":"approve_window","at":1700000000,"by":"user"}}}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/activities/"):
			deleted = strings.TrimPrefix(r.URL.Path, "/activities/")
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c := New("hlk_test", "")
	c.SetBaseURL(srv.URL)

	req := &models.ApprovalRequest{
		ID:         "req1",
		SecretName: "Deploy Key",
		Vault:      "AI Agents",
		Reason:     "deploy service",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
		Secrets: []models.SecretRequest{{
			SecretName:  "Deploy Key",
			Vault:       "AI Agents",
			Fields:      []string{"private_key"},
			Attachments: []models.Attachment{{ID: "f1", Name: "cert.pem", Size: 512}},
		}},
	}
	slug, err := c.SendApprovalRequest(req, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if slug != "sg-req1" || created.Slug != "sg-req1" {
		t.Fatalf("slug = %q, created = %#v", slug, created)
	}
	if patched.Content.Template != "approval" || len(patched.Content.Options) != 3 || patched.Content.Options[0].Title != "Approve" {
		t.Fatalf("patched content = %#v", patched.Content)
	}
	if created.Name != "Read Deploy Key" || patched.Content.State != "deploy service" {
		t.Fatalf("name = %q, state = %q", created.Name, patched.Content.State)
	}
	if len(patched.Content.Details) != 1 || !strings.Contains(patched.Content.Details[0].Value, "📎 cert.pem") {
		t.Fatalf("details = %#v", patched.Content.Details)
	}

	gotCh := make(chan string, 1)
	c.WatchApproval(req, slug, func(data, approver string) {
		gotCh <- data + "@" + approver
	})
	select {
	case got := <-gotCh:
		if got != "approve_window:req1@pushward" {
			t.Fatalf("callback = %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for PushWard answer callback")
	}

	if err := c.ResolveActivity("req1", slug); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if deleted != "sg-req1" {
		t.Fatalf("deleted = %q, want sg-req1", deleted)
	}
}

func TestEncryptedAuditNotificationOmitsPlaintextFields(t *testing.T) {
	var got notificationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1}`))
	}))
	defer srv.Close()

	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	c := New("hlk_test", keyHex)
	c.SetBaseURL(srv.URL)

	req := &models.ApprovalRequest{
		ID:         "req1",
		SecretName: "Deploy Key",
		Vault:      "AI Agents",
		Reason:     "deploy service",
	}
	if err := c.SendAutoApprovedNotification(req, "nerveband", time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Encrypted, "pw1.767c0806.") {
		t.Fatalf("Encrypted = %q", got.Encrypted)
	}
	if got.Title != "" || got.Body != "" || got.Subtitle != "" {
		t.Fatalf("plaintext fields leaked alongside Encrypted: %#v", got)
	}
}
