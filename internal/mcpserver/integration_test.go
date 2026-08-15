package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

type intSearchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

type intFieldsResponse struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

type intRequestResponse struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
}

type intStatusResponse struct {
	Status    string `json:"status"`
	SecretURL string `json:"secret_url,omitempty"`
}

type intSecretResponse struct {
	Secrets map[string]map[string]string `json:"secrets"`
}

func TestIntegration_FullFlow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	// 1. Create mock HTTP proxy server
	var mockURL string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(intSearchResponse{
				Results: []SearchResultItem{
					{SecretName: "test-key", VaultName: "test-vault", Score: 1.0, MatchType: "exact"},
				},
				Query: "test",
			})

		case r.URL.Path == "/fields" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(intFieldsResponse{
				SecretName: "test-key",
				VaultName:  "test-vault",
				Fields: []FieldInfo{
					{Label: "password", Type: "concealed"},
				},
			})

		case r.URL.Path == "/request" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(intRequestResponse{
				Token:     "test-token",
				StatusURL: mockURL + "/status/test-token",
				ExpiresAt: "2099-01-01T00:00:00Z",
			})

		case r.URL.Path == "/status/test-token" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(intStatusResponse{
				Status:    "approved",
				SecretURL: mockURL + "/secret/test-token",
			})

		case r.URL.Path == "/secret/test-token" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(intSecretResponse{
				Secrets: map[string]map[string]string{"test-key": {"password": "test-value"}},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()
	mockURL = mockServer.URL

	// 2. Create mock daemon client
	dc := newMockDaemonClient(true)

	// 3. Create real httpProxyClient pointing to mock server
	pc := NewHTTPProxyClient(mockServer.URL, dc, 3600)

	ctx := context.Background()

	// 4. Test search_secrets
	t.Run("search_secrets", func(t *testing.T) {
		res, out, err := handleSearchSecrets(ctx, pc, SearchSecretsInput{
			Query: "test",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil CallToolResult for success, got: %v", res)
		}
		if out.Count != 1 {
			t.Errorf("expected 1 result, got %d", out.Count)
		}
		if len(out.Results) != 1 || out.Results[0].SecretName != "test-key" {
			t.Errorf("unexpected results: %+v", out.Results)
		}
	})

	// 5. Test inspect_fields
	t.Run("inspect_fields", func(t *testing.T) {
		res, out, err := handleInspectFields(ctx, pc, InspectFieldsInput{
			SecretName: "test-key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil CallToolResult for success, got: %v", res)
		}
		if len(out.Fields) != 1 || out.Fields[0].Label != "password" {
			t.Errorf("unexpected fields: %+v", out.Fields)
		}
	})

	// 6. Test request_secret (full polling flow through real httpProxyClient)
	t.Run("request_secret", func(t *testing.T) {
		res, out, err := handleRequestSecret(ctx, dc, pc, RequestSecretInput{
			SecretName: "test-key",
			Reason:     "integration testing",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil CallToolResult for success, got: %v", res)
		}
		if out.Status != "approved" {
			t.Errorf("expected status 'approved', got %q", out.Status)
		}
		if !out.Cached {
			t.Error("expected cached=true")
		}

		// Verify secret is in daemon cache
		cached, err := dc.Get("test-key", "")
		if err != nil {
			t.Fatalf("failed to get from cache: %v", err)
		}
		if cached["password"] != "test-value" {
			t.Errorf("expected cached password='test-value', got %q", cached["password"])
		}
	})

	// 7. Test exec_with_secret using the cached secret
	t.Run("exec_with_secret", func(t *testing.T) {
		res, out, err := handleExecWithSecret(ctx, dc, ExecWithSecretInput{
			SecretName: "test-key",
			Field:      "password",
			EnvVar:     "MY_SECRET",
			Command:    "echo $MY_SECRET",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil CallToolResult for success, got: %v", res)
		}
		if out.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", out.ExitCode)
		}
		if !strings.Contains(out.Stdout, "[REDACTED:test-key/password]") {
			t.Errorf("expected stdout to contain redacted secret, got %q", out.Stdout)
		}
		if strings.Contains(out.Stdout, "test-value") {
			t.Errorf("expected secret value to be redacted, got raw value in stdout: %q", out.Stdout)
		}
	})
}
