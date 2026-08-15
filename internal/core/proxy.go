package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultPollInterval = 5 * time.Second
	defaultPollTimeout  = 15 * time.Minute
)

// httpProxyClient implements ProxyClient and AsyncProxyClient over the
// secret-gate server HTTP API.
type httpProxyClient struct {
	serverURL    string
	dc           FullDaemonClient
	cacheTTLSec  int
	httpClient   *http.Client
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// NewHTTPProxyClient creates a ProxyClient that talks to the secret-gate
// server. The returned client also implements AsyncProxyClient.
func NewHTTPProxyClient(serverURL string, dc FullDaemonClient, cacheTTLSec int) ProxyClient {
	return &httpProxyClient{
		serverURL:    serverURL,
		dc:           dc,
		cacheTTLSec:  cacheTTLSec,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

// --- HTTP wire types ---

type searchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

type searchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

type fieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

type fieldsResponse struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

type requestPayload struct {
	SecretName string                 `json:"secret_name"`
	Vault      string                 `json:"vault,omitempty"`
	Machine    string                 `json:"machine"`
	Reason     string                 `json:"reason,omitempty"`
	Action     string                 `json:"action,omitempty"`
	Secrets    []secretRequestPayload `json:"secrets,omitempty"`
	Context    RequestContext         `json:"context,omitempty"`
	Mutation   *mutationPayload       `json:"mutation,omitempty"`
}

type secretRequestPayload struct {
	SecretName string   `json:"secret_name"`
	Vault      string   `json:"vault,omitempty"`
	Fields     []string `json:"fields,omitempty"`
}

type mutationPayload struct {
	Operation string            `json:"operation"`
	Category  string            `json:"category,omitempty"`
	Fields    map[string]string `json:"fields"`
}

type requestResponse struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
	Message   string `json:"message"`
}

type statusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type secretResponse struct {
	Secret  map[string]string            `json:"secret"`
	Secrets map[string]map[string]string `json:"secrets"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// --- shared HTTP helpers ---

// postJSON posts a payload and returns the body when the status matches
// wantStatus. Non-matching statuses are decoded into coded errors:
// 404 → ErrNotFound, everything else → ErrNetwork.
func (p *httpProxyClient) postJSON(path string, payload any, wantStatus int) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, E(ErrInternal, "marshaling request: "+err.Error(), "")
	}
	resp, err := p.httpClient.Post(p.serverURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, E(ErrNetwork, "request to "+path+" failed: "+err.Error(),
			"check that the secret-gate server is reachable")
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, E(ErrNetwork, "reading response: "+err.Error(), "")
	}
	if resp.StatusCode != wantStatus {
		return nil, httpError(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func (p *httpProxyClient) getJSON(url string) ([]byte, error) {
	resp, err := p.httpClient.Get(url)
	if err != nil {
		return nil, E(ErrNetwork, "request failed: "+err.Error(),
			"check that the secret-gate server is reachable")
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, E(ErrNetwork, "reading response: "+err.Error(), "")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp.StatusCode, respBody)
	}
	return respBody, nil
}

func httpError(status int, body []byte) error {
	code := ErrNetwork
	if status == http.StatusNotFound {
		code = ErrNotFound
	}
	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Message != "" {
		return E(code, fmt.Sprintf("%s: %s", errResp.Error, errResp.Message), "")
	}
	return E(code, fmt.Sprintf("server returned status %d: %s", status, string(body)), "")
}

// --- ProxyClient implementation ---

func (p *httpProxyClient) Search(query string, limit int) ([]SearchResultItem, error) {
	respBody, err := p.postJSON("/search", searchPayload{Query: query, Limit: limit}, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var searchResp searchResponse
	if err := json.Unmarshal(respBody, &searchResp); err != nil {
		return nil, E(ErrInternal, "parsing search response: "+err.Error(), "")
	}
	if searchResp.Results == nil {
		searchResp.Results = []SearchResultItem{}
	}
	return searchResp.Results, nil
}

func (p *httpProxyClient) GetFields(secretName, vault string) (*FieldsResult, error) {
	respBody, err := p.postJSON("/fields", fieldsPayload{SecretName: secretName, Vault: vault}, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var fieldsResp fieldsResponse
	if err := json.Unmarshal(respBody, &fieldsResp); err != nil {
		return nil, E(ErrInternal, "parsing fields response: "+err.Error(), "")
	}
	return &FieldsResult{
		SecretName: fieldsResp.SecretName,
		VaultName:  fieldsResp.VaultName,
		Fields:     fieldsResp.Fields,
	}, nil
}

func (p *httpProxyClient) Request(ctx context.Context, secretName, vault, reason string, fields []string, requestContext RequestContext) (*RequestResult, error) {
	pending, err := p.Submit(ctx, secretName, vault, reason, fields, requestContext)
	if err != nil {
		return nil, err
	}
	return p.waitLoop(ctx, pending, secretName, vault, true)
}

func (p *httpProxyClient) Write(ctx context.Context, secretName, vault, reason, operation, category string, fields map[string]string, requestContext RequestContext) (*RequestResult, error) {
	hostname, _ := os.Hostname()
	requestContext = enrichRequestContext(requestContext, hostname, reason)
	payload := requestPayload{
		SecretName: secretName, Vault: vault, Machine: hostname, Reason: reason,
		Action:  operation,
		Secrets: []secretRequestPayload{{SecretName: secretName, Vault: vault}},
		Context: requestContext,
		Mutation: &mutationPayload{Operation: operation, Category: category, Fields: fields},
	}
	pending, err := p.post(payload)
	if err != nil {
		return nil, err
	}
	return p.waitLoop(ctx, pending, secretName, vault, false)
}

// --- AsyncProxyClient implementation ---

func (p *httpProxyClient) Submit(ctx context.Context, secretName, vault, reason string, fields []string, requestContext RequestContext) (*PendingRequest, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "mcp-agent"
	}
	requestContext = enrichRequestContext(requestContext, hostname, reason)
	payload := requestPayload{
		SecretName: secretName, Vault: vault, Machine: hostname, Reason: reason,
		Action:  "read",
		Secrets: []secretRequestPayload{{SecretName: secretName, Vault: vault, Fields: fields}},
		Context: requestContext,
	}
	return p.post(payload)
}

func (p *httpProxyClient) post(payload requestPayload) (*PendingRequest, error) {
	respBody, err := p.postJSON("/request", payload, http.StatusAccepted)
	if err != nil {
		return nil, err
	}
	var reqResp requestResponse
	if err := json.Unmarshal(respBody, &reqResp); err != nil {
		return nil, E(ErrInternal, "parsing request response: "+err.Error(), "")
	}
	return &PendingRequest{Token: reqResp.Token, StatusURL: reqResp.StatusURL, ExpiresAt: reqResp.ExpiresAt}, nil
}

func (p *httpProxyClient) Status(_ context.Context, statusURL string) (*StatusResult, error) {
	respBody, err := p.getJSON(statusURL)
	if err != nil {
		return nil, err
	}
	var status statusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, E(ErrInternal, "parsing status response: "+err.Error(), "")
	}
	return &StatusResult{Status: status.Status, Message: status.Message, SecretURL: status.SecretURL}, nil
}

func (p *httpProxyClient) Retrieve(_ context.Context, secretURL, secretName, vault string) (*RequestResult, error) {
	respBody, err := p.getJSON(secretURL)
	if err != nil {
		return nil, err
	}
	var secretResp secretResponse
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, E(ErrInternal, "parsing secret response: "+err.Error(), "")
	}
	fields := secretResp.Secret
	if fields == nil && len(secretResp.Secrets) > 0 {
		fields = secretResp.Secrets[secretName]
		if fields == nil && len(secretResp.Secrets) == 1 {
			for _, only := range secretResp.Secrets {
				fields = only
			}
		}
	}
	if fields == nil {
		return nil, E(ErrInternal, fmt.Sprintf("secret response did not contain fields for %q", secretName), "")
	}

	result := &RequestResult{
		Status:          "approved",
		SecretName:      secretName,
		Cached:          true,
		FieldsAvailable: FieldNames(fields),
		Message:         "Secret approved and cached. Use exec, ssh, otp, or item read --reveal to use it.",
	}
	if p.dc != nil {
		if err := p.dc.EnsureRunning(); err != nil {
			result.Message = "Warning: secret approved but daemon failed to start: " + err.Error()
		} else if err := p.dc.Store(secretName, vault, fields, p.cacheTTLSec); err != nil {
			result.Message = "Warning: secret approved but caching failed: " + err.Error()
		}
	}
	return result, nil
}

// waitLoop polls the status URL until a terminal state or timeout.
func (p *httpProxyClient) waitLoop(ctx context.Context, pending *PendingRequest, secretName, vault string, cache bool) (*RequestResult, error) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()
	deadline := time.After(p.pollTimeout)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return &RequestResult{Status: "timeout", SecretName: secretName, Message: "Timed out waiting for approval."}, nil
		case <-ticker.C:
			status, err := p.Status(ctx, pending.StatusURL)
			if err != nil {
				continue
			}
			switch status.Status {
			case "pending":
				continue
			case "approved":
				if cache {
					return p.Retrieve(ctx, status.SecretURL, secretName, vault)
				}
				if _, err := p.getJSON(status.SecretURL); err != nil {
					return nil, err
				}
				return &RequestResult{Status: "completed", SecretName: secretName, Message: "1Password item written after approval."}, nil
			case "denied":
				return &RequestResult{Status: "denied", SecretName: secretName, Message: "Request was denied by the approver."}, nil
			case "expired":
				return &RequestResult{Status: "expired", SecretName: secretName, Message: "Request expired before approval."}, nil
			default:
				return nil, E(ErrInternal, "unknown status: "+status.Status, "")
			}
		}
	}
}

// enrichRequestContext fills approver-facing context from env and cwd
// (moved verbatim from internal/mcpserver/proxy.go).
func enrichRequestContext(requestContext RequestContext, hostname, reason string) RequestContext {
	if requestContext.Agent == "" {
		requestContext.Agent = firstEnv("SECRET_GATE_AGENT", "CODEX_AGENT_NAME")
		if requestContext.Agent == "" {
			requestContext.Agent = "Codex"
		}
	}
	if requestContext.Model == "" {
		requestContext.Model = firstEnv("SECRET_GATE_MODEL", "OPENAI_MODEL", "CODEX_MODEL")
	}
	if requestContext.Think == "" {
		requestContext.Think = firstEnv("SECRET_GATE_THINK", "CODEX_REASONING_EFFORT")
	}
	if requestContext.Project == "" {
		if wd, err := os.Getwd(); err == nil {
			requestContext.Project = filepath.Base(wd)
		}
		if requestContext.Project == "" {
			requestContext.Project = hostname
		}
	}
	if requestContext.Task == "" {
		requestContext.Task = reason
	}
	return requestContext
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
