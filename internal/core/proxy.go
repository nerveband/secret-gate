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
	"strconv"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/johnuopini/secret-gate/internal/requeststate"
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
	waitClient   *http.Client
	ledger       *requeststate.Ledger
	ledgerErr    error
	pollInterval time.Duration
	pollTimeout  time.Duration
	syncWait     time.Duration
}

// NewHTTPProxyClient creates a ProxyClient that talks to the secret-gate
// server. The returned client also implements AsyncProxyClient.
func NewHTTPProxyClient(serverURL string, dc FullDaemonClient, cacheTTLSec int, stateDirs ...string) ProxyClient {
	var ledger *requeststate.Ledger
	var ledgerErr error
	if len(stateDirs) > 0 && stateDirs[0] != "" {
		ledger, ledgerErr = requeststate.Open(stateDirs[0])
	}
	return &httpProxyClient{
		serverURL:    serverURL,
		dc:           dc,
		cacheTTLSec:  cacheTTLSec,
		ledger:       ledger,
		ledgerErr:    ledgerErr,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		waitClient:   &http.Client{Timeout: 0},
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
		syncWait:     defaultSyncWait(),
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
	Token         string `json:"token"`
	StatusURL     string `json:"status_url"`
	ExpiresAt     string `json:"expires_at"`
	Message       string `json:"message"`
	RequestReused bool   `json:"request_reused,omitempty"`
}

type statusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type secretResponse struct {
	Secret  map[string]string            `json:"secret"`
	Secrets map[string]map[string]string `json:"secrets"`
	Vault   string                       `json:"vault,omitempty"`
	Vaults  map[string]string            `json:"vaults,omitempty"`
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
		switch errResp.Error {
		case string(ErrVaultWriteUnavailable):
			code = ErrVaultWriteUnavailable
		case string(ErrWriteCapabilityUnknown):
			code = ErrWriteCapabilityUnknown
		}
		return E(code, errResp.Message, capabilityHint(code))
	}
	return E(code, fmt.Sprintf("server returned status %d: %s", status, string(body)), "")
}

func capabilityHint(code ErrCode) string {
	if code == ErrVaultWriteUnavailable {
		return "grant the configured 1Password Connect token write access to the target vault, then retry"
	}
	if code == ErrWriteCapabilityUnknown {
		return "restore 1Password Connect connectivity or configure verifiable write access, then retry"
	}
	return ""
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
	return p.waitLoop(ctx, pending, secretName, vault, true, fields)
}

func (p *httpProxyClient) Write(ctx context.Context, secretName, vault, reason, operation, category string, fields map[string]string, requestContext RequestContext) (*RequestResult, error) {
	hostname, _ := os.Hostname()
	requestContext = enrichRequestContext(requestContext, hostname, reason)
	payload := requestPayload{
		SecretName: secretName, Vault: vault, Machine: hostname, Reason: reason,
		Action:   operation,
		Secrets:  []secretRequestPayload{{SecretName: secretName, Vault: vault}},
		Context:  requestContext,
		Mutation: &mutationPayload{Operation: operation, Category: category, Fields: fields},
	}
	pending, err := p.post(payload)
	if err != nil {
		return nil, err
	}
	return p.waitLoop(ctx, pending, secretName, vault, false, nil)
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
	return &PendingRequest{Token: reqResp.Token, StatusURL: reqResp.StatusURL, ExpiresAt: reqResp.ExpiresAt, RequestReused: reqResp.RequestReused}, nil
}

func (p *httpProxyClient) Status(ctx context.Context, statusURL string) (*StatusResult, error) {
	return p.StatusWait(ctx, statusURL, 0)
}

func (p *httpProxyClient) StatusWait(ctx context.Context, statusURL string, waitSec int) (*StatusResult, error) {
	targetURL := statusURL
	if waitSec > 0 {
		sep := "?"
		if strings.Contains(statusURL, "?") {
			sep = "&"
		}
		targetURL = fmt.Sprintf("%s%swait=%d", statusURL, sep, waitSec)
	}

	reqTimeout := time.Duration(waitSec+10) * time.Second
	if reqTimeout < 30*time.Second {
		reqTimeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, E(ErrInternal, "creating status request: "+err.Error(), "")
	}

	client := p.waitClient
	if client == nil {
		client = p.httpClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, E(ErrNetwork, "querying status: "+err.Error(), "")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, E(ErrInternal, "reading status response: "+err.Error(), "")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, E(ErrNotFound, "request not found or expired", "")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, E(ErrNetwork, fmt.Sprintf("status returned HTTP %d: %s", resp.StatusCode, string(respBody)), "")
	}

	var status statusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, E(ErrInternal, "parsing status response: "+err.Error(), "")
	}
	return &StatusResult{Status: status.Status, Message: status.Message, SecretURL: status.SecretURL}, nil
}

func defaultSyncWait() time.Duration {
	if val := os.Getenv("SECRET_GATE_SYNC_WAIT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			return d
		}
		if s, err := strconv.Atoi(val); err == nil && s > 0 {
			return time.Duration(s) * time.Second
		}
	}
	return 0
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

	if p.dc != nil {
		if err := p.dc.EnsureRunning(); err != nil {
			return nil, E(ErrInternal, "secret was approved but the local daemon could not start: "+err.Error(),
				"retry the request after restoring the local daemon")
		}
		resolvedVault := secretResp.Vault
		if resolvedVault == "" {
			resolvedVault = secretResp.Vaults[secretName]
		}
		if resolvedVault == "" && len(secretResp.Vaults) == 1 {
			for _, only := range secretResp.Vaults {
				resolvedVault = only
			}
		}
		if resolvedVault == "" {
			resolvedVault = vault
		}
		if err := p.dc.Store(secretName, resolvedVault, fields, p.cacheTTLSec); err != nil {
			return nil, E(ErrInternal, "secret was approved but could not be cached locally: "+err.Error(),
				"submit a new approval request; the one-time response has already been consumed")
		}
		if vault != resolvedVault {
			if err := p.dc.Store(secretName, vault, fields, p.cacheTTLSec); err != nil {
				return nil, E(ErrInternal, "secret was approved but its requested-vault cache alias failed: "+err.Error(), "")
			}
		}
	}
	return &RequestResult{
		Status:          "approved",
		SecretName:      secretName,
		Cached:          p.dc != nil,
		FieldsAvailable: FieldNames(fields),
		Message:         "Secret approved and cached. Use exec, ssh, otp, or item read --reveal to use it.",
	}, nil
}

func (p *httpProxyClient) waitLoop(ctx context.Context, pending *PendingRequest, secretName, vault string, cache bool, fields []string) (*RequestResult, error) {
	deadline := time.After(p.pollTimeout)
	var syncDeadline <-chan time.Time
	if p.syncWait > 0 {
		syncDeadline = time.After(p.syncWait)
	}

	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return &RequestResult{Status: "timeout", SecretName: secretName, Message: "Timed out waiting for approval."}, nil
		case <-syncDeadline:
			if p.dc == nil {
				return nil, E(ErrInternal, "approval is still pending and no local daemon is available to finish it", "")
			}
			operation := "read"
			if !cache {
				operation = "write"
			}
			stateDir := ""
			if p.ledger != nil {
				stateDir = p.ledger.Dir()
				if err := p.ledger.Put(requeststate.Entry{
					Token: pending.Token, SecretName: secretName, Vault: vault,
					StatusURL: pending.StatusURL, SubmittedAt: time.Now().UTC().Format(time.RFC3339),
					ExpiresAt: pending.ExpiresAt, Operation: operation, State: "pending",
				}); err != nil {
					return nil, E(ErrInternal, "approval is pending but request recovery state could not be saved: "+err.Error(), "")
				}
			}
			if p.ledgerErr != nil {
				return nil, E(ErrInternal, "approval is pending but request recovery state is unavailable: "+p.ledgerErr.Error(), "")
			}
			if err := p.dc.Watch(daemon.WatchSpec{
				Token:       pending.Token,
				StatusURL:   pending.StatusURL,
				SecretName:  secretName,
				Vault:       vault,
				Fields:      fields,
				IsMutation:  !cache,
				CacheTTLSec: p.cacheTTLSec,
				ExpiresAt:   pending.ExpiresAt,
				Activation:  daemon.SniffActivationSpec(),
				StateDir:    stateDir,
			}); err != nil {
				return nil, E(ErrInternal, "approval is still pending and the local watcher could not start: "+err.Error(), "")
			}
			result := &RequestResult{
				Status: "pending", SecretName: secretName, Token: pending.Token, ExpiresAt: pending.ExpiresAt,
				RequestReused: pending.RequestReused,
				Message:       "Approval pending on Telegram. The local watcher will finish the operation and notify this agent.",
			}
			if p.ledger != nil {
				result.Resume = fmt.Sprintf("secret-gate request wait %s", pending.Token)
			}
			return result, nil
		default:
		}

		status, err := p.StatusWait(ctx, pending.StatusURL, 25)
		if err != nil {
			if CodeOf(err) == ErrNotFound && p.dc != nil && p.dc.IsRunning() {
				if cached, _ := p.dc.Get(secretName, vault); cached != nil {
					return &RequestResult{
						Status:          "approved",
						SecretName:      secretName,
						Cached:          true,
						FieldsAvailable: FieldNames(cached),
						Message:         "Secret approved and cached in daemon.",
					}, nil
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-deadline:
				return &RequestResult{Status: "timeout", SecretName: secretName, Message: "Timed out waiting for approval."}, nil
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		backoff = 500 * time.Millisecond

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

// enrichRequestContext fills approver-facing context from env and cwd
// (moved verbatim from internal/mcpserver/proxy.go).
func enrichRequestContext(requestContext RequestContext, hostname, reason string) RequestContext {
	if requestContext.PaseoAgentID == "" {
		requestContext.PaseoAgentID = firstEnv("PASEO_AGENT_ID", "SECRET_GATE_PASEO_AGENT_ID")
	}
	if requestContext.Runtime == "" {
		requestContext.Runtime = firstEnv("SECRET_GATE_RUNTIME", "PASEO_RUNTIME")
		if requestContext.Runtime == "" && requestContext.PaseoAgentID != "" {
			requestContext.Runtime = "Paseo"
		}
	}
	if requestContext.Provider == "" {
		requestContext.Provider = firstEnv("SECRET_GATE_PROVIDER", "PASEO_PROVIDER", "PASEO_AGENT_PROVIDER", "OMP_PROVIDER")
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
