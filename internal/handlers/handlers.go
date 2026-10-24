package handlers

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/autosession"
	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
)

type telegramClient interface {
	SendApprovalRequest(*models.ApprovalRequest, string, time.Duration) (int, error)
	SendAutoApprovedNotification(*models.ApprovalRequest, string, time.Time) error
	UpdateApprovalRequest(int, *models.ApprovalRequest, time.Duration) error
	SendWriteBlocked(*models.ApprovalRequest, string) error
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	store     *store.Store
	opClient  *opconnect.Client
	tgClient  telegramClient
	config    *config.Config
	sessions  *autosession.Store
	requestMu sync.Mutex
	log       *logger.Logger
}

// New creates a new Handler
func New(s *store.Store, op *opconnect.Client, tg telegramClient, cfg *config.Config, sessions *autosession.Store) *Handler {
	return &Handler{
		store:    s,
		opClient: op,
		tgClient: tg,
		config:   cfg,
		sessions: sessions,
		log:      logger.New(),
	}
}

// SearchPayload is the JSON body for secret search
type SearchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

// SearchResponse contains search results
type SearchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

// SearchResultItem is a single search result
type SearchResultItem struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// FieldsPayload is the JSON body for fields request
type FieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

// FieldsResponse contains field metadata
type FieldsResponse struct {
	SecretName string                `json:"secret_name"`
	VaultName  string                `json:"vault_name"`
	Fields     []opconnect.FieldInfo `json:"fields"`
}

// BatchRequestPayload is the JSON body for batch secret requests
type BatchRequestPayload struct {
	// Batch mode
	Secrets []models.SecretRequest `json:"secrets,omitempty"`
	// Legacy single-item mode
	SecretName string `json:"secret_name,omitempty"`
	Vault      string `json:"vault,omitempty"`
	// Common fields
	Machine  string                `json:"machine"`
	Reason   string                `json:"reason,omitempty"`
	Action   string                `json:"action,omitempty"`
	Context  models.RequestContext `json:"context,omitempty"`
	Mutation *models.ItemMutation  `json:"mutation,omitempty"`
}

// RequestResponse is the response for a new secret request
type RequestResponse struct {
	Token         string `json:"token"`
	StatusURL     string `json:"status_url"`
	ExpiresAt     string `json:"expires_at"`
	Message       string `json:"message"`
	RequestReused bool   `json:"request_reused,omitempty"`
}

// StatusResponse is the response for status checks
type StatusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type SecretResponse struct {
	Secret map[string]string `json:"secret"`
	Vault  string            `json:"vault,omitempty"`
}

// BatchSecretResponse is the response containing multiple secrets.
type BatchSecretResponse struct {
	Secrets map[string]map[string]string `json:"secrets"`
	Vaults  map[string]string            `json:"vaults,omitempty"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// HandleRequest handles POST /request
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}
	h.requestMu.Lock()
	defer h.requestMu.Unlock()

	var payload BatchRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}
	secrets := payload.Secrets
	if len(secrets) == 0 && payload.SecretName != "" {
		secrets = []models.SecretRequest{{SecretName: payload.SecretName, Vault: payload.Vault}}
	}
	if len(secrets) == 0 {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name or secrets[] is required")
		return
	}
	if h.config.WebhookBaseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	if payload.Mutation == nil {
		for i := range secrets {
			_, actualVault, actualTitle, err := h.opClient.GetItemFields(secrets[i].Vault, secrets[i].SecretName)
			if err != nil {
				h.writeError(w, http.StatusForbidden, "secret_unavailable", "Secret Gate cannot verify read access to the requested item.")
				return
			}
			secrets[i].Vault = actualVault
			secrets[i].SecretName = actualTitle
		}
	}

	requesterIP := r.Header.Get("X-Forwarded-For")
	if requesterIP == "" {
		requesterIP = r.RemoteAddr
	}
	req, err := models.NewApprovalRequest(
		secrets[0].SecretName,
		secrets[0].Vault,
		payload.Machine,
		normalizeRequesterIP(requesterIP),
		payload.Reason,
		h.config.RequestTTL,
	)
	if err != nil {
		h.log.Error("Failed to create request", logger.F("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create request")
		return
	}
	req.Secrets = secrets
	req.Action = payload.Action
	if req.Action == "" {
		req.Action = "read"
	}
	req.Context = payload.Context
	req.Mutation = payload.Mutation

	if req.Mutation != nil {
		if len(secrets) != 1 || secrets[0].Vault == "" || secrets[0].Vault == "_auto_" {
			h.writeError(w, http.StatusBadRequest, "invalid_mutation", "writes require exactly one item and an explicit vault")
			return
		}
		if req.Mutation.Operation != "create" && req.Mutation.Operation != "update" {
			h.writeError(w, http.StatusBadRequest, "invalid_mutation", "mutation operation must be create or update")
			return
		}
		req.Action = req.Mutation.Operation
		capability := h.opClient.CheckWriteCapability(req.Vault)
		if !capability.Allowed {
			if notifyErr := h.tgClient.SendWriteBlocked(req, capability.Message); notifyErr != nil {
				h.log.Error("Failed to send blocked-write audit notification", logger.F("error", notifyErr.Error()))
			}
			status := http.StatusServiceUnavailable
			if capability.Code == "vault_write_unavailable" {
				status = http.StatusForbidden
			}
			h.writeError(w, status, capability.Code, capability.Message)
			return
		}
	}
	req.Fingerprint = fingerprintRequest(req)

	// Mutations always require a one-request approval.
	if session, ok := h.sessions.Match(); ok && req.Mutation == nil {
		req.Approve()
		if err := h.store.Save(req); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
			return
		}
		if err := h.tgClient.SendAutoApprovedNotification(req, session.Approver, session.ExpiresAt); err != nil {
			h.log.Error("Failed to send auto-approval audit notification", logger.F("error", err.Error(), "request_id", req.ID))
		}
		h.writeJSON(w, http.StatusAccepted, RequestResponse{
			Token:     req.Token,
			StatusURL: h.config.WebhookBaseURL + "/status/" + req.Token,
			ExpiresAt: req.ExpiresAt.Format(time.RFC3339),
			Message:   "Request auto-approved by active approval session.",
		})
		return
	}

	stored, reused, err := h.store.SaveOrRenew(req, h.config.RequestTTL)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return
	}
	req = stored
	if reused {
		if err := h.tgClient.UpdateApprovalRequest(req.TelegramMsgID, req, h.config.AutoApproveTTL); err != nil {
			h.writeError(w, http.StatusBadGateway, "telegram_delivery_failed", "Failed to refresh the existing Telegram approval request.")
			return
		}
	} else {
		msgID, sendErr := h.tgClient.SendApprovalRequest(req, h.config.WebhookBaseURL, h.config.AutoApproveTTL)
		if sendErr != nil {
			_ = h.store.Delete(req.Token)
			h.writeError(w, http.StatusBadGateway, "telegram_delivery_failed", "Failed to deliver the Telegram approval request.")
			return
		}
		req.TelegramMsgID = msgID
		if err := h.store.Update(req); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to record the Telegram approval request.")
			return
		}
	}

	message := "Request submitted. Waiting for human approval via Telegram."
	if reused {
		message = "An equivalent approval request is already pending. Secret Gate reused it without sending another Telegram message."
	}
	h.log.Info("Submitted approval request", logger.F(
		"request_id", req.ID,
		"request_reused", reused,
		"machine", req.RequesterMachine,
		"requester_ip", req.RequesterIP,
	))
	h.writeJSON(w, http.StatusAccepted, RequestResponse{
		Token:         req.Token,
		StatusURL:     h.config.WebhookBaseURL + "/status/" + req.Token,
		ExpiresAt:     req.ExpiresAt.Format(time.RFC3339),
		Message:       message,
		RequestReused: reused,
	})
}

func fingerprintRequest(req *models.ApprovalRequest) string {
	type fingerprintSecret struct {
		Name   string
		Vault  string
		Fields []string
	}
	type fingerprintMutation struct {
		Operation string
		Category  string
		Labels    []string
	}
	secrets := make([]fingerprintSecret, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		fields := append([]string(nil), secret.Fields...)
		sort.Strings(fields)
		secrets = append(secrets, fingerprintSecret{Name: secret.SecretName, Vault: secret.Vault, Fields: fields})
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].Vault != secrets[j].Vault {
			return secrets[i].Vault < secrets[j].Vault
		}
		return secrets[i].Name < secrets[j].Name
	})
	var mutation *fingerprintMutation
	if req.Mutation != nil {
		labels := make([]string, 0, len(req.Mutation.Fields))
		for label := range req.Mutation.Fields {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		mutation = &fingerprintMutation{Operation: req.Mutation.Operation, Category: req.Mutation.Category, Labels: labels}
	}
	canonical := struct {
		Action   string
		Secrets  []fingerprintSecret
		Context  models.RequestContext
		Reason   string
		Mutation *fingerprintMutation
	}{
		Action: req.Action, Secrets: secrets, Context: req.Context,
		Reason: strings.Join(strings.Fields(req.Reason), " "), Mutation: mutation,
	}
	payload, _ := json.Marshal(canonical)
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func normalizeRequesterIP(requesterIP string) string {
	if requesterIP == "" {
		return ""
	}
	if forwarded := strings.Split(requesterIP, ","); len(forwarded) > 0 {
		requesterIP = strings.TrimSpace(forwarded[0])
	}
	if host, _, err := net.SplitHostPort(requesterIP); err == nil {
		return host
	}
	return requesterIP
}

// HandleStatus handles GET /status/{token}
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/status/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	baseURL := h.config.WebhookBaseURL
	if baseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	waitParam := r.URL.Query().Get("wait")
	if waitParam != "" && req.Status == models.StatusPending && !req.IsExpired() {
		if waitSec, err := strconv.Atoi(waitParam); err == nil && waitSec > 0 {
			maxWait := h.config.LongPollMaxWait
			if maxWait <= 0 {
				maxWait = 25 * time.Second
			}
			waitDuration := time.Duration(waitSec) * time.Second
			if waitDuration > maxWait {
				waitDuration = maxWait
			}

			watchCh, cancel := h.store.Watch(token)
			if watchCh != nil {
				defer cancel()
				timer := time.NewTimer(waitDuration)
				defer timer.Stop()

				select {
				case <-r.Context().Done():
					return
				case status, ok := <-watchCh:
					if ok {
						if updatedReq, err := h.store.GetByToken(token); err == nil {
							req = updatedReq
						} else {
							req.Status = status
						}
					}
				case <-timer.C:
					if updatedReq, err := h.store.GetByToken(token); err == nil {
						req = updatedReq
					}
				}
			}
		}
	}

	var resp StatusResponse
	switch req.Status {
	case models.StatusPending:
		resp = StatusResponse{
			Status:  "pending",
			Message: "Waiting for human approval. Continue polling this endpoint.",
		}
	case models.StatusApproved:
		resp = StatusResponse{
			Status:    "approved",
			Message:   "Request approved! Retrieve your secret from secret_url.",
			SecretURL: baseURL + "/secret/" + token,
		}
	case models.StatusDenied:
		resp = StatusResponse{
			Status:  "denied",
			Message: "Request was denied by the approver.",
		}
	case models.StatusExpired:
		resp = StatusResponse{
			Status:  "expired",
			Message: "Request has expired. Please submit a new request.",
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// HandleSecret handles GET /secret/{token}
func (h *Handler) HandleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/secret/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	if !req.CanRetrieveSecret() {
		h.writeError(w, http.StatusForbidden, "not_approved", "Request is not approved or has expired")
		return
	}
	if req.Mutation != nil {
		claimed, state, claimErr := h.store.ClaimMutation(token)
		if claimErr != nil {
			h.writeError(w, http.StatusForbidden, "not_approved", "Request is not approved or has expired")
			return
		}
		if state == "completed" {
			h.writeJSON(w, http.StatusOK, map[string]any{"mutation": map[string]any{
				"status": "completed", "operation": claimed.Mutation.Operation,
				"item": claimed.MutationItem, "vault": claimed.Secrets[0].Vault,
			}})
			return
		}
		if state == "executing" {
			h.writeError(w, http.StatusConflict, "mutation_in_progress", "Approved mutation is already being executed")
			return
		}
		if state == "failed" {
			h.writeError(w, http.StatusInternalServerError, "mutation_outcome_unknown", "Approved mutation did not reach a recoverable completion state")
			return
		}
		s := claimed.Secrets[0]
		item, mutationErr := h.opClient.PutItem(s.Vault, s.SecretName, claimed.Mutation.Operation, claimed.Mutation.Category, claimed.Mutation.Fields)
		if mutationErr != nil {
			_ = h.store.ReleaseMutation(token)
			h.log.Error("Failed to write 1Password item", logger.F("error", mutationErr.Error(), "request_id", req.ID, "item", s.SecretName, "vault", s.Vault))
			var verr *opconnect.ValidationError
			if errors.As(mutationErr, &verr) {
				h.writeError(w, http.StatusUnprocessableEntity, "validation", "1Password rejected the item: "+verr.Message)
				return
			}
			h.writeError(w, http.StatusInternalServerError, "item_write_failed", "Failed to write item to 1Password")
			return
		}
		if err := h.store.CompleteMutation(token, item.Title); err != nil {
			h.log.Error("Failed to record completed 1Password write", logger.F("error", err.Error(), "request_id", req.ID))
			h.writeError(w, http.StatusInternalServerError, "mutation_state_failed", "Item was written but completion state could not be recorded")
			return
		}
		h.log.Info("1Password item written", logger.F("request_id", req.ID, "item", item.Title, "vault", s.Vault, "operation", claimed.Mutation.Operation))
		h.writeJSON(w, http.StatusOK, map[string]any{"mutation": map[string]any{"status": "completed", "operation": claimed.Mutation.Operation, "item": item.Title, "vault": s.Vault}})
		return
	}

	// Batch mode: multiple secrets requested or field filtering specified
	if len(req.Secrets) > 1 || (len(req.Secrets) == 1 && len(req.Secrets[0].Fields) > 0) {
		result := make(map[string]map[string]string)
		resolvedVaults := make(map[string]string)
		for _, s := range req.Secrets {
			vault := s.Vault
			if vault == "" {
				vault = "_auto_"
			}

			var allFields map[string]string
			var actualName string

			if vault == "_auto_" {
				var err error
				allFields, vault, actualName, err = h.opClient.FindSecretAcrossVaults(s.SecretName)
				if err != nil {
					h.log.Error("Failed to find secret", logger.F("error", err.Error(), "secret", s.SecretName))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
			} else {
				var err error
				allFields, err = h.opClient.GetSecret(vault, s.SecretName)
				if err != nil {
					h.log.Error("Failed to fetch secret", logger.F("error", err.Error(), "secret", s.SecretName, "vault", vault))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
				actualName = s.SecretName
			}
			resolvedVaults[actualName] = vault

			// Filter fields if specified
			if len(s.Fields) > 0 {
				filtered := make(map[string]string)
				for _, f := range s.Fields {
					if actual, val, ok := core.ResolveField(allFields, f); ok {
						filtered[actual] = val
					}
				}
				result[actualName] = filtered
			} else {
				result[actualName] = allFields
			}
		}

		h.log.Info("Batch secrets retrieved", logger.F("request_id", req.ID, "count", len(result)))
		h.store.Delete(token)
		h.writeJSON(w, http.StatusOK, BatchSecretResponse{Secrets: result, Vaults: resolvedVaults})
		return
	}

	// Legacy single-item mode
	var secret map[string]string
	var actualVault, actualSecret string

	if req.Vault == "_auto_" {
		secret, actualVault, actualSecret, err = h.opClient.FindSecretAcrossVaults(req.SecretName)
		if err != nil {
			h.log.Error("Failed to find secret across vaults", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", err.Error())
			return
		}
	} else {
		secret, err = h.opClient.GetSecret(req.Vault, req.SecretName)
		if err != nil {
			h.log.Error("Failed to fetch secret from 1Password", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName, "vault", req.Vault))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", "Failed to retrieve secret from 1Password")
			return
		}
		actualVault = req.Vault
		actualSecret = req.SecretName
	}

	h.log.Info("Secret retrieved", logger.F("request_id", req.ID, "secret", actualSecret, "vault", actualVault))
	h.store.Delete(token)
	h.writeJSON(w, http.StatusOK, SecretResponse{Secret: secret, Vault: actualVault})
}

// HandleHealth handles GET /health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleClientDownload handles GET /client/{os}/{arch} and legacy GET /client/{arch}
func (h *Handler) HandleClientDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/client/")
	parts := strings.Split(path, "/")

	var goos, arch string
	switch len(parts) {
	case 1:
		// Legacy: /client/{arch} — assumes linux
		goos = "linux"
		arch = parts[0]
	case 2:
		// New: /client/{os}/{arch}
		goos = parts[0]
		arch = parts[1]
	default:
		h.writeError(w, http.StatusBadRequest, "invalid_path", "Use /client/{os}/{arch} or /client/{arch}")
		return
	}

	if goos != "linux" && goos != "darwin" {
		h.writeError(w, http.StatusBadRequest, "invalid_os", "Supported operating systems: linux, darwin")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		h.writeError(w, http.StatusBadRequest, "invalid_arch", "Supported architectures: amd64, arm64")
		return
	}

	clientPath := "/app/clients/client-" + goos + "-" + arch

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=secret-gate")

	http.ServeFile(w, r, clientPath)
}

// HandleSearch handles POST /search - fuzzy search for secrets
func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload SearchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.Query == "" {
		h.writeError(w, http.StatusBadRequest, "missing_query", "query is required")
		return
	}

	limit := payload.Limit
	if limit <= 0 {
		limit = 10
	}

	results, err := h.opClient.SearchSecrets(payload.Query, limit)
	if err != nil {
		h.log.Error("Search failed", logger.F("error", err.Error(), "query", payload.Query))
		h.writeError(w, http.StatusInternalServerError, "search_failed", "Failed to search secrets")
		return
	}

	var items []SearchResultItem
	for _, r := range results {
		items = append(items, SearchResultItem{
			SecretName: r.Item.Title,
			VaultName:  r.VaultName,
			Score:      r.Score,
			MatchType:  r.MatchType,
		})
	}

	h.writeJSON(w, http.StatusOK, SearchResponse{
		Results: items,
		Query:   payload.Query,
	})
}

// HandleFields handles POST /fields - get field metadata without values
func (h *Handler) HandleFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload FieldsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.SecretName == "" {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name is required")
		return
	}

	fields, vaultName, secretName, err := h.opClient.GetItemFields(payload.Vault, payload.SecretName)
	if err != nil {
		h.log.Error("Failed to get item fields", logger.F("error", err.Error(), "secret", payload.SecretName))
		h.writeError(w, http.StatusInternalServerError, "fields_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, FieldsResponse{
		SecretName: secretName,
		VaultName:  vaultName,
		Fields:     fields,
	})
}

// HandleOpenAPI handles GET /openapi.json - returns OpenAPI spec
func (h *Handler) HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	spec := OpenAPISpec()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(spec))
}

// OpenAPISpec returns the OpenAPI 3.0 specification
func OpenAPISpec() string {
	return `{
  "openapi": "3.0.3",
  "info": {
    "title": "Secret Gate API",
    "description": "Human-in-the-loop gateway for approved reads and writes to 1Password items.",
    "version": "0.5.2"
  },
  "servers": [
    {"url": "/", "description": "Relative to deployment URL"}
  ],
  "paths": {
    "/request": {
      "post": {
        "summary": "Request access to one or more secrets",
        "description": "Submits a request to access secrets. A Telegram notification will be sent for human approval. Supports two formats: legacy single-item (secret_name at top level) and batch (secrets array). Use /search to find secret names and /fields to discover available fields before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "secrets": {
                    "type": "array",
                    "description": "Batch mode: array of secrets to request. Each item specifies a secret and optionally which fields to retrieve.",
                    "items": {
                      "type": "object",
                      "required": ["secret_name"],
                      "properties": {
                        "secret_name": {
                          "type": "string",
                          "description": "Name of the secret to access"
                        },
                        "vault": {
                          "type": "string",
                          "description": "Optional vault name. If omitted, searches across all vaults."
                        },
                        "fields": {
                          "type": "array",
                          "items": {"type": "string"},
                          "description": "Optional list of field labels to retrieve. If omitted, all fields are returned. Use /fields to discover available field labels."
                        }
                      }
                    }
                  },
                  "secret_name": {
                    "type": "string",
                    "description": "Legacy mode: name of a single secret to access. Use 'secrets' array for batch requests."
                  },
                  "vault": {
                    "type": "string",
                    "description": "Legacy mode: optional vault name. If omitted, searches across all vaults."
                  },
                  "machine": {
                    "type": "string",
                    "description": "Identifier for the requesting machine/agent"
                  },
                  "reason": {
                    "type": "string",
                    "description": "Reason for requesting access (shown in approval notification)"
                  },
                  "action": {
                    "type": "string",
                    "description": "Requested action. Defaults to read; create and update are set from mutation.operation."
                  },
                  "context": {
                    "type": "object",
                    "description": "Human-readable agent context shown in Telegram.",
                    "properties": {
                      "runtime": {"type": "string"},
                      "provider": {"type": "string"},
                      "model": {"type": "string"},
                      "think": {"type": "string"},
                      "project": {"type": "string"},
                      "task": {"type": "string"}
                    }
                  },
                  "mutation": {
                    "type": "object",
                    "description": "Approval-gated item creation or update. Requires one item and an explicit vault.",
                    "required": ["operation", "fields"],
                    "properties": {
                      "operation": {"type": "string", "enum": ["create", "update"]},
                      "category": {"type": "string", "description": "1Password category for a new item. Defaults to SECURE_NOTE."},
                      "fields": {"type": "object", "additionalProperties": {"type": "string"}}
                    }
                  }
                }
              },
              "examples": {
                "batch": {
                  "summary": "Batch request for multiple secrets with field filtering",
                  "value": {
                    "secrets": [
                      {"secret_name": "homelab-ssh-key", "fields": ["private_key"]},
                      {"secret_name": "database-credentials", "vault": "Infrastructure", "fields": ["username", "password"]}
                    ],
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                },
                "legacy": {
                  "summary": "Legacy single-item request",
                  "value": {
                    "secret_name": "homelab-ssh-key",
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "202": {
            "description": "Request accepted, waiting for approval",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "token": {"type": "string", "description": "Unique token for this request. Use with /status/{token} and /secret/{token}."},
                    "status_url": {"type": "string", "description": "URL to poll for approval status"},
                    "expires_at": {"type": "string", "description": "ISO 8601 timestamp when this request expires"},
                    "message": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/search": {
      "post": {
        "summary": "Search for secrets",
        "description": "Fuzzy search for secrets across all vaults. Use this to find the correct secret name before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                  "query": {
                    "type": "string",
                    "description": "Search query (supports fuzzy matching)"
                  },
                  "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of results"
                  }
                }
              },
              "example": {"query": "ssh", "limit": 5}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Search results",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "query": {"type": "string"},
                    "results": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "secret_name": {"type": "string"},
                          "vault_name": {"type": "string"},
                          "score": {"type": "number"},
                          "match_type": {"type": "string", "enum": ["exact", "prefix", "contains", "fuzzy"]}
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/fields": {
      "post": {
        "summary": "Get field metadata for a secret",
        "description": "Returns the field labels and types for a secret item without exposing any values. Use this to discover which fields are available before making a batch request with field filtering.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                  "secret_name": {
                    "type": "string",
                    "description": "Name of the secret to inspect"
                  },
                  "vault": {
                    "type": "string",
                    "description": "Optional vault name. If omitted, searches across all vaults."
                  }
                }
              },
              "example": {"secret_name": "database-credentials"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Field metadata for the secret",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "secret_name": {"type": "string", "description": "Resolved name of the secret"},
                    "vault_name": {"type": "string", "description": "Vault containing the secret"},
                    "fields": {
                      "type": "array",
                      "description": "List of fields available on this secret",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": {"type": "string", "description": "Stable field ID"},
                          "label": {"type": "string", "description": "Field label"},
                          "type": {"type": "string", "description": "Field type (for example STRING, CONCEALED, URL, EMAIL, OTP, or PASSKEY)"},
                          "purpose": {"type": "string"},
                          "section": {"type": "string", "description": "Section label; combine with the field label as section.label when labels repeat"},
                          "reference": {"type": "string", "description": "1Password secret reference when supplied by Connect"}
                        }
                      }
                    }
                  }
                },
                "example": {
                  "secret_name": "database-credentials",
                  "vault_name": "Infrastructure",
                  "fields": [
                    {"label": "username", "type": "STRING"},
                    {"label": "password", "type": "CONCEALED"},
                    {"label": "hostname", "type": "STRING"},
                    {"label": "port", "type": "STRING"}
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/status/{token}": {
      "get": {
        "summary": "Check request status",
        "description": "Poll this endpoint to check if your request has been approved or denied.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "wait",
            "in": "query",
            "required": false,
            "description": "Optional long-polling wait duration in seconds (clamped to server maximum, default 25s)",
            "schema": {"type": "integer"}
          }
        ],
        "responses": {
          "200": {
            "description": "Request status",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": {"type": "string", "enum": ["pending", "approved", "denied", "expired"]},
                    "message": {"type": "string"},
                    "secret_url": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/secret/{token}": {
      "get": {
        "summary": "Retrieve approved secret(s)",
        "description": "Retrieve the secret after approval. This is a one-time use endpoint - the token is invalidated after retrieval. Returns batch format (secrets map) for batch requests or legacy format (single secret) for legacy requests.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {
            "description": "Secret data. Response format depends on how the request was made.",
            "content": {
              "application/json": {
                "schema": {
                  "oneOf": [
                    {
                      "type": "object",
                      "description": "Legacy single-item response",
                      "properties": {
                        "secret": {
                          "type": "object",
                          "additionalProperties": {"type": "string"},
                          "description": "Map of field labels to values for the single requested secret"
                        }
                      }
                    },
                    {
                      "type": "object",
                      "description": "Batch response containing multiple secrets",
                      "properties": {
                        "secrets": {
                          "type": "object",
                          "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                          },
                          "description": "Map of secret names to their field label-value maps"
                        }
                      }
                    }
                  ]
                },
                "examples": {
                  "legacy": {
                    "summary": "Legacy single-item response",
                    "value": {
                      "secret": {
                        "username": "admin",
                        "password": "s3cret"
                      }
                    }
                  },
                  "batch": {
                    "summary": "Batch response with multiple secrets",
                    "value": {
                      "secrets": {
                        "homelab-ssh-key": {
                          "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----..."
                        },
                        "database-credentials": {
                          "username": "admin",
                          "password": "s3cret"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/client/{os}/{arch}": {
      "get": {
        "summary": "Download CLI client",
        "description": "Download the pre-compiled CLI client binary for the specified OS and architecture. Legacy path /client/{arch} is also supported (assumes linux).",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["linux", "darwin"]}
          },
          {
            "name": "arch",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["amd64", "arm64"]}
          }
        ],
        "responses": {
          "200": {
            "description": "Binary file",
            "content": {"application/octet-stream": {}}
          }
        }
      }
    },
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/openapi.json": {
      "get": {
        "summary": "OpenAPI specification",
        "responses": {
          "200": {
            "description": "OpenAPI 3.0 spec",
            "content": {"application/json": {}}
          }
        }
      }
    }
  }
}`
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, errCode, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: errCode, Message: message})
}
