package pushward

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/writegrant"
)

const defaultBaseURL = "https://api.pushward.app"

// AnswerCallback is called when a user taps an option on a PushWard approval
// Live Activity. data has the same "action:requestID" form as Telegram callbacks.
type AnswerCallback = func(data, approver string)

// Client sends PushWard approval Live Activities and E2E-encrypted audit notifications.
type Client struct {
	token      string
	e2eKeyHex  string
	baseURL    string
	httpClient *http.Client
	pollClient *http.Client
	log        *logger.Logger

	mu      sync.Mutex
	watches map[string]context.CancelFunc // requestID -> cancel
}

// New creates a PushWard client. e2eKeyHex is optional; when set, audit and
// reminder notifications are sealed with the pw1 E2E format before sending.
func New(token, e2eKeyHex string) *Client {
	return &Client{
		token:      strings.TrimSpace(token),
		e2eKeyHex:  strings.TrimSpace(e2eKeyHex),
		baseURL:    defaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		pollClient: &http.Client{Timeout: 35 * time.Second},
		log:        logger.New(),
		watches:    make(map[string]context.CancelFunc),
	}
}

// SetBaseURL overrides the API root (for tests).
func (c *Client) SetBaseURL(url string) {
	c.baseURL = strings.TrimRight(url, "/")
}

type activityCreateRequest struct {
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	Priority     int    `json:"priority,omitempty"`
	EndedTTL     int    `json:"ended_ttl,omitempty"`
	DismissalTTL *int   `json:"dismissal_ttl,omitempty"`
}

type activityPatchRequest struct {
	State        string          `json:"state,omitempty"`
	Priority     int             `json:"priority,omitempty"`
	Sound        string          `json:"sound,omitempty"`
	DismissalTTL *int            `json:"dismissal_ttl,omitempty"`
	Content      activityContent `json:"content"`
}

type activityContent struct {
	Template    string           `json:"template"`
	State       string           `json:"state"`
	Source      string           `json:"source,omitempty"`
	Icon        string           `json:"icon,omitempty"`
	AccentColor string           `json:"accent_color,omitempty"`
	Details     []activityDetail `json:"details,omitempty"`
	Options     []activityOption `json:"options,omitempty"`
	EndDate     int64            `json:"end_date,omitempty"`
	OnExpire    string           `json:"on_expire,omitempty"`
	Answer      *activityAnswer  `json:"answer,omitempty"`
}

type activityDetail struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type activityOption struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Style string `json:"style,omitempty"`
	Icon  string `json:"icon,omitempty"`
}

type activityAnswer struct {
	Option string `json:"option"`
	At     int64  `json:"at"`
	By     string `json:"by"`
}

type activityResponse struct {
	Slug    string          `json:"slug"`
	State   string          `json:"state"`
	Content activityContent `json:"content"`
}

type notificationRequest struct {
	Title             string `json:"title,omitempty"`
	Subtitle          string `json:"subtitle,omitempty"`
	Body              string `json:"body,omitempty"`
	Encrypted         string `json:"encrypted,omitempty"`
	Level             string `json:"level,omitempty"`
	Source            string `json:"source,omitempty"`
	SourceDisplayName string `json:"source_display_name,omitempty"`
	ActivitySlug      string `json:"activity_slug,omitempty"`
}

// ActivitySlug returns the PushWard activity slug for an approval request.
func ActivitySlug(requestID string) string {
	return "sg-" + requestID
}

// SendApprovalRequest creates and starts an approval Live Activity on PushWard.
func (c *Client) SendApprovalRequest(req *models.ApprovalRequest, windowTTL time.Duration) (string, error) {
	slug := ActivitySlug(req.ID)
	dismissal := 300
	createBody := activityCreateRequest{
		Slug:         slug,
		Name:         truncateRunes(cardTitle(req), 48),
		Priority:     8,
		EndedTTL:     3600,
		DismissalTTL: &dismissal,
	}
	if err := c.doJSON(context.Background(), http.MethodPost, "/activities", "application/json", createBody, nil); err != nil {
		return "", fmt.Errorf("creating PushWard activity: %w", err)
	}
	if err := c.patchApproval(req, slug, windowTTL, "default"); err != nil {
		return "", err
	}
	return slug, nil
}

// UpdateApprovalRequest refreshes a running approval Live Activity when a pending request is renewed.
func (c *Client) UpdateApprovalRequest(slug string, req *models.ApprovalRequest, windowTTL time.Duration) error {
	if slug == "" {
		slug = ActivitySlug(req.ID)
	}
	return c.patchApproval(req, slug, windowTTL, "")
}

func (c *Client) patchApproval(req *models.ApprovalRequest, slug string, windowTTL time.Duration, sound string) error {
	accent := "blue"
	icon := "key.fill"
	if req.IsWrite() {
		accent = "orange"
		icon = "square.and.pencil"
	}
	patch := activityPatchRequest{
		State:    "ongoing",
		Priority: 8,
		Sound:    sound,
		Content: activityContent{
			Template:    "approval",
			State:       truncateRunes(questionState(req), 256),
			Source:      truncateRunes(sourceLabel(req), 24),
			Icon:        icon,
			AccentColor: accent,
			Details:     approvalDetails(req),
			Options:     approvalOptions(req, windowTTL),
			EndDate:     req.ExpiresAt.Unix(),
			OnExpire:    "none",
		},
	}
	if err := c.doJSON(context.Background(), http.MethodPatch, "/activities/"+slug, "application/merge-patch+json", patch, nil); err != nil {
		return fmt.Errorf("updating PushWard approval activity: %w", err)
	}
	return nil
}

// ResolveActivity stops any active long-poll watcher for the request and deletes
// the Live Activity so it is dismissed from the Lock Screen immediately when
// another channel (such as Telegram) resolves the request or when it expires.
func (c *Client) ResolveActivity(requestID, slug string) error {
	c.stopWatch(requestID)
	if slug == "" {
		slug = ActivitySlug(requestID)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, c.baseURL+"/activities/"+slug, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("deleting PushWard activity: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PushWard DELETE /activities/%s returned HTTP %d", slug, resp.StatusCode)
	}
	return nil
}

// WatchApproval long-polls GET /activities/{slug}?wait=25 until the user answers,
// the request expires, or ResolveActivity cancels the watch.
func (c *Client) WatchApproval(req *models.ApprovalRequest, slug string, onAnswer AnswerCallback) {
	if slug == "" {
		slug = ActivitySlug(req.ID)
	}
	ctx, cancel := context.WithDeadline(context.Background(), req.ExpiresAt.Add(5*time.Second))
	c.mu.Lock()
	if prev, ok := c.watches[req.ID]; ok {
		prev()
	}
	c.watches[req.ID] = cancel
	c.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			c.mu.Lock()
			delete(c.watches, req.ID)
			c.mu.Unlock()
		}()
		backoff := time.Second
		for {
			if ctx.Err() != nil {
				return
			}
			var act activityResponse
			err := c.getActivity(ctx, slug, 25, &act)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
					if backoff < 10*time.Second {
						backoff *= 2
					}
					continue
				}
			}
			backoff = time.Second
			if act.Content.Answer != nil {
				ans := act.Content.Answer
				if ans.By == "user" && ans.Option != "" && ans.Option != "none" {
					onAnswer(ans.Option+":"+req.ID, "pushward")
				}
				return
			}
			if act.State == "ended" {
				return
			}
		}
	}()
}

func (c *Client) stopWatch(requestID string) {
	c.mu.Lock()
	cancel, ok := c.watches[requestID]
	if ok {
		delete(c.watches, requestID)
	}
	c.mu.Unlock()
	if ok {
		cancel()
	}
}

func (c *Client) getActivity(ctx context.Context, slug string, waitSec int, out *activityResponse) error {
	reqCtx, cancel := context.WithTimeout(ctx, 32*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/activities/%s?wait=%d", c.baseURL, slug, waitSec)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.pollClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /activities/%s returned HTTP %d", slug, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// SendAutoApprovedNotification sends an audit notification for a read covered by an approval window.
func (c *Client) SendAutoApprovedNotification(req *models.ApprovalRequest, approver string, expiresAt time.Time) error {
	title := "✅ Auto-approved read: " + itemTitle(req)
	body := fmt.Sprintf("%s in vault %q (approved by %s until %s).\nReason: %s",
		plainActionSummary(req), req.Vault, approver, expiresAt.Format("15:04 MST"), firstNonEmpty(req.Reason, req.Context.Task, "unspecified"))
	return c.sendNotification(title, req.Vault, body, "passive", "")
}

// SendWriteAutoApproved sends an audit notification for a write covered by a write window or follow-up grant.
func (c *Client) SendWriteAutoApproved(req *models.ApprovalRequest, match writegrant.Match) error {
	title := "✅ Auto-approved write: " + itemTitle(req)
	scope := "follow-up to " + match.Source
	if match.Kind == models.AutoApprovedWriteWindow {
		scope = "write window until " + match.ExpiresAt.Format("15:04 MST")
	}
	body := fmt.Sprintf("%s (%s, approved by %s).\nReason: %s",
		plainActionSummary(req), scope, match.Approver, firstNonEmpty(req.Reason, req.Context.Task, "unspecified"))
	return c.sendNotification(title, req.Vault, body, "active", "")
}

// SendReminder sends a reminder notification shortly before a pending write expires.
func (c *Client) SendReminder(req *models.ApprovalRequest) error {
	title := "⏰ Write approval expires at " + req.ExpiresAt.Format("15:04 MST")
	body := fmt.Sprintf("%s.\nReason: %s", plainActionSummary(req), firstNonEmpty(req.Reason, req.Context.Task, "unspecified"))
	return c.sendNotification(title, req.Vault, body, "time-sensitive", req.PushWardSlug)
}

// SendWindowRevoked confirms that a write window was closed.
func (c *Client) SendWindowRevoked(window writegrant.Window, revoker string, dropped int) error {
	title := "🛑 Write window revoked"
	body := fmt.Sprintf("Revoked by %s for vault %q (%d follow-up grants removed).", revoker, window.Scope.Vault, dropped)
	return c.sendNotification(title, window.Scope.Vault, body, "active", "")
}

// SendWriteBlocked sends an audit warning when a write is blocked by capability checks.
func (c *Client) SendWriteBlocked(req *models.ApprovalRequest, detail string) error {
	title := "⛔ Write request blocked: " + itemTitle(req)
	body := fmt.Sprintf("%s.\n%s", plainActionSummary(req), detail)
	return c.sendNotification(title, req.Vault, body, "time-sensitive", "")
}

func (c *Client) sendNotification(title, subtitle, body, level, activitySlug string) error {
	title = truncateRunes(title, 256)
	subtitle = truncateRunes(subtitle, 256)
	body = truncateRunes(body, 1800)
	nreq := notificationRequest{
		Level:             level,
		Source:            "secret-gate",
		SourceDisplayName: "Secret Gate",
		ActivitySlug:      activitySlug,
	}
	if c.e2eKeyHex != "" {
		env, err := Seal(c.e2eKeyHex, E2EMessage{
			Title:    title,
			Subtitle: subtitle,
			Body:     body,
		})
		if err != nil {
			return fmt.Errorf("sealing PushWard notification: %w", err)
		}
		nreq.Encrypted = env
	} else {
		nreq.Title = title
		nreq.Subtitle = subtitle
		nreq.Body = body
	}
	return c.doJSON(context.Background(), http.MethodPost, "/notifications", "application/json", nreq, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path, contentType string, in any, out any) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", contentType)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("PushWard %s %s returned HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return err
		}
	}
	return nil
}

// E2EMessage is the plaintext payload inside a PushWard pw1 E2E envelope.
type E2EMessage struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Subtitle string `json:"subtitle,omitempty"`
	URL      string `json:"url,omitempty"`
}

// KeyID derives the 8-hex-character PushWard Key ID for a 64-hex-character E2E key.
func KeyID(keyHex string) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(key) != 32 {
		return "", errors.New("the key must be 64 hex characters")
	}
	kidBytes, err := hkdf.Key(sha256.New, key, nil, "pushward/e2e/v1/kid", 4)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(kidBytes), nil
}

// Seal encrypts msg in PushWard's pw1 E2E envelope format.
func Seal(keyHex string, msg E2EMessage) (string, error) {
	if msg.Title == "" || msg.Body == "" {
		return "", errors.New("title and body are required")
	}
	if utf8.RuneCountInString(msg.Title) > 256 || utf8.RuneCountInString(msg.Subtitle) > 256 {
		return "", errors.New("title and subtitle must be at most 256 characters")
	}
	if utf8.RuneCountInString(msg.Body) > 4096 {
		return "", errors.New("body must be at most 4096 characters")
	}
	plaintext, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	if pad := (64 - len(plaintext)%64) % 64; len(plaintext)+pad <= 2266 {
		plaintext = append(plaintext, bytes.Repeat([]byte(" "), pad)...)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return sealPlaintextWithNonce(keyHex, nonce, plaintext)
}

func sealPlaintextWithNonce(keyHex string, nonce, plaintext []byte) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(key) != 32 {
		return "", errors.New("the key must be 64 hex characters")
	}
	if len(nonce) != 12 {
		return "", errors.New("nonce must be 12 bytes")
	}
	encKey, err := hkdf.Key(sha256.New, key, nil, "pushward/e2e/v1/enc", 32)
	if err != nil {
		return "", err
	}
	kidBytes, err := hkdf.Key(sha256.New, key, nil, "pushward/e2e/v1/kid", 4)
	if err != nil {
		return "", err
	}
	kid := hex.EncodeToString(kidBytes)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, []byte("pw1."+kid))
	envelope := "pw1." + kid + "." + base64.RawURLEncoding.EncodeToString(sealed)
	if len(envelope) > 3072 {
		return "", errors.New("too long to encrypt: shorten the title, subtitle, body or url")
	}
	return envelope, nil
}

func approvalOptions(req *models.ApprovalRequest, windowTTL time.Duration) []activityOption {
	deny := activityOption{ID: "deny", Title: "Deny", Style: "destructive", Icon: "xmark.circle.fill"}
	if req.AwaitingOwner() {
		// Values are typed on the entry page linked from Telegram.
		return []activityOption{deny}
	}
	if req.Sensitive {
		title := "Approve"
		if req.Context.Amount != "" && !req.IsWrite() {
			title = truncateRunes("Approve "+req.Context.Amount, 24)
		}
		return []activityOption{{ID: "approve", Title: title, Style: "primary", Icon: "checkmark.circle.fill"}, deny}
	}
	if !req.IsWrite() {
		return []activityOption{
			{ID: "approve", Title: "Approve", Style: "primary", Icon: "checkmark.circle.fill"},
			{ID: "approve_window", Title: truncateRunes("Approve "+formatDuration(windowTTL), 24), Style: "secondary", Icon: "clock.fill"},
			{ID: "deny", Title: "Deny", Style: "destructive", Icon: "xmark.circle.fill"},
		}
	}
	if windowTTL > 0 {
		return []activityOption{
			{ID: "approve", Title: "Approve", Style: "primary", Icon: "checkmark.circle.fill"},
			{ID: "approve_writes", Title: truncateRunes("Approve + "+formatDuration(windowTTL), 24), Style: "secondary", Icon: "clock.badge.checkmark"},
			{ID: "deny", Title: "Deny", Style: "destructive", Icon: "xmark.circle.fill"},
		}
	}
	return []activityOption{
		{ID: "approve", Title: "Approve", Style: "primary"},
		{ID: "deny", Title: "Deny", Style: "destructive"},
	}
}

func approvalDetails(req *models.ApprovalRequest) []activityDetail {
	var details []activityDetail
	if req.AwaitingOwner() {
		details = append(details, activityDetail{Label: "Values", Value: "Enter them from the Telegram link"})
	}
	vault := firstNonEmpty(req.Vault, "default")
	fieldsSummary := compactFieldsSummary(req)
	if fieldsSummary == "" {
		details = append(details, activityDetail{
			Label: "Vault",
			Value: truncateRunes(vault, 64),
		})
		return details
	}
	combined := vault + " · " + fieldsSummary
	if len([]rune(combined)) <= 40 {
		details = append(details, activityDetail{
			Label: "Vault",
			Value: combined,
		})
		return details
	}
	details = append(details,
		activityDetail{Label: "Vault", Value: truncateRunes(vault, 64)},
		activityDetail{Label: "Fields", Value: truncateRunes(fieldsSummary, 64)},
	)
	return details
}

func compactFieldsSummary(req *models.ApprovalRequest) string {
	var labels []string
	var files []string
	if req.IsWrite() {
		if len(req.Mutations) == 1 {
			m := req.Mutations[0]
			for _, l := range m.Labels() {
				labels = append(labels, shortFieldLabel(l))
			}
			for _, f := range m.Files {
				files = append(files, "📎 "+f.Name)
			}
		} else {
			names := make([]string, 0, len(req.Mutations))
			for _, m := range req.Mutations {
				names = append(names, m.Item)
			}
			return compactList(names, 2)
		}
	} else if len(req.Secrets) > 0 {
		s := req.Secrets[0]
		for _, f := range s.Fields {
			if !strings.HasPrefix(f, models.AttachmentPrefix) {
				labels = append(labels, shortFieldLabel(f))
			}
		}
		for _, a := range s.Attachments {
			files = append(files, "📎 "+a.Name)
		}
	}
	var parts []string
	if len(labels) > 0 {
		parts = append(parts, compactList(labels, 3))
	}
	if len(files) > 0 {
		parts = append(parts, compactList(files, 2))
	}
	return strings.Join(parts, ", ")
}

func shortFieldLabel(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "one-time password", "onetimepassword":
		return "otp"
	case "notesplain", "secure note":
		return "notes"
	case "passkey credential id":
		return "passkey id"
	case "passkey private key":
		return "passkey key"
	case "passkey user handle":
		return "user handle"
	case "passkey sign count":
		return "sign count"
	}
	return label
}

func compactList(items []string, maxShow int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= maxShow {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s +%d", strings.Join(items[:maxShow-1], ", "), len(items)-(maxShow-1))
}

func cardTitle(req *models.ApprovalRequest) string {
	if req.IsWrite() {
		if len(req.Mutations) == 1 {
			m := req.Mutations[0]
			verb := "Create"
			if m.Operation == "update" {
				verb = "Update"
			}
			return verb + " " + m.Item
		}
		return fmt.Sprintf("Write %d items", len(req.Mutations))
	}
	return "Read " + itemTitle(req)
}

func questionState(req *models.ApprovalRequest) string {
	if card := req.CardLine(); card != "" {
		return card
	}
	return firstNonEmpty(req.Reason, req.Context.Task, plainActionSummary(req))
}

func sourceLabel(req *models.ApprovalRequest) string {
	return firstNonEmpty(req.Context.Provider, req.Context.Runtime, req.RequesterMachine, "Secret Gate")
}

func itemTitle(req *models.ApprovalRequest) string {
	if req.IsWrite() {
		if len(req.Mutations) == 1 {
			return req.Mutations[0].Item
		}
		return fmt.Sprintf("%d items", len(req.Mutations))
	}
	if len(req.Secrets) > 0 && req.Secrets[0].SecretName != "" {
		return req.Secrets[0].SecretName
	}
	return firstNonEmpty(req.SecretName, "item")
}

func plainActionSummary(req *models.ApprovalRequest) string {
	if req.IsWrite() {
		if len(req.Mutations) == 1 {
			m := req.Mutations[0]
			verb := "Create"
			if m.Operation == "update" {
				verb = "Update"
			}
			return fmt.Sprintf("%s %q", verb, m.Item)
		}
		return fmt.Sprintf("Write %d items in %q", len(req.Mutations), req.Vault)
	}
	return fmt.Sprintf("Read %q", itemTitle(req))
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "window"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}


func truncateRunes(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + "…"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
