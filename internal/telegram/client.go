package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
)

// CallbackHandler is called when a callback query is received from polling
type CallbackHandler func(callback *CallbackQuery)

// Client wraps the Telegram Bot API
type Client struct {
	token        string
	chatID       int64
	httpClient   *http.Client
	baseURL      string
	lastUpdateID int64
}

// Message represents a Telegram message
type Message struct {
	MessageID int   `json:"message_id"`
	Chat      Chat  `json:"chat"`
	Date      int64 `json:"date"`
}

// Chat represents a Telegram chat
type Chat struct {
	ID int64 `json:"id"`
}

// InlineKeyboardButton represents an inline keyboard button
type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// InlineKeyboardMarkup represents an inline keyboard
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// SendMessageRequest represents a request to send a message
type SendMessageRequest struct {
	ChatID      int64                 `json:"chat_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// EditMessageTextRequest represents a request to edit a message
type EditMessageTextRequest struct {
	ChatID      int64                 `json:"chat_id"`
	MessageID   int                   `json:"message_id"`
	Text        string                `json:"text"`
	ParseMode   string                `json:"parse_mode,omitempty"`
	ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

// APIResponse represents a Telegram API response
type APIResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result,omitempty"`
	Description string          `json:"description,omitempty"`
	ErrorCode   int             `json:"error_code,omitempty"`
}

// CallbackQuery represents a callback query from inline button press
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data"`
}

// User represents a Telegram user
type User struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
}

// Update represents an incoming Telegram update
type Update struct {
	UpdateID      int64          `json:"update_id"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// New creates a new Telegram client
func New(token string, chatID int64) *Client {
	return &Client{
		token:   token,
		chatID:  chatID,
		baseURL: "https://api.telegram.org/bot" + token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendApprovalRequest sends an approval request message with approve/deny buttons.
func (c *Client) SendApprovalRequest(req *models.ApprovalRequest, webhookBaseURL string, autoApproveTTL time.Duration) (int, error) {
	text := approvalMessage(req)

	approveRow := []InlineKeyboardButton{{Text: "✅ Approve once", CallbackData: fmt.Sprintf("approve:%s", req.ID)}}
	if req.Mutation == nil {
		approveRow = append(approveRow, InlineKeyboardButton{Text: fmt.Sprintf("✅ Approve %s", formatDurationLabel(autoApproveTTL)), CallbackData: fmt.Sprintf("approve_window:%s", req.ID)})
	}
	keyboard := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{approveRow, {{Text: "❌ Deny", CallbackData: fmt.Sprintf("deny:%s", req.ID)}}}}

	msgReq := SendMessageRequest{
		ChatID:      c.chatID,
		Text:        text,
		ParseMode:   "HTML",
		ReplyMarkup: keyboard,
	}

	body, err := json.Marshal(msgReq)
	if err != nil {
		return 0, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return 0, fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return 0, fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	var msg Message
	if err := json.Unmarshal(apiResp.Result, &msg); err != nil {
		return 0, fmt.Errorf("parsing message: %w", err)
	}

	return msg.MessageID, nil
}

func approvalMessage(req *models.ApprovalRequest) string {
	var b strings.Builder
	b.WriteString("🔐 1Password access request\n\nAction:\n")
	b.WriteString(actionDescription(req))
	writeReason(&b, req)
	writeRequester(&b, req)
	b.WriteString("\n\nExpires: ")
	b.WriteString(req.ExpiresAt.Format("15:04 MST"))
	b.WriteString("\nRequest: <code>")
	b.WriteString(html.EscapeString(req.ID))
	b.WriteString("</code>")
	return b.String()
}

func approvedMessage(req *models.ApprovalRequest, approver, scope string) string {
	requester := firstNonEmpty(req.Context.Provider, req.Context.Runtime, req.RequesterMachine, "The requester")
	return "✅ Approved: " + purposeSuffix(req) + "\n\n" +
		html.EscapeString(requester) + " may " + strings.ToLower(actionSummary(req)) + " for the " +
		html.EscapeString(firstNonEmpty(req.Context.Project, "unspecified")) + " project." +
		reasonBlock(req) + "\n\nApproved by: @" + html.EscapeString(approver) +
		"\nScope: " + html.EscapeString(scope) + "\nRequest: <code>" + html.EscapeString(req.ID) + "</code>"
}

func deniedMessage(req *models.ApprovalRequest, denier string) string {
	return "❌ Denied: " + purposeSuffix(req) + reasonBlock(req) +
		"\n\nDenied by: @" + html.EscapeString(denier) +
		"\nRequest: <code>" + html.EscapeString(req.ID) + "</code>"
}

func blockedWriteMessage(req *models.ApprovalRequest, detail string) string {
	return "⛔ Write request blocked\n\nCannot " + strings.ToLower(actionDescription(req)) + ".\n" +
		html.EscapeString(detail) + reasonBlock(req) + requesterBlock(req)
}

func actionDescription(req *models.ApprovalRequest) string {
	description := actionSummary(req)
	if firstNonEmpty(req.Action, "read") == "read" {
		description += "\nVault: " + html.EscapeString(req.Vault)
	}
	return description
}

func actionSummary(req *models.ApprovalRequest) string {
	action := firstNonEmpty(req.Action, "read")
	name := firstNonEmpty(req.SecretName, "item")
	if len(req.Secrets) > 0 {
		name = req.Secrets[0].SecretName
	}
	switch action {
	case "create":
		return "Create \"" + html.EscapeString(name) + "\" in the \"" + html.EscapeString(req.Vault) + "\" vault"
	case "update":
		return "Update \"" + html.EscapeString(name) + "\" in the \"" + html.EscapeString(req.Vault) + "\" vault"
	default:
		fields := "all fields"
		if len(req.Secrets) > 0 && len(req.Secrets[0].Fields) > 0 {
			fields = strings.Join(req.Secrets[0].Fields, ", ")
		}
		return "Read " + html.EscapeString(fields) + " from \"" + html.EscapeString(name) + "\""
	}
}

func writeReason(b *strings.Builder, req *models.ApprovalRequest) {
	b.WriteString(reasonBlock(req))
}

func reasonBlock(req *models.ApprovalRequest) string {
	reason := firstNonEmpty(req.Reason, req.Context.Task, "No reason provided.")
	return "\n\nReason:\n<b>" + html.EscapeString(reason) + "</b>"
}

func writeRequester(b *strings.Builder, req *models.ApprovalRequest) {
	b.WriteString(requesterBlock(req))
}

func requesterBlock(req *models.ApprovalRequest) string {
	values := [][2]string{
		{"Runtime", req.Context.Runtime},
		{"Provider", req.Context.Provider},
		{"Model", req.Context.Model},
		{"Thinking", req.Context.Think},
		{"Project", req.Context.Project},
	}
	var lines []string
	for _, value := range values {
		if value[1] != "" {
			lines = append(lines, value[0]+": "+html.EscapeString(value[1]))
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\n\nRequested by:\n" + strings.Join(lines, "\n")
}

func purposeSuffix(req *models.ApprovalRequest) string {
	text := firstNonEmpty(req.Context.Task, req.Reason, req.Action, "request")
	text = strings.Join(strings.Fields(text), " ")
	text = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(text, "."), "!"), "?")
	runes := []rune(text)
	for i, r := range runes {
		if unicode.IsLetter(r) {
			runes[i] = unicode.ToLower(r)
			break
		}
	}
	if len(runes) > 72 {
		runes = append(runes[:71], '…')
	}
	return html.EscapeString(string(runes))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func formatDurationLabel(d time.Duration) string {
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

// SendAutoApprovedNotification sends an audit message for a request covered by an approval session.
func (c *Client) SendAutoApprovedNotification(req *models.ApprovalRequest, approver string, expiresAt time.Time) error {
	text := approvedMessage(req, approver, "Until "+expiresAt.Format("15:04 MST"))

	msgReq := SendMessageRequest{
		ChatID:    c.chatID,
		Text:      text,
		ParseMode: "HTML",
	}

	body, err := json.Marshal(msgReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		// Re-editing a message to identical text and buttons is a no-op, not a failure.
		if strings.Contains(apiResp.Description, "message is not modified") {
			return nil
		}
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	return nil
}

// UpdateMessageApproved updates a message to show it was approved
func (c *Client) UpdateMessageApproved(messageID int, req *models.ApprovalRequest, approver string) error {
	return c.editMessage(messageID, approvedMessage(req, approver, "One use"), nil)
}

// UpdateMessageDenied updates a message to show it was denied
func (c *Client) UpdateMessageDenied(messageID int, req *models.ApprovalRequest, denier string) error {
	return c.editMessage(messageID, deniedMessage(req, denier), nil)
}

// UpdateApprovalRequest refreshes the original actionable request after renewal.
func (c *Client) UpdateApprovalRequest(messageID int, req *models.ApprovalRequest, autoApproveTTL time.Duration) error {
	approveRow := []InlineKeyboardButton{{Text: "✅ Approve once", CallbackData: fmt.Sprintf("approve:%s", req.ID)}}
	if req.Mutation == nil {
		approveRow = append(approveRow, InlineKeyboardButton{Text: fmt.Sprintf("✅ Approve %s", formatDurationLabel(autoApproveTTL)), CallbackData: fmt.Sprintf("approve_window:%s", req.ID)})
	}
	keyboard := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{approveRow, {{Text: "❌ Deny", CallbackData: fmt.Sprintf("deny:%s", req.ID)}}}}
	return c.editMessage(messageID, approvalMessage(req), keyboard)
}

// SendWriteBlocked sends an audit warning without approval buttons.
func (c *Client) SendWriteBlocked(req *models.ApprovalRequest, detail string) error {
	return c.sendText(blockedWriteMessage(req, detail))
}

func (c *Client) sendText(text string) error {
	msgReq := SendMessageRequest{ChatID: c.chatID, Text: text, ParseMode: "HTML"}
	body, err := json.Marshal(msgReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending message: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	if !apiResp.OK {
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}
	return nil
}

// AnswerCallbackQuery answers a callback query (removes loading state from button)
func (c *Client) AnswerCallbackQuery(callbackID, text string) error {
	reqBody := map[string]interface{}{
		"callback_query_id": callbackID,
		"text":              text,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/answerCallbackQuery", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	return nil
}

// GetUpdates fetches new updates from Telegram using long polling
func (c *Client) GetUpdates(timeout int) ([]Update, error) {
	url := fmt.Sprintf("%s/getUpdates?offset=%d&timeout=%d&allowed_updates=[\"callback_query\"]",
		c.baseURL, c.lastUpdateID+1, timeout)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching updates: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		return nil, fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	var updates []Update
	if err := json.Unmarshal(apiResp.Result, &updates); err != nil {
		return nil, fmt.Errorf("parsing updates: %w", err)
	}

	// Track the last update ID so we don't process it again
	for _, u := range updates {
		if u.UpdateID > c.lastUpdateID {
			c.lastUpdateID = u.UpdateID
		}
	}

	return updates, nil
}

// DeleteWebhook removes any active webhook so getUpdates polling can work
func (c *Client) DeleteWebhook() error {
	resp, err := c.httpClient.Post(c.baseURL+"/deleteWebhook", "application/json", nil)
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		// Re-editing a message to identical text and buttons is a no-op, not a failure.
		if strings.Contains(apiResp.Description, "message is not modified") {
			return nil
		}
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	return nil
}

// PollUpdates starts a long-polling loop that calls handler for each callback query
func (c *Client) PollUpdates(handler CallbackHandler) {
	log := logger.New()

	// Delete any active webhook before starting long polling (retry until success)
	for {
		if err := c.DeleteWebhook(); err != nil {
			log.Error("Failed to delete webhook, retrying in 5s", logger.F("error", err.Error()))
			time.Sleep(5 * time.Second)
			continue
		}
		log.Info("Cleared Telegram webhook, starting long polling")
		break
	}

	// Use a longer timeout for the HTTP client during long polling
	pollingClient := &http.Client{Timeout: 35 * time.Second}
	origClient := c.httpClient

	for {
		c.httpClient = pollingClient
		updates, err := c.GetUpdates(30)
		c.httpClient = origClient

		if err != nil {
			// If webhook was re-enabled externally, delete it again
			if strings.Contains(err.Error(), "webhook is active") {
				log.Info("Webhook detected, deleting before retry")
				c.DeleteWebhook()
			} else {
				log.Error("Error polling Telegram updates", logger.F("error", err.Error()))
			}
			time.Sleep(5 * time.Second)
			continue
		}

		for _, update := range updates {
			if update.CallbackQuery != nil {
				handler(update.CallbackQuery)
			}
		}
	}
}

func (c *Client) editMessage(messageID int, text string, keyboard *InlineKeyboardMarkup) error {
	editReq := EditMessageTextRequest{
		ChatID:      c.chatID,
		MessageID:   messageID,
		Text:        text,
		ParseMode:   "HTML",
		ReplyMarkup: keyboard,
	}

	body, err := json.Marshal(editReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+"/editMessageText", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	if !apiResp.OK {
		// Re-editing a message to identical text and buttons is a no-op, not a failure.
		if strings.Contains(apiResp.Description, "message is not modified") {
			return nil
		}
		return fmt.Errorf("telegram API error: %s", apiResp.Description)
	}

	return nil
}
