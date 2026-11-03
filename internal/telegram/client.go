package telegram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/writegrant"
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
	CallbackData string `json:"callback_data,omitempty"`
	URL          string `json:"url,omitempty"`
}

// InlineKeyboardMarkup represents an inline keyboard
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// SendMessageRequest represents a request to send a message
type SendMessageRequest struct {
	ChatID          int64                 `json:"chat_id"`
	Text            string                `json:"text"`
	ParseMode       string                `json:"parse_mode,omitempty"`
	ReplyMarkup     *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
	ReplyParameters *ReplyParameters      `json:"reply_parameters,omitempty"`
}

// ReplyParameters makes a message a reply, so Telegram links it to the original.
type ReplyParameters struct {
	MessageID                int  `json:"message_id"`
	AllowSendingWithoutReply bool `json:"allow_sending_without_reply"`
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
// windowTTL is the length of the window the approver may open from this
// request: the read window for reads, the write window for writes.
func (c *Client) SendApprovalRequest(req *models.ApprovalRequest, webhookBaseURL string, windowTTL time.Duration) (int, error) {
	text := approvalMessage(req)
	keyboard := approvalKeyboard(req, windowTTL)

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
		return 0, fmt.Errorf("sending message: %w", transportError(err))
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
	b.WriteString("🔐 1Password access request\n\n")
	if headline := cardHeadline(req); headline != "" {
		b.WriteString("💳 <b>" + html.EscapeString(headline) + "</b>\n\n")
	}
	b.WriteString("Action:\n")
	b.WriteString(actionDescription(req))
	if req.AwaitingOwner() {
		b.WriteString("\n\n✍️ Tap \"Enter values\" to type the requested values on this device (Tailscale). Saving the page approves the write; the agent never sees them.")
	} else if req.Sensitive {
		b.WriteString("\n\nCard requests are approved one at a time (no windows).")
	}
	writeReason(&b, req)
	writeRequester(&b, req)
	b.WriteString("\n\nExpires: ")
	b.WriteString(req.ExpiresAt.Format("15:04 MST"))
	b.WriteString("\nRequest: <code>")
	b.WriteString(html.EscapeString(req.ID))
	b.WriteString("</code>")
	return b.String()
}

// cardHeadline is "Approve $412.30 at aa.com checkout, Visa ending 1111,
// expires 08/2027" for card reads, so the approver sees the charge and where
// the card is used.
func cardHeadline(req *models.ApprovalRequest) string {
	return req.CardLine()
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
	if req.IsWrite() {
		return actionSummary(req) + "\n" + writeDetails(req)
	}
	return actionSummary(req) + "\nVault: " + html.EscapeString(req.Vault) + attachmentLines(req)
}

// agentLabels are the labels whose values the agent sent.
func agentLabels(m models.ItemMutation) []string {
	owner := make(map[string]bool, len(m.OwnerFields))
	for _, l := range m.OwnerFields {
		owner[l] = true
	}
	var out []string
	for _, l := range m.Labels() {
		if !owner[l] {
			out = append(out, l)
		}
	}
	return out
}

// categoryName names the item type for the approver once the server has
// resolved it; it is empty otherwise.
func categoryName(m models.ItemMutation) string {
	switch m.TargetCategory {
	case "":
		return ""
	case "CREDIT_CARD":
		return "💳 credit card"
	case "API_CREDENTIAL":
		return "API credential"
	default:
		return strings.ToLower(strings.ReplaceAll(m.TargetCategory, "_", " "))
	}
}

// attachmentLines lists requested attachments by name and size, never content.
func attachmentLines(req *models.ApprovalRequest) string {
	var lines []string
	for _, s := range req.Secrets {
		for _, a := range s.Attachments {
			lines = append(lines, "📎 "+html.EscapeString(a.Name)+" ("+humanSize(a.Size)+")")
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "\nAttachments:\n" + strings.Join(lines, "\n")
}

// fileList names files to attach with their sizes, never their content.
func fileList(files []models.FileUpload) string {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name+" ("+humanSize(f.Size)+")")
	}
	return html.EscapeString(strings.Join(names, ", "))
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func actionSummary(req *models.ApprovalRequest) string {
	if req.IsWrite() {
		vault := " in the \"" + html.EscapeString(req.Vault) + "\" vault"
		if len(req.Mutations) == 1 {
			m := req.Mutations[0]
			return operationVerb(m.Operation) + " \"" + html.EscapeString(m.Item) + "\"" + vault
		}
		return fmt.Sprintf("Write %d items", len(req.Mutations)) + vault
	}
	name := firstNonEmpty(req.SecretName, "item")
	if len(req.Secrets) > 0 {
		name = req.Secrets[0].SecretName
	}
	fields := "all fields"
	if len(req.Secrets) > 0 && len(req.Secrets[0].Fields) > 0 {
		fields = strings.Join(req.Secrets[0].Fields, ", ")
	}
	return "Read " + html.EscapeString(fields) + " from \"" + html.EscapeString(name) + "\""
}

// writeDetails lists each write's item, field labels, and file names with
// sizes. Values and file content are never shown.
func writeDetails(req *models.ApprovalRequest) string {
	if len(req.Mutations) == 1 {
		m := req.Mutations[0]
		var lines []string
		if c := categoryName(m); c != "" {
			lines = append(lines, "Type: "+html.EscapeString(c))
		}
		if labels := agentLabels(m); len(labels) > 0 {
			lines = append(lines, "Fields: "+html.EscapeString(strings.Join(labels, ", ")))
		}
		if len(m.OwnerFields) > 0 {
			lines = append(lines, "✍️ You enter: "+html.EscapeString(strings.Join(m.OwnerFields, ", ")))
		}
		if len(m.Files) > 0 {
			lines = append(lines, "📎 Files: "+fileList(m.Files))
		}
		return strings.Join(lines, "\n")
	}
	lines := make([]string, 0, len(req.Mutations))
	for _, m := range req.Mutations {
		var parts []string
		if labels := agentLabels(m); len(labels) > 0 {
			parts = append(parts, "fields: "+html.EscapeString(strings.Join(labels, ", ")))
		}
		if len(m.OwnerFields) > 0 {
			parts = append(parts, "you enter: "+html.EscapeString(strings.Join(m.OwnerFields, ", ")))
		}
		if len(m.Files) > 0 {
			parts = append(parts, "files: "+fileList(m.Files))
		}
		lines = append(lines, "• "+operationVerb(m.Operation)+" \""+html.EscapeString(m.Item)+"\" ("+strings.Join(parts, "; ")+")")
	}
	return strings.Join(lines, "\n")
}

func operationVerb(operation string) string {
	if operation == "update" {
		return "Update"
	}
	return "Create"
}

func approvalKeyboard(req *models.ApprovalRequest, windowTTL time.Duration) *InlineKeyboardMarkup {
	deny := []InlineKeyboardButton{{Text: "❌ Deny", CallbackData: "deny:" + req.ID}}
	if req.AwaitingOwner() && req.EntryURL != "" {
		return &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{{Text: "✍️ Enter values", URL: req.EntryURL}}, deny}}
	}
	approveText := "✅ Approve once"
	if req.Context.Amount != "" && !req.IsWrite() {
		approveText = "✅ Approve " + req.Context.Amount
	}
	approveRow := []InlineKeyboardButton{{Text: approveText, CallbackData: "approve:" + req.ID}}
	switch {
	case req.Sensitive:
	case !req.IsWrite():
		approveRow = append(approveRow, InlineKeyboardButton{Text: "✅ Approve " + formatDurationLabel(windowTTL), CallbackData: "approve_window:" + req.ID})
	case windowTTL > 0:
		approveRow = append(approveRow, InlineKeyboardButton{Text: "✅ Approve + writes " + formatDurationLabel(windowTTL), CallbackData: "approve_writes:" + req.ID})
	}
	return &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{approveRow, deny}}
}

func revokeKeyboard(windowID string) *InlineKeyboardMarkup {
	return &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{{Text: "🛑 Revoke write window", CallbackData: "revoke_window:" + windowID}}}}
}

// windowScope describes who a write window covers, for the approver.
func windowScope(scope writegrant.Scope) string {
	who := firstNonEmpty(scope.Machine, scope.IP, "the requester")
	if scope.AgentID != "" {
		who += " (agent " + scope.AgentID + ")"
	}
	return "new items from " + who + " in \"" + scope.Vault + "\""
}

func approvedWriteWindowMessage(req *models.ApprovalRequest, approver string, window writegrant.Window) string {
	return approvedMessage(req, approver, "This request, plus "+windowScope(window.Scope)+" until "+window.ExpiresAt.Format("15:04 MST")+
		". Updates are covered only for items written under this approval.")
}

func autoApprovedWriteMessage(req *models.ApprovalRequest, match writegrant.Match) string {
	scope := "Follow-up to request " + match.Source + " until " + match.ExpiresAt.Format("15:04 MST")
	if match.Kind == models.AutoApprovedWriteWindow {
		scope = "Write window until " + match.ExpiresAt.Format("15:04 MST") + " (opened by request " + match.Source + ")"
	}
	requester := firstNonEmpty(req.Context.Provider, req.Context.Runtime, req.RequesterMachine, "The requester")
	return "✅ Auto-approved write: " + purposeSuffix(req) + "\n\n" +
		html.EscapeString(requester) + " may " + strings.ToLower(actionSummary(req)) + " for the " +
		html.EscapeString(firstNonEmpty(req.Context.Project, "unspecified")) + " project.\n" + writeDetails(req) +
		reasonBlock(req) + "\n\nApproved by: @" + html.EscapeString(match.Approver) +
		"\nScope: " + html.EscapeString(scope) + "\nRequest: <code>" + html.EscapeString(req.ID) + "</code>"
}

func reminderMessage(req *models.ApprovalRequest) string {
	return "⏰ Write approval expires at " + req.ExpiresAt.Format("15:04 MST") + "\n\n" + actionDescription(req) +
		"\n\nTap Approve on the request above. After expiry the agent has to submit the values again." +
		"\nRequest: <code>" + html.EscapeString(req.ID) + "</code>"
}

func expiredMessage(req *models.ApprovalRequest) string {
	outcome := "No secret was released."
	if req.IsWrite() {
		outcome = "Nothing was written. The agent has to submit a new request."
	}
	return "⌛ Expired: " + purposeSuffix(req) + "\n\n" + actionDescription(req) + reasonBlock(req) +
		"\n\n" + outcome + "\nRequest: <code>" + html.EscapeString(req.ID) + "</code>"
}

func windowRevokedMessage(window writegrant.Window, revoker string, dropped int) string {
	return "🛑 Write window revoked by @" + html.EscapeString(revoker) + "\n\nScope: " + html.EscapeString(windowScope(window.Scope)) +
		fmt.Sprintf("\nFollow-up grants removed: %d", dropped) +
		"\nOpened by request: <code>" + html.EscapeString(window.SourceRequestID) + "</code>"
}

func writeReason(b *strings.Builder, req *models.ApprovalRequest) {
	b.WriteString(reasonBlock(req))
}

func reasonBlock(req *models.ApprovalRequest) string {
	reason := firstNonEmpty(req.Reason, req.Context.Task, "No reason provided.")
	purpose := ""
	if req.Context.Purpose != "" {
		purpose = "\n\nPurpose:\n<b>" + html.EscapeString(req.Context.Purpose) + "</b>"
	}
	if req.Context.Amount != "" {
		purpose += "\n\nAmount:\n<b>" + html.EscapeString(req.Context.Amount) + "</b>"
	}
	return purpose + "\n\nReason:\n<b>" + html.EscapeString(reason) + "</b>"
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
	text := firstNonEmpty(cardHeadline(req), req.Context.Task, req.Reason, req.Action, "request")
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
		return fmt.Errorf("sending message: %w", transportError(err))
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
func (c *Client) UpdateApprovalRequest(messageID int, req *models.ApprovalRequest, windowTTL time.Duration) error {
	return c.editMessage(messageID, approvalMessage(req), approvalKeyboard(req, windowTTL))
}

// UpdateMessageApprovedWriteWindow marks a write approved with a write window
// and keeps a revoke button on the message.
func (c *Client) UpdateMessageApprovedWriteWindow(messageID int, req *models.ApprovalRequest, approver string, window writegrant.Window) error {
	return c.editMessage(messageID, approvedWriteWindowMessage(req, approver, window), revokeKeyboard(window.ID))
}

// SendWriteAutoApproved posts the audit message for a write covered by a
// write window or follow-up grant. Window-covered writes carry a revoke button.
func (c *Client) SendWriteAutoApproved(req *models.ApprovalRequest, match writegrant.Match) error {
	msgReq := SendMessageRequest{ChatID: c.chatID, Text: autoApprovedWriteMessage(req, match), ParseMode: "HTML"}
	if match.WindowID != "" {
		msgReq.ReplyMarkup = revokeKeyboard(match.WindowID)
	}
	_, err := c.sendMessage(msgReq)
	return err
}

// SendReminder replies to a pending write request shortly before it expires.
func (c *Client) SendReminder(req *models.ApprovalRequest) error {
	msgReq := SendMessageRequest{ChatID: c.chatID, Text: reminderMessage(req), ParseMode: "HTML"}
	if req.TelegramMsgID != 0 {
		msgReq.ReplyParameters = &ReplyParameters{MessageID: req.TelegramMsgID, AllowSendingWithoutReply: true}
	}
	_, err := c.sendMessage(msgReq)
	return err
}

// UpdateMessageExpired replaces an expired request's buttons with an outcome line.
func (c *Client) UpdateMessageExpired(messageID int, req *models.ApprovalRequest) error {
	return c.editMessage(messageID, expiredMessage(req), nil)
}

// SendWindowRevoked confirms that a write window was closed.
func (c *Client) SendWindowRevoked(window writegrant.Window, revoker string, dropped int) error {
	return c.sendText(windowRevokedMessage(window, revoker, dropped))
}

func (c *Client) sendMessage(msgReq SendMessageRequest) (int, error) {
	body, err := json.Marshal(msgReq)
	if err != nil {
		return 0, fmt.Errorf("marshaling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/sendMessage", "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("sending message: %w", transportError(err))
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
		return fmt.Errorf("sending message: %w", transportError(err))
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
		return fmt.Errorf("sending request: %w", transportError(err))
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
		return nil, fmt.Errorf("fetching updates: %w", transportError(err))
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
		return fmt.Errorf("deleting webhook: %w", transportError(err))
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
		return fmt.Errorf("sending request: %w", transportError(err))
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

// transportError drops the request URL from net/http errors. Bot API URLs
// embed the bot token, so a raw *url.Error would leak it into server logs.
func transportError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s Telegram Bot API: %w", urlErr.Op, urlErr.Err)
	}
	return err
}
