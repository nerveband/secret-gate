package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"
)

// Callback actions of the control surface. Data is "action:argument".
const (
	CBOpen        = "ow_open"     // argument: minutes ("0" = default)
	CBConfirm     = "ow_ok"       // argument: confirm nonce
	CBCancel      = "ow_no"       // argument: confirm nonce
	CBClose       = "ow_close"    // argument: window id
	CBCloseAll    = "ow_closeall" // argument ignored
	CBWindows     = "ow_list"     // argument ignored
	CBSet         = "set"         // argument: name=value
	CBSettings    = "settings"    // argument ignored
	CBPending     = "pending"     // argument ignored
	CBPanelRedraw = "panel"       // argument ignored
)

// Commands the bot understands, registered with Telegram's command menu.
var Commands = []struct{ Command, Description string }{
	{"panel", "Control panel to pin"},
	{"open", "Open a read window: /open [minutes]"},
	{"close", "Close every open window"},
	{"windows", "Show open windows"},
	{"pending", "Show requests waiting for a decision"},
	{"settings", "Alerts and feature switches"},
	{"set", "Change a setting: /set notifications silent"},
	{"help", "What the commands do"},
}

// SetSilent makes every outgoing message arrive without a push notification
// whenever silent() returns true.
func (c *Client) SetSilent(silent func() bool) { c.silent = silent }

// SetBaseURL points the client at another Bot API root. Tests use it with a
// fake server; the URL of a real bot contains its token, so never log it.
func (c *Client) SetBaseURL(url string) { c.baseURL = strings.TrimRight(url, "/") }

// Send posts an HTML message to the approver's chat and returns its id.
func (c *Client) Send(text string, keyboard *InlineKeyboardMarkup) (int, error) {
	return c.sendMessage(SendMessageRequest{ChatID: c.chatID, Text: text, ParseMode: "HTML", ReplyMarkup: keyboard})
}

// Edit replaces a message sent by Send. Editing never notifies.
func (c *Client) Edit(messageID int, text string, keyboard *InlineKeyboardMarkup) error {
	return c.editMessage(messageID, text, keyboard)
}

// SetCommands registers the command menu shown after typing "/".
func (c *Client) SetCommands() error {
	type command struct {
		Command     string `json:"command"`
		Description string `json:"description"`
	}
	list := make([]command, 0, len(Commands))
	for _, cmd := range Commands {
		list = append(list, command{cmd.Command, cmd.Description})
	}
	return c.callJSON("setMyCommands", map[string]any{"commands": list})
}

func (c *Client) callJSON(method string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/"+method, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("calling %s: %w", method, transportError(err))
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

// SettingsView is the state shown on the settings panel.
type SettingsView struct {
	Notifications string // on | silent | off
	// NotificationsEffective is the mode actually used: "off" falls back to
	// silent when no other channel (PushWard) can deliver alerts.
	NotificationsEffective string
	OwnerWindows           bool
	OwnerWindowsAvailable  bool // vaults are configured
	TapWindows             bool
	Saved                  bool // changes are written to disk
}

// WindowView is the state of one owner window for messages.
type WindowView struct {
	ID          string
	Vault       string
	Tag         string
	Source      string
	Opener      string
	OpenedAt    time.Time
	ExpiresAt   time.Time
	ClosedAt    time.Time
	CloseReason string // human text, set once closed
	Requests    int
	MaxRequests int
	Items       []string
	MaxItems    int
}

func clock(t time.Time) string { return t.Format("15:04 MST") }

func minutes(w WindowView) int {
	return int(w.ExpiresAt.Sub(w.OpenedAt).Round(time.Minute) / time.Minute)
}

func esc(s string) string { return html.EscapeString(s) }

// scopeLines states what a window covers, in the words used on every card.
// An empty tag means every item in the vault.
func scopeLines(vault, tag string, maxRequests, maxItems int) string {
	which := "every item in it"
	if tag != "" {
		which = "items tagged <code>" + esc(tag) + "</code> only"
	}
	return "Vault: <b>" + esc(vault) + "</b>, " + which + "\n" +
		"Reads only. Values go to commands, never to the model.\n" +
		"Not covered: cards, bank, passkeys, files, writes, or Secret Gate credentials.\n" +
		fmt.Sprintf("Max %d reads and %d items.", maxRequests, maxItems)
}

// HelpMessage lists the commands.
func HelpMessage() string {
	var b strings.Builder
	b.WriteString("🔐 <b>Secret Gate controls</b>\n\n")
	for _, cmd := range Commands {
		b.WriteString("/" + cmd.Command + ": " + esc(cmd.Description) + "\n")
	}
	b.WriteString("\nEvery open needs a second tap on the confirm card. A window ends on its own, and /close ends it early.")
	return b.String()
}

func button(text, data string) InlineKeyboardButton {
	return InlineKeyboardButton{Text: text, CallbackData: data}
}

// PanelMessage is the control message the owner pins.
func PanelMessage(open []WindowView, defaultMinutes int, owner bool) (string, *InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("🔐 <b>Secret Gate</b>\n")
	if len(open) == 0 {
		b.WriteString("No read window is open.")
	}
	for _, w := range open {
		b.WriteString(fmt.Sprintf("🟢 %s open until %s (%d of %d reads)\n", esc(w.Vault), clock(w.ExpiresAt), w.Requests, w.MaxRequests))
	}
	var rows [][]InlineKeyboardButton
	if owner {
		rows = append(rows, []InlineKeyboardButton{
			button(fmt.Sprintf("🔓 Open reads %dm", defaultMinutes), CBOpen+":0"),
			button("🛑 Close all", CBCloseAll+":x"),
		})
	}
	rows = append(rows, []InlineKeyboardButton{button("📋 Pending", CBPending+":x"), button("⚙️ Settings", CBSettings+":x")})
	return strings.TrimRight(b.String(), "\n"), &InlineKeyboardMarkup{InlineKeyboard: rows}
}

// WindowConfirm is the content of the confirm card.
type WindowConfirm struct {
	Vault       string
	Tag         string
	Minutes     int
	Until       time.Time
	MaxRequests int
	MaxItems    int
	Nonce       string
}

// WindowConfirmMessage asks the owner to confirm a window with its exact scope.
func WindowConfirmMessage(c WindowConfirm) (string, *InlineKeyboardMarkup) {
	text := "🔓 <b>Open a read window?</b>\n" + scopeLines(c.Vault, c.Tag, c.MaxRequests, c.MaxItems) +
		fmt.Sprintf("\n\nUntil <b>%s</b> (%d min). It ends on its own; /close ends it early.", clock(c.Until), c.Minutes)
	return text, &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{
		button("✅ Open until "+c.Until.Format("15:04"), CBConfirm+":"+c.Nonce),
		button("Cancel", CBCancel+":"+c.Nonce),
	}}}
}

// WindowConfirmGoneMessage replaces a confirm card that can no longer be used.
func WindowConfirmGoneMessage(reason string) string {
	return "⌛ Window not opened: " + esc(reason)
}

// WindowOpenedMessage is the card shown while a window is open.
func WindowOpenedMessage(w WindowView) (string, *InlineKeyboardMarkup) {
	by := ""
	if w.Opener != "" {
		by = " Opened by " + esc(w.Opener) + "."
	}
	text := fmt.Sprintf("🟢 <b>Reads open until %s</b> (%d min)\n", clock(w.ExpiresAt), minutes(w)) +
		scopeLines(w.Vault, w.Tag, w.MaxRequests, w.MaxItems) + "\n" +
		fmt.Sprintf("%d of %d reads so far.%s", w.Requests, w.MaxRequests, by) +
		"\nWindow: <code>" + esc(w.ID) + "</code>"
	return text, closeKeyboard(w.ID)
}

func closeKeyboard(id string) *InlineKeyboardMarkup {
	return &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{button("🛑 Close now", CBClose+":"+id)}}}
}

// WindowUse describes one first read of an item under a window.
type WindowUse struct {
	Window  WindowView
	Items   []string
	Fields  []string
	Agent   string // runtime, provider, project, machine in one line
	Reason  string
	Request string
}

// WindowUsedMessage is the audit message for the first read of an item.
func WindowUsedMessage(u WindowUse) (string, *InlineKeyboardMarkup) {
	items := make([]string, 0, len(u.Items))
	for _, it := range u.Items {
		items = append(items, "\""+esc(it)+"\"")
	}
	fields := "all fields"
	if len(u.Fields) > 0 {
		fields = esc(strings.Join(u.Fields, ", "))
	}
	text := "📖 <b>Read via window</b>: " + strings.Join(items, ", ") + "\nFields: " + fields
	if u.Agent != "" {
		text += "\nBy: " + esc(u.Agent)
	}
	if u.Reason != "" {
		text += "\nReason: <b>" + esc(u.Reason) + "</b>"
	}
	text += fmt.Sprintf("\n%d of %d reads, %d of %d items. Ends %s.",
		u.Window.Requests, u.Window.MaxRequests, len(u.Window.Items), u.Window.MaxItems, clock(u.Window.ExpiresAt))
	return text, closeKeyboard(u.Window.ID)
}

// WindowCounterMessage is the running counter edited in place of the card.
func WindowCounterMessage(w WindowView) (string, *InlineKeyboardMarkup) {
	text, kb := WindowOpenedMessage(w)
	return text, kb
}

// WindowClosedMessage replaces the card once a window is closed.
func WindowClosedMessage(w WindowView) string {
	end := w.ClosedAt
	if end.IsZero() {
		end = w.ExpiresAt
	}
	return fmt.Sprintf("⌛ <b>Reads window closed</b> at %s: %s\n%d of %d reads, %d items.\nVault: %s\nWindow: <code>%s</code>",
		clock(end), esc(w.CloseReason), w.Requests, w.MaxRequests, len(w.Items), esc(w.Vault), esc(w.ID))
}

// WindowListMessage shows the open windows.
func WindowListMessage(ws []WindowView) (string, *InlineKeyboardMarkup) {
	if len(ws) == 0 {
		return "No read window is open.", nil
	}
	var b strings.Builder
	b.WriteString("🟢 <b>Open windows</b>\n")
	var rows [][]InlineKeyboardButton
	for _, w := range ws {
		b.WriteString(fmt.Sprintf("%s until %s: %d of %d reads, %d of %d items (<code>%s</code>)\n",
			esc(w.Vault), clock(w.ExpiresAt), w.Requests, w.MaxRequests, len(w.Items), w.MaxItems, esc(w.ID)))
		rows = append(rows, []InlineKeyboardButton{button("🛑 Close "+w.Vault, CBClose+":"+w.ID)})
	}
	return strings.TrimRight(b.String(), "\n"), &InlineKeyboardMarkup{InlineKeyboard: rows}
}

func mark(on bool, label string) string {
	if on {
		return "✅ " + label
	}
	return label
}

// SettingsMessage renders the settings panel with one row per switch.
func SettingsMessage(v SettingsView) (string, *InlineKeyboardMarkup) {
	var b strings.Builder
	b.WriteString("⚙️ <b>Settings</b>\n\n")
	b.WriteString("🔔 <b>Telegram alerts</b>: " + v.Notifications)
	if v.NotificationsEffective != "" && v.NotificationsEffective != v.Notifications {
		b.WriteString(" (acting as " + v.NotificationsEffective + ": no other alert channel is configured)")
	}
	b.WriteString("\nOn pushes every alert. Silent delivers them without a push. Off sends nothing unprompted; commands, buttons, and /pending still work, and approvals made here still count.\n\n")
	b.WriteString("🔓 <b>Phone windows</b>: " + onOff(v.OwnerWindows))
	if !v.OwnerWindowsAvailable {
		b.WriteString(" (no vault is configured, so it cannot be turned on)")
	}
	b.WriteString("\nLets you open a read window from here before any request exists.\n\n")
	b.WriteString("⏱ <b>Tap windows</b>: " + onOff(v.TapWindows))
	b.WriteString("\nThe \"Approve 30m\" and \"Approve + writes\" buttons on approval cards.")
	if !v.Saved {
		b.WriteString("\n\n⚠️ Changes last until the server restarts (no settings file is configured).")
	}
	rows := [][]InlineKeyboardButton{
		{
			button(mark(v.Notifications == "on", "🔔 On"), CBSet+":telegram_notifications=on"),
			button(mark(v.Notifications == "silent", "🔕 Silent"), CBSet+":telegram_notifications=silent"),
			button(mark(v.Notifications == "off", "🚫 Off"), CBSet+":telegram_notifications=off"),
		},
		{
			button(mark(v.OwnerWindows, "🔓 Phone windows on"), CBSet+":owner_windows=on"),
			button(mark(!v.OwnerWindows, "Off"), CBSet+":owner_windows=off"),
		},
		{
			button(mark(v.TapWindows, "⏱ Tap windows on"), CBSet+":tap_windows=on"),
			button(mark(!v.TapWindows, "Off"), CBSet+":tap_windows=off"),
		},
		{button("‹ Panel", CBPanelRedraw+":x")},
	}
	return b.String(), &InlineKeyboardMarkup{InlineKeyboard: rows}
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// SettingChangedMessage is the alert sent when a setting changes.
func SettingChangedMessage(name, from, to, by string) string {
	return fmt.Sprintf("⚙️ <b>Setting changed</b>: %s, %s → %s\nBy: %s", esc(name), esc(from), esc(to), esc(by))
}

// SortedWindows orders views by opening time.
func SortedWindows(ws []WindowView) []WindowView {
	sort.Slice(ws, func(i, j int) bool { return ws[i].OpenedAt.Before(ws[j].OpenedAt) })
	return ws
}
