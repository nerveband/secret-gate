package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server settings
	Port string

	// 1Password Connect settings
	OPConnectHost  string
	OPConnectToken string
	// OPServiceAccountToken enables file uploads through the 1Password SDK.
	// Connect has no upload endpoint; without this token attaching is refused.
	OPServiceAccountToken string

	// Telegram settings
	TelegramBotToken string
	TelegramChatID   int64
	// TelegramApproverUserID is the only Telegram user whose taps and
	// commands are accepted. It defaults to TELEGRAM_CHAT_ID when that is a
	// private chat (a positive id) and is required for group chats.
	TelegramApproverUserID int64
	// TelegramNotifications is the default Telegram alert mode: on, silent
	// (delivered without a push), or off (nothing is pushed; commands and
	// on-demand approval cards still work). /set changes it at runtime.
	TelegramNotifications string

	// PushWard settings (optional second or standalone approval channel)
	PushWardAPIKey string
	PushWardE2EKey string

	// ApproverToken enables the authenticated Approver API (/approvals/*) for
	// external apps (such as Voice Workspace) to stream and decide approvals.
	// ApproverTokenSHA256 is the same credential stored as a hex SHA-256
	// digest, so the env file does not hold the token itself.
	ApproverToken       string
	ApproverTokenSHA256 string
	// OpenerTokenSHA256 is the hex SHA-256 digest of a token that may only
	// open, list, and close owner windows. It cannot read or decide approvals.
	OpenerTokenSHA256 string

	// Request settings
	RequestTTL      time.Duration
	CleanupInterval time.Duration
	AutoApproveTTL  time.Duration

	// Write approval settings
	WriteRequestTTL     time.Duration // how long a write request waits for a tap
	WriteWindowTTL      time.Duration // "Approve + writes" window length; 0 hides the button
	WriteFollowUpTTL    time.Duration // same-requester updates to just-written items; 0 disables
	WriteReminderBefore time.Duration // reminder lead time before a write expires; 0 disables

	// Owner windows: read windows the owner opens before any request exists.
	OwnerWindowEnabled     bool          // default for the "owner_windows" setting
	OwnerWindowVaults      []string      // vaults a window may cover; empty disables the feature
	OwnerWindowTag         string        // optional 1Password tag; empty covers every item in the vault
	OwnerWindowDeny        string        // case-insensitive regex of titles that are never covered
	OwnerWindowTTL         time.Duration // default length
	OwnerWindowMax         time.Duration // longest length a phone command may ask for
	OwnerWindowMaxRequests int           // covered requests per window
	OwnerWindowMaxItems    int           // distinct items per window
	OwnerWindowDailyMax    time.Duration // total window time per rolling 24 hours

	// SettingsPath stores the runtime settings changed with /set. Empty keeps
	// them in memory only.
	SettingsPath string
	// AuditLogPath appends owner window and settings events as JSON lines.
	AuditLogPath string

	// Long-polling settings
	LongPollMaxWait time.Duration

	// Webhook settings
	WebhookBaseURL string
}

// Defaults for owner windows.
const (
	DefaultOwnerWindowTTL         = 30 * time.Minute
	DefaultOwnerWindowMax         = 60 * time.Minute
	DefaultOwnerWindowMaxRequests = 30
	DefaultOwnerWindowMaxItems    = 10
	DefaultOwnerWindowDailyMax    = 4 * time.Hour
	// OwnerWindowCeiling is the longest window any configuration can allow.
	OwnerWindowCeiling = 2 * time.Hour
)

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  getEnvDefault("PORT", "8080"),
		OPConnectHost:         os.Getenv("OP_CONNECT_HOST"),
		OPConnectToken:        readSecretOrEnv("op_connect_token", "OP_CONNECT_TOKEN"),
		OPServiceAccountToken: readSecretOrEnv("op_service_account_token", "OP_SERVICE_ACCOUNT_TOKEN"),
		TelegramBotToken:      readSecretOrEnv("telegram_bot_token", "TELEGRAM_BOT_TOKEN"),
		TelegramNotifications: strings.ToLower(strings.TrimSpace(getEnvDefault("TELEGRAM_NOTIFICATIONS", "on"))),
		PushWardAPIKey:        firstEnv(readSecretOrEnv("pushward_api_key", "PUSHWARD_API_KEY"), readSecretOrEnv("pushward_api_token", "PUSHWARD_API_TOKEN")),
		PushWardE2EKey:        readSecretOrEnv("pushward_e2e_key", "PUSHWARD_E2E_KEY"),
		ApproverToken:         firstEnv(readSecretOrEnv("secret_gate_approver_token", "SECRET_GATE_APPROVER_TOKEN"), readSecretOrEnv("approver_token", "APPROVER_TOKEN")),
		ApproverTokenSHA256:   strings.ToLower(strings.TrimSpace(readSecretOrEnv("secret_gate_approver_token_sha256", "SECRET_GATE_APPROVER_TOKEN_SHA256"))),
		OpenerTokenSHA256:     strings.ToLower(strings.TrimSpace(readSecretOrEnv("secret_gate_opener_token_sha256", "SECRET_GATE_OPENER_TOKEN_SHA256"))),
		WebhookBaseURL:        os.Getenv("WEBHOOK_BASE_URL"),
		RequestTTL:            getDurationDefault("REQUEST_TTL", 15*time.Minute),
		CleanupInterval:       getDurationDefault("CLEANUP_INTERVAL", 5*time.Minute),
		AutoApproveTTL:        getDurationDefault("AUTO_APPROVE_TTL", 30*time.Minute),
		LongPollMaxWait:       getDurationDefault("LONG_POLL_MAX_WAIT", 25*time.Second),

		WriteRequestTTL:     getDurationDefault("WRITE_REQUEST_TTL", time.Hour),
		WriteWindowTTL:      getDurationDefault("WRITE_WINDOW_TTL", 15*time.Minute),
		WriteFollowUpTTL:    getDurationDefault("WRITE_FOLLOWUP_TTL", 15*time.Minute),
		WriteReminderBefore: getDurationDefault("WRITE_REMINDER_BEFORE", 10*time.Minute),

		OwnerWindowEnabled:     parseBool(os.Getenv("OWNER_WINDOW_ENABLED")),
		OwnerWindowVaults:      splitList(os.Getenv("OWNER_WINDOW_VAULTS")),
		OwnerWindowTag:         strings.TrimSpace(os.Getenv("OWNER_WINDOW_TAG")),
		OwnerWindowDeny:        os.Getenv("OWNER_WINDOW_DENY"),
		OwnerWindowTTL:         getDurationDefault("OWNER_WINDOW_TTL", DefaultOwnerWindowTTL),
		OwnerWindowMax:         getDurationDefault("OWNER_WINDOW_MAX", DefaultOwnerWindowMax),
		OwnerWindowMaxRequests: getIntDefault("OWNER_WINDOW_MAX_REQUESTS", DefaultOwnerWindowMaxRequests),
		OwnerWindowMaxItems:    getIntDefault("OWNER_WINDOW_MAX_ITEMS", DefaultOwnerWindowMaxItems),
		OwnerWindowDailyMax:    getDurationDefault("OWNER_WINDOW_DAILY_MAX", DefaultOwnerWindowDailyMax),

		SettingsPath: os.Getenv("SETTINGS_PATH"),
		AuditLogPath: os.Getenv("AUDIT_LOG_PATH"),
	}

	// Parse Telegram chat ID
	chatIDStr := readSecretOrEnv("telegram_chat_id", "TELEGRAM_CHAT_ID")
	if chatIDStr != "" {
		chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
		if err != nil {
			return nil, errors.New("invalid TELEGRAM_CHAT_ID: must be an integer")
		}
		cfg.TelegramChatID = chatID
	}
	if id := strings.TrimSpace(readSecretOrEnv("telegram_approver_user_id", "TELEGRAM_APPROVER_USER_ID")); id != "" {
		approver, err := strconv.ParseInt(id, 10, 64)
		if err != nil || approver <= 0 {
			return nil, errors.New("invalid TELEGRAM_APPROVER_USER_ID: must be a positive integer")
		}
		cfg.TelegramApproverUserID = approver
	}

	return cfg, nil
}

// ApproverUserID returns the Telegram user allowed to tap and send commands:
// the explicit setting, else the chat id of a private chat, else 0 (nobody).
func (c *Config) ApproverUserID() int64 {
	if c.TelegramApproverUserID > 0 {
		return c.TelegramApproverUserID
	}
	if c.TelegramChatID > 0 {
		return c.TelegramChatID
	}
	return 0
}

// Validate checks that required configuration is present
func (c *Config) Validate() error {
	if c.OPConnectHost == "" {
		return errors.New("OP_CONNECT_HOST is required")
	}
	if c.OPConnectToken == "" {
		return errors.New("OP_CONNECT_TOKEN is required")
	}
	hasTelegram := c.TelegramBotToken != "" || c.TelegramChatID != 0
	hasPushWard := c.PushWardAPIKey != ""
	hasApprover := c.ApproverToken != "" || c.ApproverTokenSHA256 != ""
	if !hasTelegram && !hasPushWard && !hasApprover {
		return errors.New("TELEGRAM_BOT_TOKEN (with TELEGRAM_CHAT_ID), PUSHWARD_API_KEY, or SECRET_GATE_APPROVER_TOKEN is required")
	}
	if hasTelegram {
		if c.TelegramBotToken == "" {
			return errors.New("TELEGRAM_BOT_TOKEN is required")
		}
		if c.TelegramChatID == 0 {
			return errors.New("TELEGRAM_CHAT_ID is required")
		}
		if c.ApproverUserID() == 0 {
			return errors.New("TELEGRAM_APPROVER_USER_ID is required when TELEGRAM_CHAT_ID is a group chat")
		}
	}
	switch c.TelegramNotifications {
	case "", "on", "silent", "off":
	default:
		return fmt.Errorf("TELEGRAM_NOTIFICATIONS must be on, silent, or off, not %q", c.TelegramNotifications)
	}
	for name, digest := range map[string]string{
		"SECRET_GATE_APPROVER_TOKEN_SHA256": c.ApproverTokenSHA256,
		"SECRET_GATE_OPENER_TOKEN_SHA256":   c.OpenerTokenSHA256,
	} {
		if digest != "" && !validDigest(digest) {
			return fmt.Errorf("%s must be 64 hex characters (the SHA-256 of the token)", name)
		}
	}
	if c.OwnerWindowDeny != "" {
		if _, err := regexp.Compile("(?i)" + c.OwnerWindowDeny); err != nil {
			return fmt.Errorf("invalid OWNER_WINDOW_DENY: %w", err)
		}
	}
	if c.OwnerWindowMax > OwnerWindowCeiling || c.OwnerWindowTTL > OwnerWindowCeiling {
		return fmt.Errorf("OWNER_WINDOW_TTL and OWNER_WINDOW_MAX may not exceed %s", OwnerWindowCeiling)
	}
	if c.OwnerWindowEnabled || len(c.OwnerWindowVaults) > 0 {
		if !hasTelegram && !hasPushWard {
			return errors.New("owner windows need Telegram or PushWard to deliver their audit messages")
		}
	}
	return nil
}

// TokenMatches reports whether token equals the plain token or hashes to the
// digest. Either may be empty; an empty token never matches.
func TokenMatches(token, plain, digest string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	ok := false
	if plain = strings.TrimSpace(plain); plain != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(plain)) == 1 {
			ok = true
		}
	}
	if digest != "" {
		sum := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(digest)) == 1 {
			ok = true
		}
	}
	return ok
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// getEnvDefault returns the environment variable value or a default
func getEnvDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func firstEnv(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// getDurationDefault parses a duration from env or returns the default
func getDurationDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getIntDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n > 0 {
			return n
		}
	}
	return defaultValue
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// readSecretOrEnv tries to read from OpenFaaS secret file first, then env var
func readSecretOrEnv(secretName, envName string) string {
	// OpenFaaS mounts secrets at /var/openfaas/secrets/
	secretPath := "/var/openfaas/secrets/" + secretName
	if data, err := os.ReadFile(secretPath); err == nil {
		return string(data)
	}

	return os.Getenv(envName)
}
