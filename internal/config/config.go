package config

import (
	"errors"
	"os"
	"strconv"
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


	// PushWard settings (optional second or standalone approval channel)
	PushWardAPIKey string
	PushWardE2EKey string

	// ApproverToken enables the authenticated Approver API (/approvals/*) for
	// external apps (such as Voice Workspace) to stream and decide approvals.
	ApproverToken string
	// Request settings
	RequestTTL      time.Duration
	CleanupInterval time.Duration
	AutoApproveTTL  time.Duration

	// Write approval settings
	WriteRequestTTL     time.Duration // how long a write request waits for a tap
	WriteWindowTTL      time.Duration // "Approve + writes" window length; 0 hides the button
	WriteFollowUpTTL    time.Duration // same-requester updates to just-written items; 0 disables
	WriteReminderBefore time.Duration // reminder lead time before a write expires; 0 disables

	// Long-polling settings
	LongPollMaxWait time.Duration

	// Webhook settings
	WebhookBaseURL string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  getEnvDefault("PORT", "8080"),
		OPConnectHost:         os.Getenv("OP_CONNECT_HOST"),
		OPConnectToken:        readSecretOrEnv("op_connect_token", "OP_CONNECT_TOKEN"),
		OPServiceAccountToken: readSecretOrEnv("op_service_account_token", "OP_SERVICE_ACCOUNT_TOKEN"),
		TelegramBotToken:      readSecretOrEnv("telegram_bot_token", "TELEGRAM_BOT_TOKEN"),
		PushWardAPIKey:        firstEnv(readSecretOrEnv("pushward_api_key", "PUSHWARD_API_KEY"), readSecretOrEnv("pushward_api_token", "PUSHWARD_API_TOKEN")),
		PushWardE2EKey:        readSecretOrEnv("pushward_e2e_key", "PUSHWARD_E2E_KEY"),
		ApproverToken:         firstEnv(readSecretOrEnv("secret_gate_approver_token", "SECRET_GATE_APPROVER_TOKEN"), readSecretOrEnv("approver_token", "APPROVER_TOKEN")),
		WebhookBaseURL:        os.Getenv("WEBHOOK_BASE_URL"),
		RequestTTL:            getDurationDefault("REQUEST_TTL", 15*time.Minute),
		CleanupInterval:       getDurationDefault("CLEANUP_INTERVAL", 5*time.Minute),
		AutoApproveTTL:        getDurationDefault("AUTO_APPROVE_TTL", 30*time.Minute),
		LongPollMaxWait:       getDurationDefault("LONG_POLL_MAX_WAIT", 25*time.Second),

		WriteRequestTTL:     getDurationDefault("WRITE_REQUEST_TTL", time.Hour),
		WriteWindowTTL:      getDurationDefault("WRITE_WINDOW_TTL", 15*time.Minute),
		WriteFollowUpTTL:    getDurationDefault("WRITE_FOLLOWUP_TTL", 15*time.Minute),
		WriteReminderBefore: getDurationDefault("WRITE_REMINDER_BEFORE", 10*time.Minute),
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

	return cfg, nil
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
	hasApprover := c.ApproverToken != ""
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
	}
	return nil
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

// readSecretOrEnv tries to read from OpenFaaS secret file first, then env var
func readSecretOrEnv(secretName, envName string) string {
	// OpenFaaS mounts secrets at /var/openfaas/secrets/
	secretPath := "/var/openfaas/secrets/" + secretName
	if data, err := os.ReadFile(secretPath); err == nil {
		return string(data)
	}

	return os.Getenv(envName)
}
