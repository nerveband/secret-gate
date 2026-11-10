package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/nerveband/secret-gate/internal/audit"
	"github.com/nerveband/secret-gate/internal/autosession"
	"github.com/nerveband/secret-gate/internal/config"
	"github.com/nerveband/secret-gate/internal/handlers"
	"github.com/nerveband/secret-gate/internal/logger"
	"github.com/nerveband/secret-gate/internal/opconnect"
	"github.com/nerveband/secret-gate/internal/opsdk"
	"github.com/nerveband/secret-gate/internal/pushward"
	"github.com/nerveband/secret-gate/internal/settings"
	"github.com/nerveband/secret-gate/internal/store"
	"github.com/nerveband/secret-gate/internal/telegram"
	"github.com/nerveband/secret-gate/internal/tz"
	"github.com/nerveband/secret-gate/internal/version"
)

func main() {
	log := logger.New()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config", logger.F("error", err.Error()))
	}

	if err := cfg.Validate(); err != nil {
		log.Fatal("Invalid config", logger.F("error", err.Error()))
	}

	// Initialize components
	requestStore := store.New()
	sessionStore := autosession.NewStore()
	opClient := opconnect.New(cfg.OPConnectHost, cfg.OPConnectToken)
	var tgClient *telegram.Client
	if strings.TrimSpace(cfg.TelegramBotToken) != "" && cfg.TelegramChatID != 0 {
		tgClient = telegram.New(cfg.TelegramBotToken, cfg.TelegramChatID)
	}

	// Create HTTP handler
	var h *handlers.Handler
	if tgClient != nil {
		h = handlers.New(requestStore, opClient, tgClient, cfg, sessionStore)
		h.SetControl(tgClient)
		tgClient.SetSilent(h.TelegramSilent)
	} else {
		h = handlers.New(requestStore, opClient, nil, cfg, sessionStore)
	}

	settingsStore, err := settings.Open(cfg.SettingsPath, settings.Defaults{
		TelegramNotifications: cfg.TelegramNotifications,
		OwnerWindows:          cfg.OwnerWindowEnabled,
		TapWindows:            true,
		Timezone:              cfg.Timezone,
	})
	if err != nil {
		// The store still works with defaults; a damaged file must not keep
		// the gate from starting.
		log.Error("Could not read saved settings; using defaults", logger.F("error", err.Error()))
	}
	h.SetSettings(settingsStore)
	h.SetAudit(audit.New(cfg.AuditLogPath))

	attachments := "disabled (no OP_SERVICE_ACCOUNT_TOKEN)"
	if token := strings.TrimSpace(cfg.OPServiceAccountToken); token != "" {
		h.SetFileAttacher(opsdk.New(token, version.Version))
		attachments = "enabled"
	}
	pushwardStatus := "disabled"
	if apiKey := strings.TrimSpace(cfg.PushWardAPIKey); apiKey != "" {
		e2eKey := strings.TrimSpace(cfg.PushWardE2EKey)
		if e2eKey != "" {
			kid, err := pushward.KeyID(e2eKey)
			if err != nil {
				log.Fatal("Invalid PUSHWARD_E2E_KEY", logger.F("error", err.Error()))
			}
			pushwardStatus = "enabled (e2e key_id=" + kid + ")"
		} else {
			pushwardStatus = "enabled"
		}
		h.SetPushWardClient(pushward.New(apiKey, e2eKey))
	}
	approverAPI := "disabled"
	if strings.TrimSpace(cfg.ApproverToken) != "" || cfg.ApproverTokenSHA256 != "" {
		approverAPI = "enabled"
	}
	openerToken := "disabled"
	if cfg.OpenerTokenSHA256 != "" {
		openerToken = "enabled"
	}
	persistence := "in memory (set SETTINGS_PATH to keep /set changes across restarts)"
	if settingsStore.Persistent() {
		persistence = "saved to " + cfg.SettingsPath
	}
	values := settingsStore.Get()
	if err := tz.Set(values.Timezone); err != nil {
		log.Error("Unknown time zone; times are shown in UTC", logger.F("error", err.Error(), "timezone", values.Timezone))
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/_/health", h.HandleHealth) // OpenFaaS watchdog health check path
	mux.HandleFunc("/request", h.HandleRequest)
	mux.HandleFunc("/search", h.HandleSearch)
	mux.HandleFunc("/fields", h.HandleFields)
	mux.HandleFunc("/status/", h.HandleStatus)
	mux.HandleFunc("/secret/", h.HandleSecret)
	mux.HandleFunc("/entry/", h.HandleEntry)
	mux.HandleFunc("/approvals", h.HandleApprovals)
	mux.HandleFunc("/approvals/", h.HandleApprovals)
	mux.HandleFunc("/client/", h.HandleClientDownload)
	mux.HandleFunc("/openapi.json", h.HandleOpenAPI)
	mux.HandleFunc("/", handleRoot)

	// Start Telegram polling goroutine. Only the approver's taps and direct
	// messages are acted on; the handlers check who sent them.
	if tgClient != nil {
		go func() {
			if err := tgClient.SetCommands(); err != nil {
				log.Error("Failed to register Telegram commands", logger.F("error", err.Error()))
			}
			h.AnnounceStartup()
		}()
		go tgClient.PollUpdates(h.HandleTelegramCallback, h.HandleTelegramMessage)
	}

	// Write reminders, expired-request message updates, and owner window
	// expiry need a finer tick than cleanup: a reminder is only useful
	// before the request expires, and a closed window should say so at once.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for now := range ticker.C {
			h.SweepPending(now)
		}
	}()

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			if removed := requestStore.Cleanup(); removed > 0 {
				log.Info("Cleaned up expired requests", logger.F("removed", removed))
			}
			if removed := sessionStore.Cleanup(); removed > 0 {
				log.Info("Cleaned up expired auto-approval sessions", logger.F("removed", removed))
			}
		}
	}()

	log.Info("Starting secret-gate", logger.F(
		"port", cfg.Port,
		"auto_approve_ttl", cfg.AutoApproveTTL.String(),
		"long_poll_max_wait", cfg.LongPollMaxWait.String(),
		"write_request_ttl", cfg.WriteRequestTTL.String(),
		"write_window_ttl", cfg.WriteWindowTTL.String(),
		"write_followup_ttl", cfg.WriteFollowUpTTL.String(),
		"write_reminder_before", cfg.WriteReminderBefore.String(),
		"file_uploads", attachments,
		"pushward", pushwardStatus,
		"approver_api", approverAPI,
		"opener_token", openerToken,
		"telegram_notifications", values.TelegramNotifications,
		"owner_windows", values.OwnerWindows,
		"owner_window_vaults", len(cfg.OwnerWindowVaults),
		"tap_windows", values.TapWindows,
		"timezone", tz.Name(),
		"settings", persistence,
	))
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // Disabled so long-polling handlers are not aborted by WriteTimeout
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Failed to start server", logger.F("error", err.Error()))
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Only handle exact root path, let other paths 404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"service": "secret-gate", "status": "running"}`))
}
