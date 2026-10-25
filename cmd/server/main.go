package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/johnuopini/secret-gate/internal/autosession"
	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/handlers"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/telegram"
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
	tgClient := telegram.New(cfg.TelegramBotToken, cfg.TelegramChatID)

	// Create HTTP handler
	h := handlers.New(requestStore, opClient, tgClient, cfg, sessionStore)

	// Set up routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.HandleHealth)
	mux.HandleFunc("/_/health", h.HandleHealth) // OpenFaaS watchdog health check path
	mux.HandleFunc("/request", h.HandleRequest)
	mux.HandleFunc("/search", h.HandleSearch)
	mux.HandleFunc("/fields", h.HandleFields)
	mux.HandleFunc("/status/", h.HandleStatus)
	mux.HandleFunc("/secret/", h.HandleSecret)
	mux.HandleFunc("/client/", h.HandleClientDownload)
	mux.HandleFunc("/openapi.json", h.HandleOpenAPI)
	mux.HandleFunc("/", handleRoot)

	// Start Telegram polling goroutine
	go tgClient.PollUpdates(func(callback *telegram.CallbackQuery) {
		approver := callback.From.Username
		if approver == "" {
			approver = callback.From.FirstName
		}
		h.HandleTelegramAction(callback.ID, callback.Data, approver)
	})

	// Write reminders and expired-request message updates need a finer tick
	// than cleanup: a reminder is only useful before the request expires.
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
