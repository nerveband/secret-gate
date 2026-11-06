package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nerveband/secret-gate/internal/requeststate"
)

type watchTask struct {
	spec      WatchSpec
	startedAt time.Time
	cancel    context.CancelFunc
}

type Watcher struct {
	mu         sync.Mutex
	watches    map[string]*watchTask
	cache      *Cache
	defaultTTL time.Duration
	stopping   bool
	httpClient *http.Client
	store      *watchStore
	restoreErr error
}

func NewWatcher(cache *Cache, defaultTTL time.Duration, storePaths ...string) *Watcher {
	w := &Watcher{
		watches:    make(map[string]*watchTask),
		cache:      cache,
		defaultTTL: defaultTTL,
		httpClient: &http.Client{Timeout: 0},
	}
	if len(storePaths) > 0 && storePaths[0] != "" {
		w.store = newWatchStore(storePaths[0])
		specs, err := w.store.load()
		if err != nil {
			w.restoreErr = fmt.Errorf("load persisted watches: %w", err)
		} else {
			for _, spec := range specs {
				w.registerLocked(spec)
			}
		}
	}
	return w
}

// Register durably records a watch before reporting success.
func (w *Watcher) Register(spec WatchSpec) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, exists := w.watches[spec.Token]; exists {
		return false, nil
	}
	w.registerLocked(spec)
	if err := w.persistLocked(); err != nil {
		task := w.watches[spec.Token]
		task.cancel()
		delete(w.watches, spec.Token)
		return false, err
	}
	return true, nil
}

func (w *Watcher) registerLocked(spec WatchSpec) {
	ctx, cancel := context.WithCancel(context.Background())
	task := &watchTask{
		spec:      spec,
		startedAt: time.Now(),
		cancel:    cancel,
	}
	w.watches[spec.Token] = task
	go w.runWatch(ctx, spec, task)
}

func (w *Watcher) persistLocked() error {
	if w.store == nil {
		return nil
	}
	specs := make([]WatchSpec, 0, len(w.watches))
	for _, task := range w.watches {
		specs = append(specs, task.spec)
	}
	return w.store.save(specs)
}

// Unwatch removes a watch only after the durable store reflects the removal.
func (w *Watcher) Unwatch(token string) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	task, exists := w.watches[token]
	if !exists {
		return false, nil
	}
	delete(w.watches, token)
	if err := w.persistLocked(); err != nil {
		w.watches[token] = task
		return false, err
	}
	task.cancel()
	return true, nil
}

// List returns a snapshot of active watches.
func (w *Watcher) List() []WatchInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	infos := make([]WatchInfo, 0, len(w.watches))
	for token, task := range w.watches {
		infos = append(infos, WatchInfo{
			Token:      token,
			SecretName: task.spec.SecretName,
			Vault:      task.spec.Vault,
			State:      "watching",
			Since:      task.startedAt.Format(time.RFC3339),
		})
	}
	return infos
}

// Count returns the number of active watches.
func (w *Watcher) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watches)
}

func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopping = true
	for _, task := range w.watches {
		task.cancel()
	}
	// Keep the durable watch file intact. A replacement daemon restores these
	// non-terminal watches after the current goroutines exit.
	w.watches = make(map[string]*watchTask)
}

func (w *Watcher) runWatch(ctx context.Context, spec WatchSpec, task *watchTask) {
	defer func() {
		for {
			w.mu.Lock()
			if w.stopping || w.watches[spec.Token] != task {
				w.mu.Unlock()
				return
			}
			delete(w.watches, spec.Token)
			if err := w.persistLocked(); err == nil {
				w.mu.Unlock()
				return
			}
			w.watches[spec.Token] = task
			w.mu.Unlock()
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
		}
	}()
	var deadline time.Time
	if spec.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, spec.ExpiresAt); err == nil {
			deadline = t
		}
	}
	if deadline.IsZero() {
		deadline = time.Now().Add(15 * time.Minute)
	}
	approvedSeen := false

	backoff := 1 * time.Second
	maxBackoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if time.Now().After(deadline) {
			state := "expired"
			if approvedSeen {
				state = "failed"
			}
			w.recordState(spec, state)
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, state, "")
			return
		}

		// Long-poll status endpoint with wait=25
		targetURL := spec.StatusURL
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = fmt.Sprintf("%s%swait=25", targetURL, sep)

		reqCtx, reqCancel := context.WithTimeout(ctx, 35*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			reqCancel()
			return
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			reqCancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		reqCancel()

		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			if entry, ok := w.cache.Get(spec.SecretName, spec.Vault); ok && entry.Fields != nil {
				w.recordState(spec, "approved")
				_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "approved", "")
			} else {
				w.recordState(spec, "expired")
				_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "expired", "")
			}
			return
		}

		if resp.StatusCode != http.StatusOK {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		backoff = 1 * time.Second

		var status statusWireResponse
		if err := json.Unmarshal(respBody, &status); err != nil {
			continue
		}

		switch status.Status {
		case "pending":
			continue

		case "approved":
			approvedSeen = true
			if status.SecretURL == "" {
				w.recordState(spec, "failed")
				_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "failed", "approved request did not include a completion URL")
				return
			}
			if err := w.retrieveAndCache(ctx, spec, status.SecretURL); err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
					backoff = min(backoff*2, maxBackoff)
					continue
				}
			}
			terminal := "approved"
			if spec.IsMutation {
				terminal = "completed"
			}
			w.recordState(spec, terminal)
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, terminal, "")
			return

		case "denied":
			w.recordState(spec, "denied")
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "denied", "")
			return

		case "expired":
			w.recordState(spec, "expired")
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "expired", "")
			return

		default:
			w.recordState(spec, "failed")
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "failed", "server returned an unknown request status")
			return
		}
	}
}

func (w *Watcher) recordState(spec WatchSpec, state string) {
	if spec.StateDir == "" {
		return
	}
	for {
		ledger, err := requeststate.Open(spec.StateDir)
		if err == nil {
			err = ledger.SetState(spec.Token, state)
		}
		if err == nil {
			return
		}
		w.mu.Lock()
		stopping := w.stopping
		w.mu.Unlock()
		if stopping {
			return
		}
		time.Sleep(time.Second)
	}
}

func (w *Watcher) retrieveAndCache(ctx context.Context, spec WatchSpec, secretURL string) error {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, secretURL, nil)
	if err != nil {
		return fmt.Errorf("create completion request: %w", err)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("complete approved request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("completion returned HTTP %d", resp.StatusCode)
	}

	if spec.IsMutation {
		// The successful GET committed the mutation. Its response contains
		// metadata only and must never be cached as secret fields.
		return nil
	}

	var secretResp secretWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return fmt.Errorf("decode completion response: %w", err)
	}

	fields := secretResp.Secret
	if fields == nil && len(secretResp.Secrets) > 0 {
		fields = secretResp.Secrets[spec.SecretName]
		if fields == nil && len(secretResp.Secrets) == 1 {
			for _, f := range secretResp.Secrets {
				fields = f
			}
		}
	}

	if fields == nil {
		return fmt.Errorf("completion response did not contain fields for %q", spec.SecretName)
	}
	resolvedVault := secretResp.Vault
	if resolvedVault == "" {
		resolvedVault = secretResp.Vaults[spec.SecretName]
	}
	if resolvedVault == "" && len(secretResp.Vaults) == 1 {
		for _, only := range secretResp.Vaults {
			resolvedVault = only
		}
	}
	if resolvedVault == "" {
		resolvedVault = spec.Vault
	}
	ttl := w.defaultTTL
	if spec.CacheTTLSec > 0 {
		ttl = time.Duration(spec.CacheTTLSec) * time.Second
	}
	w.cache.Store(spec.SecretName, resolvedVault, fields, ttl)
	if spec.Vault != resolvedVault {
		w.cache.Store(spec.SecretName, spec.Vault, fields, ttl)
	}
	return nil
}

type statusWireResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type secretWireResponse struct {
	Secret  map[string]string            `json:"secret"`
	Secrets map[string]map[string]string `json:"secrets"`
	Vault   string                       `json:"vault,omitempty"`
	Vaults  map[string]string            `json:"vaults,omitempty"`
}
