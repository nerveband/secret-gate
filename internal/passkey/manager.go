package passkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

const (
	// DefaultHold is how long a loaded or armed authenticator stays in the tab.
	DefaultHold = 10 * time.Minute
	// MaxHold caps how long one approval can keep a passkey usable.
	MaxHold = 30 * time.Minute
)

// Credential has the shape of the DevTools WebAuthn.Credential type. Binary
// values are standard base64 strings, as DevTools sends and accepts them.
type Credential struct {
	CredentialID string `json:"credentialId"`
	IsResident   bool   `json:"isResidentCredential"`
	RPID         string `json:"rpId,omitempty"`
	PrivateKey   string `json:"privateKey"`
	UserHandle   string `json:"userHandle,omitempty"`
	SignCount    uint32 `json:"signCount"`
}

// Info describes a held authenticator. It never contains key material.
type Info struct {
	Session      string    `json:"session"`
	Mode         string    `json:"mode"` // register | signin
	TargetID     string    `json:"target_id"`
	PageURL      string    `json:"page_url"`
	RPID         string    `json:"rp_id,omitempty"`
	CredentialID string    `json:"credential_id,omitempty"`
	SignCount    uint32    `json:"sign_count"`
	Item         string    `json:"item,omitempty"`
	Vault        string    `json:"vault,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Target names the browser tab to hold an authenticator in.
type Target struct {
	Endpoint string        // DevTools address, loopback only
	PageURL  string        // substring of the tab URL
	TargetID string        // exact DevTools target ID
	Hold     time.Duration // 0 means DefaultHold
}

// SignCountFloor returns the counter to load a credential with: the stored
// value or the current Unix time, whichever is larger. Every later load starts
// above any count a relying party has seen, so a sign-in never needs a counter
// write to stay valid. uint32 seconds last until 2106.
func SignCountFloor(stored uint32, now time.Time) uint32 {
	if t := uint32(now.Unix()); t > stored {
		return t
	}
	return stored
}

type session struct {
	info            Info
	conn            *cdpConn
	cdpSession      string
	authenticatorID string
	timer           *time.Timer
}

// Manager keeps DevTools sessions open while their authenticators are in use.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*session
	now      func() time.Time
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*session), now: time.Now}
}

// Arm adds an empty authenticator so the agent can register a passkey on the
// site. Collect then reads the new credential.
func (m *Manager) Arm(ctx context.Context, t Target) (Info, error) {
	return m.open(ctx, t, "register", nil)
}

// Load adds an authenticator holding cred so the agent can sign in.
func (m *Manager) Load(ctx context.Context, t Target, cred Credential, item, vault string) (Info, error) {
	if cred.CredentialID == "" || cred.PrivateKey == "" || cred.RPID == "" {
		return Info{}, errors.New("credential ID, private key, and RP ID are required")
	}
	cred.SignCount = SignCountFloor(cred.SignCount, m.now())
	info, err := m.open(ctx, t, "signin", &cred)
	if err != nil {
		return Info{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[info.Session]
	s.info.Item, s.info.Vault = item, vault
	s.info.RPID, s.info.CredentialID, s.info.SignCount = cred.RPID, cred.CredentialID, cred.SignCount
	return s.info, nil
}

func (m *Manager) open(ctx context.Context, t Target, mode string, cred *Credential) (Info, error) {
	hold := t.Hold
	if hold <= 0 {
		hold = DefaultHold
	}
	if hold > MaxHold {
		return Info{}, fmt.Errorf("hold %s is longer than the %s maximum", hold, MaxHold)
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	wsURL, err := ResolveEndpoint(ctx, t.Endpoint)
	if err != nil {
		return Info{}, err
	}
	conn, err := dialCDP(ctx, wsURL)
	if err != nil {
		return Info{}, err
	}
	s, err := setUp(ctx, conn, t, cred)
	if err != nil {
		conn.close()
		return Info{}, err
	}
	id, err := randomID()
	if err != nil {
		conn.close()
		return Info{}, err
	}
	s.info.Session, s.info.Mode, s.info.ExpiresAt = id, mode, m.now().Add(hold)
	m.mu.Lock()
	m.sessions[id] = s
	s.timer = time.AfterFunc(hold, func() { _, _ = m.Release(context.Background(), id) })
	m.mu.Unlock()
	return s.info, nil
}

func setUp(ctx context.Context, conn *cdpConn, t Target, cred *Credential) (*session, error) {
	var targets struct {
		TargetInfos []pageTarget `json:"targetInfos"`
	}
	if err := conn.call(ctx, "", "Target.getTargets", map[string]any{}, &targets); err != nil {
		return nil, err
	}
	page, err := pickTarget(targets.TargetInfos, t.TargetID, t.PageURL)
	if err != nil {
		return nil, err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": page.TargetID, "flatten": true}, &attached); err != nil {
		return nil, err
	}
	sid := attached.SessionID
	// WebAuthn needs a focused document; a background agent tab is not.
	if err := conn.call(ctx, sid, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true}, nil); err != nil {
		return nil, err
	}
	if err := conn.call(ctx, sid, "WebAuthn.enable", map[string]any{"enableUI": false}, nil); err != nil {
		return nil, err
	}
	var added struct {
		AuthenticatorID string `json:"authenticatorId"`
	}
	options := map[string]any{
		"protocol": "ctap2", "transport": "internal",
		"hasResidentKey": true, "hasUserVerification": true, "isUserVerified": true,
		"automaticPresenceSimulation": true,
	}
	if err := conn.call(ctx, sid, "WebAuthn.addVirtualAuthenticator", map[string]any{"options": options}, &added); err != nil {
		return nil, err
	}
	if cred != nil {
		if err := conn.call(ctx, sid, "WebAuthn.addCredential", map[string]any{"authenticatorId": added.AuthenticatorID, "credential": cred}, nil); err != nil {
			return nil, err
		}
	}
	return &session{
		info:            Info{TargetID: page.TargetID, PageURL: page.URL},
		conn:            conn,
		cdpSession:      sid,
		authenticatorID: added.AuthenticatorID,
	}, nil
}

func (m *Manager) get(id string) (*session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("no passkey session %q (it may have expired or been released)", id)
	}
	return s, nil
}

func (s *session) credentials(ctx context.Context) ([]Credential, error) {
	var out struct {
		Credentials []Credential `json:"credentials"`
	}
	if err := s.conn.call(ctx, s.cdpSession, "WebAuthn.getCredentials", map[string]any{"authenticatorId": s.authenticatorID}, &out); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}

// Collect returns the credential the site registered on an armed
// authenticator and records which item it will be stored in. The
// authenticator stays in the tab so the agent can test a sign-in.
func (m *Manager) Collect(ctx context.Context, id, item, vault string) (Credential, Info, error) {
	s, err := m.get(id)
	if err != nil {
		return Credential{}, Info{}, err
	}
	if s.info.Mode != "register" {
		return Credential{}, Info{}, errors.New("this session holds a loaded passkey; only armed sessions can register")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	creds, err := s.credentials(ctx)
	if err != nil {
		return Credential{}, Info{}, err
	}
	if len(creds) != 1 {
		return Credential{}, Info{}, fmt.Errorf("the authenticator holds %d credentials; expected exactly 1 (finish the site's passkey registration first)", len(creds))
	}
	c := creds[0]
	m.mu.Lock()
	s.info.Item, s.info.Vault = item, vault
	s.info.RPID, s.info.CredentialID, s.info.SignCount = c.RPID, c.CredentialID, c.SignCount
	info := s.info
	m.mu.Unlock()
	return c, info, nil
}

// Release removes the authenticator from the tab, detaches, and returns the
// final sign count. A session whose browser went away is dropped silently.
func (m *Manager) Release(ctx context.Context, id string) (Info, error) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
		if s.timer != nil {
			s.timer.Stop()
		}
	}
	m.mu.Unlock()
	if !ok {
		return Info{}, fmt.Errorf("no passkey session %q (it may have expired or been released)", id)
	}
	defer s.conn.close()
	if !s.conn.alive() {
		return s.info, nil
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if creds, err := s.credentials(ctx); err == nil {
		for _, c := range creds {
			if s.info.CredentialID == "" || c.CredentialID == s.info.CredentialID {
				s.info.SignCount = c.SignCount
				break
			}
		}
	}
	_ = s.conn.call(ctx, s.cdpSession, "WebAuthn.removeVirtualAuthenticator", map[string]any{"authenticatorId": s.authenticatorID}, nil)
	_ = s.conn.call(ctx, s.cdpSession, "WebAuthn.disable", map[string]any{}, nil)
	_ = s.conn.call(ctx, s.cdpSession, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": false}, nil)
	_ = s.conn.call(ctx, "", "Target.detachFromTarget", map[string]any{"sessionId": s.cdpSession}, nil)
	return s.info, nil
}

// List returns the held sessions, oldest expiry first.
func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// Active reports whether any authenticator is held.
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions) > 0
}

// CloseAll releases every session, for daemon shutdown.
func (m *Manager) CloseAll() {
	for _, info := range m.List() {
		_, _ = m.Release(context.Background(), info.Session)
	}
}

func randomID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
