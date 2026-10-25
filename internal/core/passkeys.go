package core

import (
	"fmt"
	"strconv"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/johnuopini/secret-gate/internal/passkey"
)

// Field labels of an agent-owned passkey item. Only the private key is
// concealed; the others identify the credential.
const (
	PasskeyFieldCredentialID = "passkey credential id"
	PasskeyFieldPrivateKey   = "passkey private key"
	PasskeyFieldRPID         = "passkey rp id"
	PasskeyFieldUserHandle   = "passkey user handle"
	PasskeyFieldSignCount    = "passkey sign count"
)

// PasskeyTarget names the DevTools endpoint and tab that hold an authenticator.
type PasskeyTarget struct {
	Endpoint string
	PageURL  string
	TargetID string
	Hold     time.Duration
}

func (t PasskeyTarget) request(action string) daemon.PasskeyRequest {
	return daemon.PasskeyRequest{Action: action, Endpoint: t.Endpoint, PageURL: t.PageURL, TargetID: t.TargetID, HoldSec: int(t.Hold / time.Second)}
}

func (s *Service) passkeyDaemon() (PasskeyDaemonClient, error) {
	pd, ok := s.Daemon.(PasskeyDaemonClient)
	if !ok {
		return nil, E(ErrInternal, "this daemon client cannot hold passkeys", "")
	}
	if err := s.Daemon.EnsureRunning(); err != nil {
		return nil, E(ErrInternal, "local daemon could not start: "+err.Error(), "")
	}
	return pd, nil
}

func (s *Service) passkeyCall(req daemon.PasskeyRequest) (*daemon.Response, error) {
	pd, err := s.passkeyDaemon()
	if err != nil {
		return nil, err
	}
	resp, err := pd.Passkey(req)
	if err != nil {
		return nil, E(ErrValidation, "passkey "+req.Action+" failed: "+err.Error(), "")
	}
	if len(resp.Passkeys) == 0 && req.Action != daemon.PasskeyList {
		return nil, E(ErrInternal, "daemon returned no passkey session", "")
	}
	return resp, nil
}

// PasskeyArm adds an empty virtual authenticator to the tab so the agent can
// register a passkey on the site.
func (s *Service) PasskeyArm(t PasskeyTarget) (*passkey.Info, error) {
	resp, err := s.passkeyCall(t.request(daemon.PasskeyArm))
	if err != nil {
		return nil, err
	}
	return &resp.Passkeys[0], nil
}

// PasskeyCollect reads the credential registered on an armed session and
// returns the create write that stores it. The caller submits the write.
func (s *Service) PasskeyCollect(session, item, vault, category string) (*passkey.Info, ItemWrite, error) {
	if session == "" || item == "" || vault == "" {
		return nil, ItemWrite{}, E(ErrValidation, "session, item, and vault are required", "")
	}
	resp, err := s.passkeyCall(daemon.PasskeyRequest{Action: daemon.PasskeyCollect, Session: session, Item: item, Vault: vault})
	if err != nil {
		return nil, ItemWrite{}, err
	}
	if resp.Credential == nil {
		return nil, ItemWrite{}, E(ErrInternal, "daemon returned no credential", "")
	}
	c := resp.Credential
	fields := map[string]string{
		PasskeyFieldCredentialID: c.CredentialID,
		PasskeyFieldPrivateKey:   c.PrivateKey,
		PasskeyFieldRPID:         c.RPID,
		PasskeyFieldSignCount:    strconv.FormatUint(uint64(c.SignCount), 10),
	}
	if c.UserHandle != "" {
		fields[PasskeyFieldUserHandle] = c.UserHandle
	}
	return &resp.Passkeys[0], ItemWrite{Item: item, Operation: "create", Category: category, Fields: fields}, nil
}

// PasskeyLoad puts an approved, cached passkey item into the tab as a
// virtual authenticator. The key goes daemon → browser; nothing is returned.
func (s *Service) PasskeyLoad(item, vault string, t PasskeyTarget) (*passkey.Info, error) {
	values, err := s.CachedFields(item, vault)
	if err != nil {
		return nil, err
	}
	get := func(label string) string {
		_, value, _ := ResolveField(values, label)
		return value
	}
	cred := passkey.Credential{
		CredentialID: get(PasskeyFieldCredentialID),
		PrivateKey:   get(PasskeyFieldPrivateKey),
		RPID:         get(PasskeyFieldRPID),
		UserHandle:   get(PasskeyFieldUserHandle),
	}
	if cred.CredentialID == "" || cred.PrivateKey == "" || cred.RPID == "" {
		return nil, E(ErrNotFound, fmt.Sprintf("item %q has no approved passkey fields", item),
			fmt.Sprintf("run: secret-gate request submit --item %q --reason <why> (approve the whole item or the %q, %q, %q, %q, and %q fields)",
				item, PasskeyFieldCredentialID, PasskeyFieldPrivateKey, PasskeyFieldRPID, PasskeyFieldUserHandle, PasskeyFieldSignCount))
	}
	cred.IsResident = cred.UserHandle != ""
	if raw := get(PasskeyFieldSignCount); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return nil, E(ErrValidation, fmt.Sprintf("%q is not a number", PasskeyFieldSignCount), "")
		}
		cred.SignCount = uint32(n)
	}
	req := t.request(daemon.PasskeyLoad)
	req.Item, req.Vault, req.Credential = item, vault, &cred
	resp, err := s.passkeyCall(req)
	if err != nil {
		return nil, err
	}
	return &resp.Passkeys[0], nil
}

// PasskeyRelease removes the authenticator from the tab. When saveCounter is
// set it returns the update write that stores the final sign count.
func (s *Service) PasskeyRelease(session string, saveCounter bool) (*passkey.Info, *ItemWrite, error) {
	if session == "" {
		return nil, nil, E(ErrValidation, "session is required", "pass --session <id>")
	}
	resp, err := s.passkeyCall(daemon.PasskeyRequest{Action: daemon.PasskeyRelease, Session: session})
	if err != nil {
		return nil, nil, err
	}
	info := &resp.Passkeys[0]
	if !saveCounter {
		return info, nil, nil
	}
	if info.Item == "" || info.Vault == "" {
		return info, nil, E(ErrValidation, "the session has no item and vault to save the counter to",
			"register the passkey first, or load it with an explicit --vault")
	}
	return info, &ItemWrite{Item: info.Item, Operation: "update", Fields: map[string]string{
		PasskeyFieldSignCount: strconv.FormatUint(uint64(info.SignCount), 10),
	}}, nil
}

// PasskeyList returns the held authenticators.
func (s *Service) PasskeyList() ([]passkey.Info, error) {
	resp, err := s.passkeyCall(daemon.PasskeyRequest{Action: daemon.PasskeyList})
	if err != nil {
		return nil, err
	}
	return resp.Passkeys, nil
}
