package passkey

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeBrowser speaks the slice of DevTools that Manager uses.
type fakeBrowser struct {
	mu       sync.Mutex
	pages    []pageTarget
	creds    []Credential
	calls    []string
	attached string
}

func (f *fakeBrowser) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeBrowser) handle(method string, params json.RawMessage) (any, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	switch method {
	case "Target.getTargets":
		return map[string]any{"targetInfos": f.pages}, ""
	case "Target.attachToTarget":
		var p struct {
			TargetID string `json:"targetId"`
		}
		_ = json.Unmarshal(params, &p)
		f.attached = p.TargetID
		return map[string]any{"sessionId": "S1"}, ""
	case "WebAuthn.addVirtualAuthenticator":
		return map[string]any{"authenticatorId": "A1"}, ""
	case "WebAuthn.addCredential":
		var p struct {
			Credential Credential `json:"credential"`
		}
		_ = json.Unmarshal(params, &p)
		f.creds = append(f.creds, p.Credential)
		return map[string]any{}, ""
	case "WebAuthn.getCredentials":
		return map[string]any{"credentials": f.creds}, ""
	}
	return map[string]any{}, ""
}

func newFakeBrowser(t *testing.T, pages ...pageTarget) (*fakeBrowser, string) {
	t.Helper()
	fb := &fakeBrowser{pages: pages}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/version" {
			_ = json.NewEncoder(w).Encode(map[string]string{"webSocketDebuggerUrl": "ws" + strings.TrimPrefix(srv.URL, "http") + "/devtools/browser/x"})
			return
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		ctx := context.Background()
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var msg struct {
				ID     int64           `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			_ = json.Unmarshal(data, &msg)
			result, _ := fb.handle(msg.Method, msg.Params)
			reply, _ := json.Marshal(map[string]any{"id": msg.ID, "result": result})
			_ = ws.Write(ctx, websocket.MessageText, reply)
		}
	}))
	t.Cleanup(srv.Close)
	return fb, srv.URL
}

func TestLoadUsesSignCountFloorAndReleaseRemovesAuthenticator(t *testing.T) {
	fb, endpoint := newFakeBrowser(t,
		pageTarget{TargetID: "T1", Type: "page", URL: "https://example.com/"},
		pageTarget{TargetID: "T2", Type: "page", URL: "https://webauthn.io/"})
	m := NewManager()
	now := time.Unix(1_800_000_000, 0)
	m.now = func() time.Time { return now }
	info, err := m.Load(context.Background(), Target{Endpoint: endpoint, PageURL: "webauthn.io"},
		Credential{CredentialID: "Y3JlZA==", PrivateKey: "a2V5", RPID: "webauthn.io", UserHandle: "dXNlcg==", IsResident: true, SignCount: 7}, "item", "vault")
	if err != nil {
		t.Fatal(err)
	}
	if fb.attached != "T2" || info.TargetID != "T2" {
		t.Fatalf("attached to %q, want the webauthn.io tab", fb.attached)
	}
	if len(fb.creds) != 1 || fb.creds[0].SignCount != 1_800_000_000 || fb.creds[0].PrivateKey != "a2V5" {
		t.Fatalf("credential added = %#v", fb.creds)
	}
	if raw, _ := json.Marshal(info); strings.Contains(string(raw), "a2V5") {
		t.Fatalf("session info carries the private key: %s", raw)
	}
	if !m.Active() {
		t.Fatal("loaded session not active")
	}
	released, err := m.Release(context.Background(), info.Session)
	if err != nil {
		t.Fatal(err)
	}
	if released.SignCount != 1_800_000_000 || m.Active() {
		t.Fatalf("released = %#v active=%v", released, m.Active())
	}
	if calls := strings.Join(fb.log(), ","); !strings.Contains(calls, "WebAuthn.removeVirtualAuthenticator") {
		t.Fatalf("authenticator not removed: %s", calls)
	}
	if _, err := m.Release(context.Background(), info.Session); err == nil {
		t.Fatal("second release of the same session succeeded")
	}
}

func TestCollectReturnsTheRegisteredCredential(t *testing.T) {
	fb, endpoint := newFakeBrowser(t, pageTarget{TargetID: "T1", Type: "page", URL: "https://webauthn.io/"})
	m := NewManager()
	armed, err := m.Arm(context.Background(), Target{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Collect(context.Background(), armed.Session, "item", "vault"); err == nil {
		t.Fatal("collect before the site registered a passkey succeeded")
	}
	fb.mu.Lock()
	fb.creds = []Credential{{CredentialID: "aWQ=", PrivateKey: "c2VjcmV0", RPID: "webauthn.io", SignCount: 1}}
	fb.mu.Unlock()
	cred, info, err := m.Collect(context.Background(), armed.Session, "item", "vault")
	if err != nil {
		t.Fatal(err)
	}
	if cred.PrivateKey != "c2VjcmV0" || info.RPID != "webauthn.io" || info.Item != "item" {
		t.Fatalf("cred=%#v info=%#v", cred, info)
	}
	_, _ = m.Release(context.Background(), armed.Session)
}

func TestHoldExpiryReleasesTheAuthenticator(t *testing.T) {
	fb, endpoint := newFakeBrowser(t, pageTarget{TargetID: "T1", Type: "page", URL: "https://webauthn.io/"})
	m := NewManager()
	if _, err := m.Arm(context.Background(), Target{Endpoint: endpoint, Hold: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for m.Active() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if m.Active() || !strings.Contains(strings.Join(fb.log(), ","), "WebAuthn.removeVirtualAuthenticator") {
		t.Fatalf("expired session still held: active=%v calls=%v", m.Active(), fb.log())
	}
	if _, err := m.Arm(context.Background(), Target{Endpoint: endpoint, Hold: MaxHold + time.Minute}); err == nil {
		t.Fatal("hold above the maximum was accepted")
	}
}

func TestEndpointMustBeOnThisMachine(t *testing.T) {
	for _, endpoint := range []string{"ws://10.0.0.5:9222/devtools/browser/x", "http://example.com:9222", "wss://192.168.1.2:443/x"} {
		if _, err := ResolveEndpoint(context.Background(), endpoint); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("%s: err = %v", endpoint, err)
		}
	}
	got, err := ResolveEndpoint(context.Background(), "ws://127.0.0.1:9222/devtools/browser/x")
	if err != nil || got != "ws://127.0.0.1:9222/devtools/browser/x" {
		t.Fatalf("loopback ws URL: %q %v", got, err)
	}
}

func TestPickTarget(t *testing.T) {
	pages := []pageTarget{
		{TargetID: "W", Type: "service_worker", URL: "https://webauthn.io/sw.js"},
		{TargetID: "A", Type: "page", URL: "https://a.example/"},
		{TargetID: "B", Type: "page", URL: "https://webauthn.io/"},
	}
	if got, err := pickTarget(pages, "", "webauthn.io"); err != nil || got.TargetID != "B" {
		t.Fatalf("by URL: %v %v", got, err)
	}
	if got, err := pickTarget(pages, "A", ""); err != nil || got.TargetID != "A" {
		t.Fatalf("by ID: %v %v", got, err)
	}
	if _, err := pickTarget(pages, "", ""); err == nil {
		t.Fatal("two open tabs without a selector should be ambiguous")
	}
	if got, err := pickTarget(pages[:2], "", ""); err != nil || got.TargetID != "A" {
		t.Fatalf("single tab: %v %v", got, err)
	}
}
