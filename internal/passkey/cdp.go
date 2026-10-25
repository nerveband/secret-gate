// Package passkey holds agent-owned WebAuthn credentials in a browser through
// the Chrome DevTools Protocol WebAuthn domain. Secret Gate attaches its own
// DevTools session to the agent's tab and adds a virtual authenticator there,
// so the private key goes from Secret Gate to the browser and never through
// the agent. Virtual authenticators belong to the session that created them,
// so this package keeps the session open until the credential is released.
package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// cdpConn is a minimal DevTools Protocol client over one browser WebSocket.
type cdpConn struct {
	ws     *websocket.Conn
	nextID atomic.Int64

	mu      sync.Mutex
	pending map[int64]chan cdpReply
	closed  chan struct{}
	err     error
}

type cdpReply struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type cdpMessage struct {
	ID int64 `json:"id"`
	cdpReply
}

// ResolveEndpoint turns a DevTools address into a browser WebSocket URL. It
// accepts ws:// URLs, http:// base URLs (resolved through /json/version),
// host:port, or a bare port. Only loopback hosts are accepted, so key
// material is never sent to another machine.
func ResolveEndpoint(ctx context.Context, address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("a DevTools endpoint is required (for agent-browser: agent-browser get cdp-url)")
	}
	if !strings.Contains(address, "://") {
		if !strings.Contains(address, ":") {
			address = "127.0.0.1:" + address
		}
		address = "http://" + address
	}
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("invalid DevTools endpoint: %w", err)
	}
	if err := requireLoopback(u); err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws", "wss":
		return u.String(), nil
	case "http", "https":
	default:
		return "", fmt.Errorf("unsupported DevTools endpoint scheme %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(u.String(), "/")+"/json/version", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("reaching DevTools endpoint: %w", err)
	}
	defer resp.Body.Close()
	var version struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&version); err != nil || version.WebSocketDebuggerURL == "" {
		return "", errors.New("DevTools endpoint did not report a browser WebSocket URL")
	}
	ws, err := url.Parse(version.WebSocketDebuggerURL)
	if err != nil {
		return "", fmt.Errorf("invalid browser WebSocket URL: %w", err)
	}
	if err := requireLoopback(ws); err != nil {
		return "", err
	}
	return ws.String(), nil
}

func requireLoopback(u *url.URL) error {
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("DevTools endpoint %q is not on this machine; only loopback endpoints are allowed", host)
}

func dialCDP(ctx context.Context, wsURL string) (*cdpConn, error) {
	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to DevTools: %w", err)
	}
	ws.SetReadLimit(64 << 20)
	c := &cdpConn{ws: ws, pending: make(map[int64]chan cdpReply), closed: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *cdpConn) readLoop() {
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			c.mu.Lock()
			c.err = err
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.mu.Unlock()
			close(c.closed)
			return
		}
		var msg cdpMessage
		if json.Unmarshal(data, &msg) != nil || msg.ID == 0 {
			continue // events are not used
		}
		c.mu.Lock()
		ch := c.pending[msg.ID]
		delete(c.pending, msg.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- msg.cdpReply
		}
	}
}

// call sends one command and decodes its result into out (which may be nil).
// Error messages name the method only; params can carry key material.
func (c *cdpConn) call(ctx context.Context, sessionID, method string, params any, out any) error {
	id := c.nextID.Add(1)
	ch := make(chan cdpReply, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return fmt.Errorf("%s: DevTools connection closed", method)
	}
	c.pending[id] = ch
	c.mu.Unlock()
	msg := map[string]any{"id": id, "method": method, "params": params}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("%s: encoding command: %w", method, err)
	}
	if err := c.ws.Write(ctx, websocket.MessageText, data); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("%s: %w", method, err)
	}
	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("%s: %w", method, ctx.Err())
	case reply, ok := <-ch:
		if !ok {
			return fmt.Errorf("%s: DevTools connection closed", method)
		}
		if reply.Error != nil {
			return fmt.Errorf("%s: %s", method, reply.Error.Message)
		}
		if out != nil {
			if err := json.Unmarshal(reply.Result, out); err != nil {
				return fmt.Errorf("%s: decoding result: %w", method, err)
			}
		}
		return nil
	}
}

func (c *cdpConn) close() {
	_ = c.ws.Close(websocket.StatusNormalClosure, "")
}

// alive reports whether the browser connection is still open.
func (c *cdpConn) alive() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

// pageTarget is a browser tab as Target.getTargets reports it.
type pageTarget struct {
	TargetID string `json:"targetId"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	Title    string `json:"title"`
}

// pickTarget selects the tab by target ID, else by URL substring, else the
// only open tab.
func pickTarget(targets []pageTarget, targetID, pageURL string) (pageTarget, error) {
	var pages []pageTarget
	for _, t := range targets {
		if t.Type == "page" {
			pages = append(pages, t)
		}
	}
	for _, t := range pages {
		if targetID != "" && t.TargetID == targetID {
			return t, nil
		}
	}
	if targetID != "" {
		return pageTarget{}, fmt.Errorf("no open tab has target ID %q", targetID)
	}
	if pageURL != "" {
		for _, t := range pages {
			if strings.Contains(t.URL, pageURL) {
				return t, nil
			}
		}
		return pageTarget{}, fmt.Errorf("no open tab URL contains %q (%d tabs open)", pageURL, len(pages))
	}
	if len(pages) == 1 {
		return pages[0], nil
	}
	return pageTarget{}, fmt.Errorf("%d tabs are open; pass a page URL substring or target ID", len(pages))
}

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}
