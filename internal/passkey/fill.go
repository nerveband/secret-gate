package passkey

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// This file reuses the package's DevTools client to type approved values
// into form fields (browser fill). Values go from Secret Gate to the page
// over a loopback DevTools session and never through the agent.

// FillStep types one value into the element matching Selector.
type FillStep struct {
	Field    string // item field, for the result only
	Selector string // CSS selector; searched in the document, same-origin frames, and open shadow roots
	Value    string
}

// FillResult reports one step without its value.
type FillResult struct {
	Field    string `json:"field"`
	Selector string `json:"selector"`
	Filled   bool   `json:"filled"`
	Element  string `json:"element,omitempty"` // tag name, e.g. INPUT or SELECT
	Error    string `json:"error,omitempty"`
}

// FillTarget picks the tab, and optionally a cross-origin frame in it.
type FillTarget struct {
	Target
	FrameURL     string // substring of an out-of-process iframe URL (payment iframes)
	RequireHTTPS bool   // refuse pages that are not https (loopback excepted)
}

// FillPage is the page or frame that was filled.
type FillPage struct {
	TargetID string `json:"target_id"`
	URL      string `json:"url"`
}

const findElementJS = `(function(sel){
  function find(root){
    var el = root.querySelector(sel);
    if (el) return el;
    var all = root.querySelectorAll('*');
    for (var i = 0; i < all.length; i++) {
      var n = all[i];
      if (n.shadowRoot) { var s = find(n.shadowRoot); if (s) return s; }
      if (n.tagName === 'IFRAME' || n.tagName === 'FRAME') {
        try { var d = n.contentDocument; if (d) { var f = find(d); if (f) return f; } } catch (e) {}
      }
    }
    return null;
  }
  return find(document);
})(%s)`

const prepareElementJS = `function(){
  this.scrollIntoView({block: 'center'});
  this.focus();
  if (this.tagName !== 'SELECT' && typeof this.select === 'function') { this.select(); }
  return this.tagName;
}`

// selectOptionJS picks the option whose value or text matches, ignoring
// case and leading zeros, so "08", "8", and "August" style menus work.
const selectOptionJS = `function(v){
  var want = String(v).trim().toLowerCase();
  var strip = function(s){ return String(s).trim().toLowerCase().replace(/^0+(?=\d)/, ''); };
  for (var i = 0; i < this.options.length; i++) {
    var o = this.options[i];
    if (o.value.toLowerCase() === want || o.text.trim().toLowerCase() === want || strip(o.value) === strip(want) || strip(o.text) === strip(want)) {
      this.selectedIndex = i;
      this.dispatchEvent(new Event('input', {bubbles: true}));
      this.dispatchEvent(new Event('change', {bubbles: true}));
      return true;
    }
  }
  return false;
}`

const finishElementJS = `function(){
  this.dispatchEvent(new Event('change', {bubbles: true}));
  if (typeof this.blur === 'function') { this.blur(); }
  return this.tagName === 'SELECT' ? this.selectedIndex >= 0 : String(this.value || this.textContent || '').length > 0;
}`

type remoteObject struct {
	Type     string          `json:"type"`
	Subtype  string          `json:"subtype"`
	ObjectID string          `json:"objectId"`
	Value    json.RawMessage `json:"value"`
}

type evalReply struct {
	Result           remoteObject `json:"result"`
	ExceptionDetails *struct {
		Text string `json:"text"`
	} `json:"exceptionDetails"`
}

// Fill types each step's value into the tab (or frame). Error messages name
// selectors and DevTools methods, never values.
func Fill(ctx context.Context, t FillTarget, steps []FillStep) (FillPage, []FillResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	wsURL, err := ResolveEndpoint(ctx, t.Endpoint)
	if err != nil {
		return FillPage{}, nil, err
	}
	conn, err := dialCDP(ctx, wsURL)
	if err != nil {
		return FillPage{}, nil, err
	}
	defer conn.close()
	var targets struct {
		TargetInfos []pageTarget `json:"targetInfos"`
	}
	if err := conn.call(ctx, "", "Target.getTargets", map[string]any{}, &targets); err != nil {
		return FillPage{}, nil, err
	}
	page, err := pickTarget(targets.TargetInfos, t.TargetID, t.PageURL)
	if err != nil {
		return FillPage{}, nil, err
	}
	chosen := page
	if t.FrameURL != "" {
		found := false
		for _, ti := range targets.TargetInfos {
			if ti.Type == "iframe" && strings.Contains(ti.URL, t.FrameURL) {
				chosen, found = ti, true
				break
			}
		}
		if !found {
			return FillPage{}, nil, fmt.Errorf("no cross-origin frame URL contains %q; same-origin frames are searched without --frame-url", t.FrameURL)
		}
	}
	if t.RequireHTTPS {
		if err := requireSecurePage(chosen.URL); err != nil {
			return FillPage{}, nil, err
		}
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := conn.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": chosen.TargetID, "flatten": true}, &attached); err != nil {
		return FillPage{}, nil, err
	}
	sid := attached.SessionID
	defer func() {
		_ = conn.call(context.Background(), sid, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": false}, nil)
		_ = conn.call(context.Background(), "", "Target.detachFromTarget", map[string]any{"sessionId": sid}, nil)
	}()
	// Background agent tabs are not focused; focus events need emulation.
	if err := conn.call(ctx, sid, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true}, nil); err != nil {
		return FillPage{}, nil, err
	}
	results := make([]FillResult, 0, len(steps))
	for _, step := range steps {
		res := FillResult{Field: step.Field, Selector: step.Selector}
		res.Element, res.Filled, err = fillOne(ctx, conn, sid, step)
		if err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	return FillPage{TargetID: chosen.TargetID, URL: chosen.URL}, results, nil
}

func requireSecurePage(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("cannot read the page URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing to fill card values into a page that is not https (%s)", u.Scheme)
}

func fillOne(ctx context.Context, conn *cdpConn, sid string, step FillStep) (string, bool, error) {
	sel, _ := json.Marshal(step.Selector)
	var found evalReply
	if err := conn.call(ctx, sid, "Runtime.evaluate", map[string]any{"expression": fmt.Sprintf(findElementJS, sel)}, &found); err != nil {
		return "", false, err
	}
	if found.ExceptionDetails != nil {
		return "", false, fmt.Errorf("selector is not valid CSS")
	}
	if found.Result.ObjectID == "" || found.Result.Subtype == "null" {
		return "", false, fmt.Errorf("no element matches the selector")
	}
	obj := found.Result.ObjectID
	defer func() {
		_ = conn.call(context.Background(), sid, "Runtime.releaseObject", map[string]any{"objectId": obj}, nil)
	}()
	var tag struct {
		Result remoteObject `json:"result"`
	}
	if err := conn.call(ctx, sid, "Runtime.callFunctionOn", map[string]any{"objectId": obj, "functionDeclaration": prepareElementJS, "returnByValue": true}, &tag); err != nil {
		return "", false, err
	}
	var tagName string
	_ = json.Unmarshal(tag.Result.Value, &tagName)
	if tagName == "SELECT" {
		var picked struct {
			Result remoteObject `json:"result"`
		}
		if err := conn.call(ctx, sid, "Runtime.callFunctionOn", map[string]any{
			"objectId": obj, "functionDeclaration": selectOptionJS, "returnByValue": true,
			"arguments": []map[string]any{{"value": step.Value}},
		}, &picked); err != nil {
			return tagName, false, err
		}
		var ok bool
		_ = json.Unmarshal(picked.Result.Value, &ok)
		if !ok {
			return tagName, false, fmt.Errorf("no option of the menu matches the value")
		}
		return tagName, true, nil
	}
	if err := conn.call(ctx, sid, "Input.insertText", map[string]any{"text": step.Value}, nil); err != nil {
		return tagName, false, err
	}
	var done struct {
		Result remoteObject `json:"result"`
	}
	if err := conn.call(ctx, sid, "Runtime.callFunctionOn", map[string]any{"objectId": obj, "functionDeclaration": finishElementJS, "returnByValue": true}, &done); err != nil {
		return tagName, false, err
	}
	var filled bool
	_ = json.Unmarshal(done.Result.Value, &filled)
	return tagName, filled, nil
}
