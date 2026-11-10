package ownerwindow

import (
	"errors"
	"testing"
	"time"
)

// policy is the default: every item in the vault is eligible.
func policy(t testing.TB) Policy {
	if t != nil {
		t.Helper()
	}
	p, err := NewPolicy("", "")
	if err != nil {
		panic(err)
	}
	return p
}

func taggedPolicy(t *testing.T) Policy {
	t.Helper()
	p, err := NewPolicy("sg-window", "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func item(title string) Item {
	return Item{Vault: "AI Agents", Title: title, Category: "API_CREDENTIAL", Fields: []string{"credential"}, FieldLabels: []string{"credential", "username"}}
}

func TestPolicyCoversEveryItemInTheVaultExceptWhatCouldEscalate(t *testing.T) {
	p := policy(t)
	vaults := []string{"AI Agents"}
	cases := []struct {
		name   string
		mutate func(*Item)
		want   string // empty means covered
	}{
		{"ordinary item", func(*Item) {}, ""},
		{"untagged item", func(i *Item) { i.Tags = nil }, ""},
		{"another vault", func(i *Item) { i.Vault = "Personal" }, ReasonVault},
		{"vault name compares without case", func(i *Item) { i.Vault = "ai agents" }, ""},
		{"gate credential", func(i *Item) { i.Title = "Secret Gate Approver Token" }, ReasonControlPlane},
		{"gate credential, other spelling", func(i *Item) { i.Title = "secret-gate service account token" }, ReasonControlPlane},
		{"push service key", func(i *Item) { i.Title = "PushWard Integration Key" }, ReasonControlPlane},
		{"release credentials that merely mention a service", func(i *Item) { i.Title = "App Store Connect API key" }, ""},
		{"service account of another project", func(i *Item) { i.Title = "Release service account" }, ""},
		{"unrelated telegram item", func(i *Item) { i.Title = "Shared Telegram app id" }, ""},
		{"card", func(i *Item) { i.Category = "CREDIT_CARD" }, ReasonCategory},
		{"bank account", func(i *Item) { i.Category = "BANK_ACCOUNT" }, ReasonCategory},
		{"attachment", func(i *Item) { i.Attachments = true }, ReasonAttachment},
		{"explicit passkey field", func(i *Item) { i.Fields = []string{"Passkey Private Key"} }, ReasonPasskey},
		{"all fields on an item that holds a passkey", func(i *Item) {
			i.Fields = nil
			i.FieldLabels = []string{"username", "passkey private key"}
		}, ReasonPasskey},
	}
	for _, c := range cases {
		it := item("Deploy key")
		c.mutate(&it)
		ok, reason := p.Check(it, vaults)
		if (c.want == "") != ok || reason != c.want {
			t.Errorf("%s: ok=%v reason=%q, want %q", c.name, ok, reason, c.want)
		}
	}
}

func TestAnOptionalTagNarrowsTheWindow(t *testing.T) {
	p := taggedPolicy(t)
	vaults := []string{"AI Agents"}
	tagged := item("Deploy key")
	tagged.Tags = []string{"SG-Window"} // tags compare without case
	if ok, _ := p.Check(tagged, vaults); !ok {
		t.Fatal("a tagged item should be covered")
	}
	other := item("Deploy key")
	other.Tags = []string{"other"}
	if ok, reason := p.Check(other, vaults); ok || reason != ReasonUntagged {
		t.Fatalf("untagged item with a tag configured: ok=%v reason=%q", ok, reason)
	}
	gate := item("Secret Gate Approver Token")
	gate.Tags = []string{"sg-window"}
	if ok, reason := p.Check(gate, vaults); ok || reason != ReasonControlPlane {
		t.Fatalf("a tag must not unlock a gate credential: ok=%v reason=%q", ok, reason)
	}
}

func TestExtraDenyPatternAddsToTheBuiltInOne(t *testing.T) {
	p, err := NewPolicy("", "payroll")
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := p.Check(item("Payroll login"), []string{"AI Agents"}); ok || reason != ReasonControlPlane {
		t.Fatalf("custom deny not applied: %v %q", ok, reason)
	}
	if ok, _ := p.Check(item("Secret Gate token"), []string{"AI Agents"}); ok {
		t.Fatal("the built-in deny rule must stay when a custom one is added")
	}
}

func TestLegacyCheckKeepsGateCredentialsPasskeysAndFilesOut(t *testing.T) {
	p := taggedPolicy(t)
	untagged := item("Wifi")
	untagged.Tags = nil
	if ok, _ := p.CheckLegacy(untagged); !ok {
		t.Fatal("the older window does not need tags")
	}
	gate := item("Secret Gate Approver Token")
	gate.Tags = nil
	if ok, reason := p.CheckLegacy(gate); ok || reason != ReasonControlPlane {
		t.Fatalf("gate credential reachable through the older window: %v %q", ok, reason)
	}
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestStore() (*Store, *clock) {
	c := &clock{now: time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)}
	return newStore(c.Now), c
}

var limits = Limits{Ceiling: 2 * time.Hour, OpensPerHour: 6, DailyMax: 4 * time.Hour}

func open(t *testing.T, s *Store, ttl time.Duration) Window {
	t.Helper()
	w, err := s.Open(OpenParams{Vault: "AI Agents", Tag: "sg-window", Source: "test", Opener: "owner", TTL: ttl, MaxRequests: 3, MaxItems: 2}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func take(s *Store, titles ...string) TakeResult {
	var items []Item
	for _, title := range titles {
		items = append(items, item(title))
	}
	return s.Take(TakeRequest{Items: items, Policy: policy(nil)})
}

func TestCoveredReadsCountAndFirstUseIsReportedOnce(t *testing.T) {
	s, _ := newTestStore()
	open(t, s, 30*time.Minute)
	first := take(s, "A")
	if !first.Covered || len(first.NewItems) != 1 {
		t.Fatalf("first read = %+v", first)
	}
	again := take(s, "A")
	if !again.Covered || len(again.NewItems) != 0 || again.Window.Requests != 2 {
		t.Fatalf("second read of the same item = %+v", again)
	}
}

func TestBudgetIsEnforcedAndTheWindowClosesWhenExceeded(t *testing.T) {
	s, _ := newTestStore()
	w := open(t, s, 30*time.Minute)
	take(s, "A")
	take(s, "B")
	over := take(s, "C") // third distinct item, budget is two
	if over.Covered || over.Reason != ReasonBudgetItems || over.Closed == nil {
		t.Fatalf("item budget not enforced: %+v", over)
	}
	if !s.ClosedEarly(w.ID) {
		t.Fatal("a window closed by its budget must count as closed early")
	}
	if got := take(s, "A"); got.Covered {
		t.Fatal("a closed window still covers reads")
	}

	s2, _ := newTestStore()
	open(t, s2, 30*time.Minute)
	take(s2, "A")
	take(s2, "A")
	take(s2, "A")
	if res := take(s2, "A"); res.Covered || res.Reason != ReasonBudgetRequests || res.Closed == nil {
		t.Fatalf("request budget not enforced: %+v", res)
	}
}

func TestReleaseGivesBackWhatARefusedAuditUsed(t *testing.T) {
	s, _ := newTestStore()
	open(t, s, 30*time.Minute)
	res := take(s, "A")
	s.Release(res)
	again := take(s, "A")
	if len(again.NewItems) != 1 || again.Window.Requests != 1 {
		t.Fatalf("after release the item must count as new again: %+v", again)
	}
}

func TestUncoveredItemDoesNotConsumeBudget(t *testing.T) {
	s, _ := newTestStore()
	open(t, s, 30*time.Minute)
	res := s.Take(TakeRequest{Items: []Item{item("Secret Gate Approver Token")}, Policy: policy(nil)})
	if res.Covered || res.Reason != ReasonControlPlane || res.Window.Requests != 0 {
		t.Fatalf("gate credential read = %+v", res)
	}
}

func TestWindowEndsOnItsOwnAndNeverExtends(t *testing.T) {
	s, c := newTestStore()
	w := open(t, s, 30*time.Minute)
	if _, err := s.Open(OpenParams{Vault: "ai agents", Tag: "sg-window", TTL: time.Hour}, limits); !errors.Is(err, ErrAlreadyOpen) {
		t.Fatalf("second open = %v, want ErrAlreadyOpen", err)
	}
	if got, _ := s.Get(w.ID); !got.ExpiresAt.Equal(w.ExpiresAt) {
		t.Fatal("re-opening must not extend the window")
	}
	c.Advance(31 * time.Minute)
	if got := take(s, "A"); got.Covered {
		t.Fatal("expired window covered a read")
	}
	if expired := s.Expire(); len(expired) != 1 || expired[0].CloseReason != ReasonExpired {
		t.Fatalf("a window that ran out of time must be reported once for its closing message, got %+v", expired)
	}
	if again := s.Expire(); len(again) != 0 {
		t.Fatalf("expiry reported twice: %+v", again)
	}
	if s.ClosedEarly(w.ID) {
		t.Fatal("running out of time is not an early close")
	}
}

func TestRevokeClosesTheWindowAndReportsEarlyClose(t *testing.T) {
	s, _ := newTestStore()
	w := open(t, s, 30*time.Minute)
	if _, ok := s.Revoke(w.ID, ReasonRevoked); !ok {
		t.Fatal("revoke failed")
	}
	if take(s, "A").Covered || !s.ClosedEarly(w.ID) {
		t.Fatal("revoked window still open")
	}
	if _, ok := s.Revoke(w.ID, ReasonRevoked); ok {
		t.Fatal("revoking twice should report not open")
	}
}

func TestOpenLimits(t *testing.T) {
	s, c := newTestStore()
	if _, err := s.Open(OpenParams{Vault: "V", TTL: 3 * time.Hour}, limits); !errors.Is(err, ErrBadLength) {
		t.Fatalf("over the ceiling = %v", err)
	}
	tight := Limits{Ceiling: 2 * time.Hour, OpensPerHour: 2, DailyMax: 50 * time.Minute}
	for i, v := range []string{"A", "B"} {
		if _, err := s.Open(OpenParams{Vault: v, TTL: 10 * time.Minute}, tight); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	if _, err := s.Open(OpenParams{Vault: "C", TTL: 10 * time.Minute}, tight); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third open in an hour = %v", err)
	}
	c.Advance(61 * time.Minute)
	if _, err := s.Open(OpenParams{Vault: "C", TTL: 45 * time.Minute}, tight); !errors.Is(err, ErrDailyCap) {
		t.Fatalf("daily cap = %v", err)
	}
}

func TestPinsNarrowAWindowToOneRequester(t *testing.T) {
	s, _ := newTestStore()
	if _, err := s.Open(OpenParams{Vault: "AI Agents", Tag: "sg-window", TTL: 30 * time.Minute, Machine: "box-1", AgentID: "agent-1", MaxRequests: 5, MaxItems: 5}, limits); err != nil {
		t.Fatal(err)
	}
	other := s.Take(TakeRequest{Items: []Item{item("A")}, Machine: "box-2", AgentID: "agent-1", Policy: policy(nil)})
	if other.Covered || other.Reason != ReasonPin {
		t.Fatalf("other machine = %+v", other)
	}
	mine := s.Take(TakeRequest{Items: []Item{item("A")}, Machine: "BOX-1", AgentID: "agent-1", Policy: policy(nil)})
	if !mine.Covered {
		t.Fatalf("pinned requester = %+v", mine)
	}
}

func TestDueCountersReturnsAChangedWindowOncePerInterval(t *testing.T) {
	s, c := newTestStore()
	open(t, s, 30*time.Minute)
	take(s, "A")
	if got := s.DueCounters(10 * time.Second); len(got) != 1 {
		t.Fatalf("first due = %d", len(got))
	}
	take(s, "A")
	if got := s.DueCounters(10 * time.Second); len(got) != 0 {
		t.Fatal("counters edited again inside the interval")
	}
	c.Advance(11 * time.Second)
	if got := s.DueCounters(10 * time.Second); len(got) != 1 {
		t.Fatal("changed counters not returned after the interval")
	}
}
