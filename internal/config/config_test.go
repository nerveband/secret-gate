package config

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func valid() *Config {
	return &Config{OPConnectHost: "http://connect", OPConnectToken: "t", TelegramBotToken: "bot", TelegramChatID: 42}
}

func TestApproverIsThePrivateChatUnlessSetExplicitly(t *testing.T) {
	c := valid()
	if c.ApproverUserID() != 42 {
		t.Fatalf("private chat approver = %d", c.ApproverUserID())
	}
	c.TelegramChatID = -1001
	if c.ApproverUserID() != 0 {
		t.Fatal("a group chat must not name an approver by itself")
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "TELEGRAM_APPROVER_USER_ID") {
		t.Fatalf("group chat without an approver should be refused, got %v", err)
	}
	c.TelegramApproverUserID = 7
	if err := c.Validate(); err != nil || c.ApproverUserID() != 7 {
		t.Fatalf("group chat with an approver: %v, %d", err, c.ApproverUserID())
	}
}

func TestValidateRejectsBadSettings(t *testing.T) {
	cases := map[string]func(*Config){
		"alert mode":       func(c *Config) { c.TelegramNotifications = "loud" },
		"opener digest":    func(c *Config) { c.OpenerTokenSHA256 = "abc" },
		"approver digest":  func(c *Config) { c.ApproverTokenSHA256 = strings.Repeat("z", 64) },
		"deny pattern":     func(c *Config) { c.OwnerWindowDeny = "(" },
		"window over ceil": func(c *Config) { c.OwnerWindowMax = 3 * OwnerWindowCeiling },
		"windows no channel": func(c *Config) {
			c.OwnerWindowVaults = []string{"V"}
			c.TelegramBotToken = ""
			c.TelegramChatID = 0
			c.ApproverToken = "x"
		},
	}
	for name, mutate := range cases {
		c := valid()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

func TestTokenMatchesPlainOrDigestAndNeverEmpty(t *testing.T) {
	sum := sha256.Sum256([]byte("opener-secret"))
	digest := hex.EncodeToString(sum[:])
	if !TokenMatches("opener-secret", "", digest) {
		t.Fatal("digest match failed")
	}
	if !TokenMatches(" plain ", "plain", "") {
		t.Fatal("plain match failed")
	}
	for _, c := range []struct{ token, plain, digest string }{
		{"wrong", "", digest}, {"", "", digest}, {"", "", ""}, {"x", "", ""},
	} {
		if TokenMatches(c.token, c.plain, c.digest) {
			t.Errorf("TokenMatches(%q, %q, %q) should be false", c.token, c.plain, c.digest)
		}
	}
}
