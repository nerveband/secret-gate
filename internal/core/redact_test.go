package core

import "testing"

func TestRedactExactMatch(t *testing.T) {
	r := NewRedactor()
	r.Add("fake-api-key-123456", "prod-api/credential")

	in := "token=fake-api-key-123456 sent\nfake-api-key-123456"
	want := "token=[REDACTED:prod-api/credential] sent\n[REDACTED:prod-api/credential]"
	if got := r.Redact(in); got != want {
		t.Fatalf("Redact() = %q, want %q", got, want)
	}
}

func TestRedactLongestValueFirst(t *testing.T) {
	r := NewRedactor()
	r.Add("secret", "a/short")
	r.Add("secret-extended", "a/long")

	if got := r.Redact("x secret-extended y"); got != "x [REDACTED:a/long] y" {
		t.Fatalf("Redact() = %q, want long label", got)
	}
	if got := r.Redact("x secret y"); got != "x [REDACTED:a/short] y" {
		t.Fatalf("Redact() = %q, want short label", got)
	}
}

func TestRedactSkipsTrivialValues(t *testing.T) {
	r := NewRedactor()
	r.Add("1", "item/count") // too short — would shred unrelated output
	if got := r.Redact("exit code 1"); got != "exit code 1" {
		t.Fatalf("Redact() = %q, want unchanged", got)
	}
}

func TestRedactMultilineValue(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakefake\n-----END OPENSSH PRIVATE KEY-----"
	r := NewRedactor()
	r.Add(key, "deploy-key/private key")
	if got := r.Redact("dump:\n" + key + "\ndone"); got != "dump:\n[REDACTED:deploy-key/private key]\ndone" {
		t.Fatalf("Redact() = %q", got)
	}
}

func TestRedactNoEntriesPassthrough(t *testing.T) {
	if got := NewRedactor().Redact("hello"); got != "hello" {
		t.Fatalf("Redact() = %q, want hello", got)
	}
}
