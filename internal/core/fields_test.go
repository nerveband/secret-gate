package core

import (
	"reflect"
	"strings"
	"testing"

	"github.com/nerveband/secret-gate/internal/models"
)

func TestResolveFieldAliases(t *testing.T) {
	values := map[string]string{
		"One-Time Password": "seed",
		"notesPlain":        "the note",
		"API Key":           "fake-api-key-123456",
	}
	tests := []struct {
		wanted, actual, value string
		ok                    bool
	}{
		{"otp", "One-Time Password", "seed", true},
		{"MFA", "One-Time Password", "seed", true},
		{"2fa", "One-Time Password", "seed", true},
		{"note", "notesPlain", "the note", true},
		{"secure note", "notesPlain", "the note", true},
		{"api_key", "API Key", "fake-api-key-123456", true},
		{"missing", "", "", false},
	}
	for _, tt := range tests {
		actual, value, ok := ResolveField(values, tt.wanted)
		if actual != tt.actual || value != tt.value || ok != tt.ok {
			t.Errorf("ResolveField(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tt.wanted, actual, value, ok, tt.actual, tt.value, tt.ok)
		}
	}
}

// The "Example Co @ Accounting" shape: a login's real password field plus a
// saved web-form "Password" field that is empty. Every spelling of
// "password" must reach the real one, with or without server metadata.
func TestResolveFieldDuplicatePasswordFields(t *testing.T) {
	withMeta := map[string]string{
		"password":          "real-login-pw",
		"Password":          "",
		"username":          "admin@example.com",
		models.FieldMetaKey: `{"password":{"id":"password","type":"CONCEALED","purpose":"PASSWORD"},"Password":{"type":"STRING"},"username":{"id":"username","type":"STRING","purpose":"USERNAME"}}`,
	}
	withoutMeta := map[string]string{"password": "real-login-pw", "Password": ""}
	for name, values := range map[string]map[string]string{"with meta": withMeta, "without meta": withoutMeta} {
		for _, wanted := range []string{"password", "Password", "PASSWORD", " pass_word "} {
			for range 20 { // map order must not matter
				actual, value, ok := ResolveField(values, wanted)
				if !ok || actual != "password" || value != "real-login-pw" {
					t.Fatalf("%s: ResolveField(%q) = (%q, len %d, %v), want the login password", name, wanted, actual, len(value), ok)
				}
			}
		}
	}
	// Two non-empty password-like fields: an exact name reaches either one,
	// any other spelling gets the PASSWORD-purpose field, and each names the
	// other as an alternative so a failed login can retry with it.
	values := map[string]string{
		"password":          "real-login-pw",
		"Password":          "stale-form-value",
		models.FieldMetaKey: `{"password":{"id":"password","label":"password","selector":"password","type":"CONCEALED","purpose":"PASSWORD"},"Password":{"label":"Password","selector":"Password","type":"STRING"}}`,
	}
	for wanted, want := range map[string]string{"password": "password", "Password": "Password", "PASSWORD": "password", "pass word": "password"} {
		actual, _, ok := ResolveField(values, wanted)
		if !ok || actual != want {
			t.Fatalf("ResolveField(%q) = %q (%v), want %q", wanted, actual, ok, want)
		}
		other := map[string]string{"password": "Password", "Password": "password"}[want]
		if alts := FieldAlternatives(values, wanted, actual); !reflect.DeepEqual(alts, []string{other}) {
			t.Fatalf("FieldAlternatives(%q) = %v, want [%s]", wanted, alts, other)
		}
	}
	// An empty duplicate is never an alternative.
	if alts := FieldAlternatives(withMeta, "password", "password"); len(alts) != 0 {
		t.Fatalf("alternatives = %v, want none for an empty web-form field", alts)
	}
	// Without a purpose, a CONCEALED field beats a plain one.
	values = map[string]string{
		"pass word":         "concealed",
		"Password":          "stale-form-value",
		models.FieldMetaKey: `{"pass word":{"id":"pw-id","type":"CONCEALED"},"Password":{"type":"STRING"}}`,
	}
	if actual, _, ok := ResolveField(values, "password"); !ok || actual != "pass word" {
		t.Fatalf("password resolved to %q (%v), want the CONCEALED field", actual, ok)
	}
}

// After the server releases only the login password, the cache knows the
// other candidates by name. Asking for one of them must not return the
// cached login password; it must be requested, then it resolves.
func TestResolveFieldServerAlternativesNeedTheirOwnApproval(t *testing.T) {
	cached := map[string]string{
		"password":          "real-login-pw",
		models.FieldMetaKey: `{"password":{"id":"password","selector":"password","type":"CONCEALED","purpose":"PASSWORD","alternatives":["Password","password#1"]}}`,
	}
	if alts := FieldAlternatives(cached, "password", "password"); !reflect.DeepEqual(alts, []string{"Password", "password#1"}) {
		t.Fatalf("alternatives = %v", alts)
	}
	for _, wanted := range []string{"Password", "password#1"} {
		if actual, _, ok := ResolveField(cached, wanted); ok {
			t.Fatalf("ResolveField(%q) returned cached %q instead of asking for the alternative", wanted, actual)
		}
	}
	if _, value, ok := ResolveField(cached, "PASSWORD"); !ok || value != "real-login-pw" {
		t.Fatalf("PASSWORD did not resolve to the cached login password")
	}
	cached["Password"] = "form-value"
	if _, value, ok := ResolveField(cached, "Password"); !ok || value != "form-value" {
		t.Fatalf("approved alternative did not resolve: len %d, %v", len(value), ok)
	}
}

func TestResolveFieldCaseDuplicatesNeedAQualifiedName(t *testing.T) {
	values := map[string]string{
		"Email":               "a@example.com",
		"email":               "b@example.com",
		"Work.e-mail":         "c@example.com",
		"field-id-7":          "b@example.com",
		models.ProcessOnlyKey: "",
		models.FieldMetaKey:   `{"Email":{"type":"STRING"},"email":{"id":"field-id-7","type":"STRING"}}`,
	}
	if _, _, ok := ResolveField(values, "EMAIL"); ok {
		t.Fatal("EMAIL resolved although two fields with different values match")
	}
	err := FieldAmbiguity(values, "EMAIL")
	if err == nil || CodeOf(err) != ErrValidation || !strings.Contains(err.Error(), "Email, email") {
		t.Fatalf("FieldAmbiguity(EMAIL) = %v, want a validation error naming Email, email", err)
	}
	for wanted, want := range map[string]string{"Email": "a@example.com", "email": "b@example.com", "field-id-7": "b@example.com", "Work.e-mail": "c@example.com"} {
		if _, value, ok := ResolveField(values, wanted); !ok || value != want {
			t.Errorf("ResolveField(%q) = (%q, %v), want %q", wanted, value, ok, want)
		}
	}
	// Matches that hold the same value are one answer, not an ambiguity.
	same := map[string]string{"Token": "t", "token": "t"}
	if _, value, ok := ResolveField(same, "TOKEN"); !ok || value != "t" || FieldAmbiguity(same, "TOKEN") != nil {
		t.Fatalf("identical duplicates did not resolve: %q %v", value, ok)
	}
	for _, reserved := range []string{models.FieldMetaKey, models.ProcessOnlyKey, "secretgate.fields"} {
		if _, _, ok := ResolveField(values, reserved); ok {
			t.Errorf("reserved key resolved for %q", reserved)
		}
	}
	for _, name := range FieldNames(values) {
		if models.IsReservedKey(name) {
			t.Errorf("FieldNames lists reserved key %q", name)
		}
	}
}

func TestFieldNamesSorted(t *testing.T) {
	got := FieldNames(map[string]string{"b": "2", "a": "1", "c": "3"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("FieldNames = %v", got)
	}
}
