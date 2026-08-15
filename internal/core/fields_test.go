package core

import (
	"reflect"
	"testing"
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

func TestFieldNamesSorted(t *testing.T) {
	got := FieldNames(map[string]string{"b": "2", "a": "1", "c": "3"})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("FieldNames = %v", got)
	}
}
