package opconnect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestItemFieldValuesKeepsDuplicateLabelsAddressable(t *testing.T) {
	item := &Item{Fields: []Field{
		{ID: "first-id", Label: "context", Value: "first", Section: &Section{Label: "Development"}},
		{ID: "second-id", Label: "context", Value: "second", Section: &Section{Label: "Production"}},
		{ID: "notesPlain", Label: "notesPlain", Value: "notes"},
	}}
	got := itemFieldValues(item)
	for key, want := range map[string]string{"first-id": "first", "Development.context": "first", "second-id": "second", "Production.context": "second", "notesPlain": "notes"} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
	if _, exists := got["context"]; exists {
		t.Error("ambiguous duplicate label should not be exposed without a section or ID")
	}
}

func TestPutItemCreatesSecureNote(t *testing.T) {
	var saved Item
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]Vault{{ID: "vault-id", Name: "Agents"}})
		case "/v1/vaults/vault-id/items":
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&saved); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(saved)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := New(server.URL, "test-token")
	item, err := client.PutItem("Agents", "Release context", "create", "", map[string]string{"notesPlain": "context"})
	if err != nil {
		t.Fatal(err)
	}
	if item.Category != "SECURE_NOTE" || item.Title != "Release context" {
		t.Fatalf("item = %#v", item)
	}
	if len(saved.Fields) != 1 || saved.Fields[0].Value != "context" || saved.Fields[0].Purpose != "NOTES" {
		t.Fatalf("saved fields = %#v", saved.Fields)
	}
}

func TestNewFieldRecognizesOTPAndConcealedAliases(t *testing.T) {
	if field := newField("MFA", "seed"); field.Type != "OTP" {
		t.Fatalf("MFA type = %s", field.Type)
	}
	if field := newField("api_key", "value"); field.Type != "CONCEALED" {
		t.Fatalf("api_key type = %s", field.Type)
	}
}
