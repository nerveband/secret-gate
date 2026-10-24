package opconnect

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestItemFieldValuesKeysOTPFieldsByType(t *testing.T) {
	item := &Item{Fields: []Field{
		{ID: "TOTP_9FCC", Label: "", Type: "OTP", Value: "seed-a"},
		{ID: "custom-id", Label: "Verification", Type: "OTP", Value: "seed-b"},
		{ID: "password", Label: "password", Type: "CONCEALED", Value: "pw"},
	}}
	got := itemFieldValues(item)
	if got["TOTP_9FCC"] != "seed-a" || got["TOTP_custom-id"] != "seed-b" || got["TOTP_password"] != "" {
		t.Fatalf("OTP keys = %v", got)
	}
}

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
	if field := newField("", "MFA", "seed"); field.Type != "OTP" {
		t.Fatalf("MFA type = %s", field.Type)
	}
	if field := newField("", "api_key", "value"); field.Type != "CONCEALED" {
		t.Fatalf("api_key type = %s", field.Type)
	}
}

func TestCheckWriteCapability(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		allowed    bool
		code       string
		wantMethod string
	}{
		{name: "writable", status: http.StatusBadRequest, allowed: true, wantMethod: http.MethodPost},
		{name: "read only", status: http.StatusForbidden, code: "vault_write_unavailable", wantMethod: http.MethodPost},
		{name: "invalid token", status: http.StatusUnauthorized, code: "vault_write_unavailable", wantMethod: http.MethodPost},
		{name: "ambiguous response", status: http.StatusInternalServerError, code: "write_capability_unverified", wantMethod: http.MethodPost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/vaults":
					_ = json.NewEncoder(w).Encode([]Vault{{ID: "vault-id", Name: "AI Agents"}})
				case "/v1/vaults/vault-id/items":
					if r.Method != tt.wantMethod {
						t.Fatalf("method = %s", r.Method)
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if len(body) != 0 {
						t.Fatalf("capability probe body = %#v", body)
					}
					w.WriteHeader(tt.status)
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			got := New(server.URL, "test-token").CheckWriteCapability("AI Agents")
			if got.Allowed != tt.allowed || got.Code != tt.code {
				t.Fatalf("result = %#v", got)
			}
		})
	}
}

func TestNewFieldPasswordUsesPasswordPurpose(t *testing.T) {
	f := newField("PASSWORD", "password", "v")
	if f.ID != "password" || f.Purpose != "PASSWORD" || f.Type != "CONCEALED" {
		t.Fatalf("field = %#v", f)
	}
}

func TestPutItemSurfacesConnectValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vaults" {
			_ = json.NewEncoder(w).Encode([]Vault{{ID: "v", Name: "Agents"}})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":400,"message":"invalid"}`))
	}))
	defer server.Close()
	_, err := New(server.URL, "t").PutItem("Agents", "x", "create", "PASSWORD", map[string]string{"password": "v"})
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewFieldPurposesOnlyWhereTemplatesNeedThem(t *testing.T) {
	for cat, want := range map[string]string{"PASSWORD": "PASSWORD", "LOGIN": "PASSWORD", "SERVER": "", "DATABASE": "", "": ""} {
		if got := newField(cat, "password", "v").Purpose; got != want {
			t.Errorf("%s password purpose = %q, want %q", cat, got, want)
		}
	}
	if newField("LOGIN", "username", "u").Purpose != "USERNAME" || newField("SERVER", "username", "u").Purpose != "" {
		t.Fatal("username purpose must apply to LOGIN only")
	}
	if newField("API_CREDENTIAL", "credential", "v").Type != "CONCEALED" {
		t.Fatal("credential must be concealed")
	}
}

func TestPrecheckMutationRejectsDoomedWrites(t *testing.T) {
	titles := map[string]int{"exists": 1, "dup": 2}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vaults" {
			_ = json.NewEncoder(w).Encode([]Vault{{ID: "v", Name: "Agents"}})
			return
		}
		var out []Item
		for title, n := range titles {
			if strings.Contains(r.URL.Query().Get("filter"), `"`+title+`"`) {
				for i := 0; i < n; i++ {
					out = append(out, Item{ID: "id", Title: title})
				}
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	c := New(server.URL, "t")
	pw := map[string]string{"password": "v"}
	cases := []struct {
		name, title, op, cat string
		fields               map[string]string
		bad                  bool
	}{
		{"create ok", "new", "create", "password", pw, false},
		{"create existing", "exists", "create", "PASSWORD", pw, true},
		{"password category without password", "new", "create", "PASSWORD", map[string]string{"notes": "n"}, true},
		{"empty value", "new", "create", "PASSWORD", map[string]string{"password": ""}, true},
		{"quote in title", `a"b`, "create", "", pw, true},
		{"document unsupported", "new", "create", "DOCUMENT", pw, true},
		{"update ok", "exists", "update", "", pw, false},
		{"update missing", "new", "update", "", pw, true},
		{"update ambiguous", "dup", "update", "", pw, true},
	}
	for _, tc := range cases {
		err := c.PrecheckMutation("Agents", tc.title, tc.op, tc.cat, tc.fields)
		var verr *ValidationError
		if got := errors.As(err, &verr); got != tc.bad || (!tc.bad && err != nil) {
			t.Errorf("%s: err = %v, want validation=%v", tc.name, err, tc.bad)
		}
	}
}
