package opconnect

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/models"
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

// Regression for "Example Co @ Accounting": the login password sits next to
// saved web-form fields labeled "password" and "Password" that are empty.
// The server filter and the client cache must both pick the login password.
func TestItemFieldValuesDuplicatePasswordFieldsResolveToLoginPassword(t *testing.T) {
	item := &Item{Category: "LOGIN", Fields: []Field{
		{ID: "", Label: "password", Type: "STRING", Value: ""},
		{ID: "username", Label: "username", Type: "STRING", Purpose: "USERNAME", Value: "admin@example.com"},
		{ID: "", Label: "Password", Type: "STRING", Value: ""},
		{ID: "", Label: "SignIn", Type: "STRING", Value: ""},
		{ID: "", Label: "SignIn", Type: "STRING", Value: ""},
		{ID: "password", Label: "password", Type: "CONCEALED", Purpose: "PASSWORD", Value: "real-login-pw"},
	}}
	values := itemFieldValues(item)
	meta := core.FieldMeta(values)
	if m := meta["password"]; m.ID != "password" || m.Type != "CONCEALED" || m.Purpose != "PASSWORD" {
		t.Fatalf("meta[password] = %+v, want the login password field", m)
	}
	if m := meta["Password"]; m.ID != "" || m.Type != "STRING" || m.Purpose != "" {
		t.Fatalf("meta[Password] = %+v, want the web-form field", m)
	}
	for _, wanted := range []string{"password", "Password"} {
		for range 20 {
			// Server: filter the approved field. Client: resolve it from the cache.
			actual, value, ok := core.ResolveField(values, wanted)
			if !ok || actual != "password" || value != "real-login-pw" {
				t.Fatalf("server ResolveField(%q) = (%q, len %d, %v)", wanted, actual, len(value), ok)
			}
			cached := map[string]string{actual: value, models.FieldMetaKey: values[models.FieldMetaKey]}
			if _, value, ok := core.ResolveField(cached, wanted); !ok || value != "real-login-pw" {
				t.Fatalf("client ResolveField(%q) = (len %d, %v)", wanted, len(value), ok)
			}
		}
	}
}

// When the saved web-form fields hold other values, each is addressable by
// its selector, and releasing "password" names them as alternatives so an
// agent whose login fails can request one and retry.
func TestDuplicatePasswordFieldsAreAlternativesWithSelectors(t *testing.T) {
	item := &Item{Category: "LOGIN", Fields: []Field{
		{ID: "", Label: "password", Type: "STRING", Value: "form-lower"},
		{ID: "", Label: "Password", Type: "STRING", Value: "form-upper"},
		{ID: "", Label: "SignIn", Type: "STRING", Value: ""},
		{ID: "", Label: "SignIn", Type: "STRING", Value: ""},
		{ID: "password", Label: "password", Type: "CONCEALED", Purpose: "PASSWORD", Value: "real-login-pw"},
	}}
	var got []string
	for _, keys := range fieldSelectors(item.Fields) {
		got = append(got, keys[0])
	}
	if want := []string{"password#1", "Password", "SignIn#1", "SignIn#2", "password"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("selectors = %v, want %v", got, want)
	}
	all := itemFieldValues(item)
	// Server release of "password": the login password, alternatives by name.
	actual, value, ok := core.ResolveField(all, "password")
	if !ok || actual != "password" || value != "real-login-pw" {
		t.Fatalf("password resolved to %q (%v)", actual, ok)
	}
	alts := core.FieldAlternatives(all, "password", actual)
	if strings.Join(alts, ",") != "Password,password#1" {
		t.Fatalf("alternatives = %v, want [Password password#1]", alts)
	}
	// Retrying with each alternative releases that field's value.
	for selector, want := range map[string]string{"Password": "form-upper", "password#1": "form-lower"} {
		if _, value, ok := core.ResolveField(all, selector); !ok || value != want {
			t.Errorf("ResolveField(%q) = (%q, %v), want %q", selector, value, ok, want)
		}
	}
}

func TestItemFieldValuesLabelNeverTakesAnotherFieldsID(t *testing.T) {
	item := &Item{Category: "LOGIN", Fields: []Field{
		{ID: "password", Label: "Password", Type: "CONCEALED", Purpose: "PASSWORD", Value: "real-login-pw"},
		{ID: "", Label: "password", Type: "STRING", Value: ""},
	}}
	if got := itemFieldValues(item); got["password"] != "real-login-pw" {
		t.Fatalf("key password holds len %d, want the login password", len(got["password"]))
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
	if field := nf("", "MFA", "seed"); field.Type != "OTP" {
		t.Fatalf("MFA type = %s", field.Type)
	}
	if field := nf("", "api_key", "value"); field.Type != "CONCEALED" {
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

// nf builds a field for tests whose values are valid for their category.
func nf(category, label, value string) Field {
	f, _ := newField(category, label, value)
	return f
}

func TestNewFieldPasswordUsesPasswordPurpose(t *testing.T) {
	f := nf("PASSWORD", "password", "v")
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
		if got := nf(cat, "password", "v").Purpose; got != want {
			t.Errorf("%s password purpose = %q, want %q", cat, got, want)
		}
	}
	if nf("LOGIN", "username", "u").Purpose != "USERNAME" || nf("SERVER", "username", "u").Purpose != "" {
		t.Fatal("username purpose must apply to LOGIN only")
	}
	if nf("API_CREDENTIAL", "credential", "v").Type != "CONCEALED" {
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
		owner                []string
		bad                  bool
	}{
		{"create ok", "new", "create", "password", pw, nil, false},
		{"create existing", "exists", "create", "PASSWORD", pw, nil, true},
		{"password category without password", "new", "create", "PASSWORD", map[string]string{"notes": "n"}, nil, true},
		{"password typed by the approver", "new", "create", "PASSWORD", nil, []string{"password"}, false},
		{"empty value", "new", "create", "PASSWORD", map[string]string{"password": ""}, nil, true},
		{"quote in title", `a"b`, "create", "", pw, nil, true},
		{"document unsupported", "new", "create", "DOCUMENT", pw, nil, true},
		{"update ok", "exists", "update", "", pw, nil, false},
		{"update missing", "new", "update", "", pw, nil, true},
		{"update ambiguous", "dup", "update", "", pw, nil, true},
		{"card ok", "new", "create", "card", map[string]string{"number": "4111 1111 1111 1111", "cvv": "123", "expiry": "08/27"}, nil, false},
		{"card without number", "new", "create", "card", map[string]string{"cvv": "123"}, nil, true},
		{"card number from the approver", "new", "create", "card", map[string]string{"cardholder": "A"}, []string{"number", "cvv"}, false},
		{"card number typo", "new", "create", "card", map[string]string{"number": "4111111111111112"}, nil, true},
		{"card cvv letters", "new", "create", "card", map[string]string{"number": "4111111111111111", "cvv": "12a"}, nil, true},
		{"card bad expiry", "new", "create", "card", map[string]string{"number": "4111111111111111", "expiry": "13/27"}, nil, true},
		{"card unknown type", "new", "create", "card", map[string]string{"number": "4111111111111111", "type": "bogus"}, nil, true},
		{"card number twice", "new", "create", "card", map[string]string{"number": "4111111111111111", "ccnum": "4111111111111111"}, nil, true},
		{"field both sent and asked", "new", "create", "card", map[string]string{"number": "4111111111111111"}, []string{"number"}, true},
		{"api bad date", "new", "create", "api", map[string]string{"credential": "x", "expires": "next year"}, nil, true},
		{"api ok", "new", "create", "api", map[string]string{"credential": "x", "expires": "2027-08-01", "host": "https://api.example.com"}, nil, false},
	}
	for _, tc := range cases {
		_, err := c.PrecheckMutation("Agents", tc.title, tc.op, tc.cat, tc.fields, tc.owner)
		var verr *ValidationError
		if got := errors.As(err, &verr); got != tc.bad || (!tc.bad && err != nil) {
			t.Errorf("%s: err = %v, want validation=%v", tc.name, err, tc.bad)
		}
		if err != nil {
			for _, v := range tc.fields {
				if len(v) > 2 && strings.Contains(err.Error(), v) {
					t.Errorf("%s: error message contains a field value", tc.name)
				}
			}
		}
	}
}
