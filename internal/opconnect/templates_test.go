package opconnect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/models"
)

// captureCreate returns a client whose Connect records the created item.
func captureCreate(t *testing.T) (*Client, *Item) {
	t.Helper()
	var saved Item
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]Vault{{ID: "v", Name: "Agents"}})
		case r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&saved)
			_ = json.NewEncoder(w).Encode(saved)
		default:
			_ = json.NewEncoder(w).Encode([]Item{})
		}
	}))
	t.Cleanup(server.Close)
	return New(server.URL, "t"), &saved
}

func fieldsByID(item *Item) map[string]Field {
	out := map[string]Field{}
	for _, f := range item.Fields {
		out[f.ID] = f
	}
	return out
}

func TestAPICredentialUsesTheNativeTemplate(t *testing.T) {
	c, saved := captureCreate(t)
	_, err := c.PutItem("Agents", "Stripe test", "create", "api", map[string]string{
		"api_key": "sk_test_value", "key id": "kid", "base url": "https://api.stripe.com", "expires": "2027-08-01", "scopes": "charges:read",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := fieldsByID(saved)
	if saved.Category != "API_CREDENTIAL" || f["credential"].Type != "CONCEALED" || f["credential"].Value != "sk_test_value" ||
		f["username"].Value != "kid" || f["hostname"].Value != "https://api.stripe.com" ||
		f["expires"].Type != "DATE" || f["scopes"].Section == nil {
		t.Fatalf("item = %+v", saved)
	}
	if len(saved.Sections) != 1 || saved.Sections[0].ID != "details" {
		t.Fatalf("sections = %+v", saved.Sections)
	}
}

func TestCardTypeIsDetectedAndValuesNormalized(t *testing.T) {
	c, saved := captureCreate(t)
	if _, err := c.PutItem("Agents", "MC", "create", "Credit Card", map[string]string{"card number": "5555-5555-5555-4444", "exp": "8/2029"}); err != nil {
		t.Fatal(err)
	}
	f := fieldsByID(saved)
	if saved.Category != "CREDIT_CARD" || f["ccnum"].Value != "5555555555554444" || f["type"].Value != "mc" || f["expiry"].Value != "202908" {
		t.Fatalf("fields = %+v", f)
	}
	if got := summarizeCard(saved).String(); got != "Mastercard ending 4444, expires 08/2029" {
		t.Fatalf("summary = %q", got)
	}
}

func TestReleasedCardValuesCarryTheProcessOnlyMarker(t *testing.T) {
	item := &Item{Category: "CREDIT_CARD", Fields: []Field{
		{ID: "ccnum", Label: "number", Type: "CREDIT_CARD_NUMBER", Value: "4111111111111111"},
		{ID: "cvv", Label: "verification number", Type: "CONCEALED", Value: "123"},
		{ID: "pin", Label: "PIN", Type: "CONCEALED", Value: "9876", Section: &Section{ID: "details", Label: "Additional Details"}},
		{ID: "expiry", Label: "expiry date", Type: "MONTH_YEAR", Value: "202708"},
		{ID: "cardholder", Label: "cardholder name", Type: "STRING", Value: "A"},
	}}
	values := itemFieldValues(item)
	marker := strings.Split(values[models.ProcessOnlyKey], ",")
	want := "Additional Details.PIN,PIN,ccnum,cvv,number,pin,verification number"
	if strings.Join(marker, ",") != want {
		t.Fatalf("marker = %v, want %s", marker, want)
	}
	if values["expiry"] != "08/2027" {
		t.Fatalf("expiry reads as %q", values["expiry"])
	}
	api := &Item{Category: "API_CREDENTIAL", Fields: []Field{{ID: "expires", Label: "expires", Type: "DATE", Value: "1817078400"}, {ID: "credential", Type: "CONCEALED", Value: "x"}}}
	values = itemFieldValues(api)
	if values["expires"] != "2027-08-01" || values[models.ProcessOnlyKey] != "" {
		t.Fatalf("api values: expires %q, marker %q", values["expires"], values[models.ProcessOnlyKey])
	}
}

func TestCategoryAliases(t *testing.T) {
	for in, want := range map[string]string{"card": "CREDIT_CARD", "Credit Card": "CREDIT_CARD", "api": "API_CREDENTIAL", "note": "SECURE_NOTE", "": "SECURE_NOTE", "login": "LOGIN", "server": "SERVER", "bank": "BANK_ACCOUNT"} {
		if got := NormalizeCategory(in); got != want {
			t.Errorf("NormalizeCategory(%q) = %q, want %q", in, got, want)
		}
	}
}
