package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
)

// The "Example Co @ Accounting" shape: the login password next to saved
// web-form fields with similar labels. An approved "password" releases the
// login password and names the other non-empty fields; approving one of
// those names releases that field, so a failed login can be retried.
func TestApprovedPasswordReleasesLoginPasswordAndNamesAlternatives(t *testing.T) {
	wh := newWriteHarness(t)
	wh.connect.items["item-0"] = opconnect.Item{ID: "item-0", Title: "Accounting", Category: "LOGIN", Vault: opconnect.Vault{ID: "vid"},
		Fields: []opconnect.Field{
			{Label: "password", Type: "STRING", Value: ""},
			{Label: "Password", Type: "STRING", Value: "form-upper"},
			{Label: "SignIn", Type: "STRING"},
			{Label: "SignIn", Type: "STRING"},
			{ID: "password", Label: "password", Type: "CONCEALED", Purpose: "PASSWORD", Value: "real-login-pw"},
		}}
	release := func(field string) map[string]string {
		t.Helper()
		body := fmt.Sprintf(`{"secret_name":"Accounting","vault":"AI Agents","machine":"m","reason":"sign in","secrets":[{"secret_name":"Accounting","vault":"AI Agents","fields":[%q]}]}`, field)
		code, resp, raw := wh.submit(body, agentAddr)
		if code != http.StatusAccepted {
			t.Fatalf("submit %q: code=%d body=%s", field, code, raw)
		}
		wh.tap("approve", resp.Token)
		code, out := wh.complete(resp.Token)
		if code != http.StatusOK {
			t.Fatalf("release %q: code=%d body=%s", field, code, out)
		}
		var secrets BatchSecretResponse
		if err := json.Unmarshal([]byte(out), &secrets); err != nil {
			t.Fatal(err)
		}
		return secrets.Secrets["Accounting"]
	}

	got := release("password")
	if got["password"] != "real-login-pw" || len(core.FieldNames(got)) != 1 {
		t.Fatalf("password released keys %v, want only the login password", core.FieldNames(got))
	}
	meta := core.FieldMeta(got)["password"]
	if meta.Purpose != "PASSWORD" || meta.Type != "CONCEALED" || strings.Join(meta.Alternatives, ",") != "Password" {
		t.Fatalf("released meta = %+v, want PASSWORD/CONCEALED with alternative Password", meta)
	}
	if strings.Contains(got[models.FieldMetaKey], "form-upper") || strings.Contains(got[models.FieldMetaKey], "SignIn") {
		t.Fatal("metadata carries a value or an unreleased field")
	}
	// The client sees the alternative and refuses to answer it from the cache.
	if alts := core.FieldAlternatives(got, "password", "password"); strings.Join(alts, ",") != "Password" {
		t.Fatalf("client alternatives = %v", alts)
	}
	if _, _, ok := core.ResolveField(got, "Password"); ok {
		t.Fatal("cached login password answered a request for the alternative")
	}
	// Retry: approving the alternative releases the web-form field.
	if got = release("Password"); got["Password"] != "form-upper" {
		t.Fatalf("Password released keys %v, want the web-form field", core.FieldNames(got))
	}
}
