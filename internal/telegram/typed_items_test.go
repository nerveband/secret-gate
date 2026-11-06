package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/models"
)

func TestCardReadShowsPurposeAndMaskedCardWithoutWindows(t *testing.T) {
	req := &models.ApprovalRequest{
		ID: "r1", Vault: "AI Agents", Action: "read", Reason: "pay for the DFW flight", Sensitive: true,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Context:   models.RequestContext{Purpose: "aa.com checkout"},
		Secrets:   []models.SecretRequest{{SecretName: "Visa travel", Fields: []string{"number", "cvv"}, Summary: "Visa ending 1111, expires 08/2027"}},
	}
	text := approvalMessage(req)
	if !strings.Contains(text, "aa.com checkout, Visa ending 1111, expires 08/2027") || !strings.Contains(text, "Purpose:\n<b>aa.com checkout</b>") {
		t.Fatalf("message = %s", text)
	}
	if got := approvedMessage(req, "nerveband", "One use"); !strings.Contains(got, "aa.com checkout, Visa ending 1111") {
		t.Fatalf("approved message = %s", got)
	}
	kb := approvalKeyboard(req, 30*time.Minute)
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, "approve_window") || strings.HasPrefix(b.CallbackData, "approve_writes") {
				t.Fatalf("card read offers %q", b.Text)
			}
		}
	}
}

func TestCardReadWithAmountAsksToApproveThatAmount(t *testing.T) {
	req := &models.ApprovalRequest{
		ID: "r3", Vault: "AI Agents", Action: "read", Reason: "pay for the DFW flight", Sensitive: true,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Context:   models.RequestContext{Purpose: "aa.com checkout", Amount: "$412.30"},
		Secrets:   []models.SecretRequest{{SecretName: "Visa travel", Fields: []string{"number", "cvv"}, Summary: "Visa ending 1111, expires 08/2027"}},
	}
	if text := approvalMessage(req); !strings.Contains(text, "Approve $412.30 at aa.com checkout, Visa ending 1111, expires 08/2027") || !strings.Contains(text, "Amount:\n<b>$412.30</b>") {
		t.Fatalf("message = %s", text)
	}
	if b := approvalKeyboard(req, 0).InlineKeyboard[0][0]; b.Text != "✅ Approve $412.30" || b.CallbackData != "approve:r3" {
		t.Fatalf("approve button = %+v", b)
	}
}

func TestOwnerEntryWriteLinksTheEntryPageInsteadOfApprove(t *testing.T) {
	req := &models.ApprovalRequest{
		ID: "r2", Vault: "AI Agents", Action: "update", Reason: "add the CVV", Sensitive: true,
		ExpiresAt:  time.Now().Add(time.Hour),
		EntryURL:   "https://gate.example/entry/abc",
		EntryToken: "abc",
		Mutations: []models.ItemMutation{{Item: "Visa travel", Operation: "update", TargetCategory: "CREDIT_CARD",
			Fields: map[string]string{"zip": "02139"}, OwnerFields: []string{"cvv"}}},
	}
	text := approvalMessage(req)
	if !strings.Contains(text, "You enter: cvv") || !strings.Contains(text, "Fields: zip") || !strings.Contains(text, "credit card") || strings.Contains(text, "02139") {
		t.Fatalf("message = %s", text)
	}
	kb := approvalKeyboard(req, 15*time.Minute)
	if len(kb.InlineKeyboard) != 2 || kb.InlineKeyboard[0][0].URL != req.EntryURL || kb.InlineKeyboard[0][0].CallbackData != "" ||
		kb.InlineKeyboard[1][0].CallbackData != "deny:r2" {
		t.Fatalf("keyboard = %+v", kb.InlineKeyboard)
	}
}
