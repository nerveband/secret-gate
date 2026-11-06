package core

import (
	"strings"
	"testing"
	"time"

	"github.com/nerveband/secret-gate/internal/otp"
)

const (
	unlabeledOTPSeed = "GEZDGNBVGEZDGNBVGEZDGNBVGEZDGNBV" // RFC 6238 demo seed
	unlabeledOTPID   = "TOTP_9FCC2DA5B1254F84BC189D2E91B7503E"
)

// unlabeledOTPItem mirrors what the server's item map holds for an item whose
// only OTP field has an empty label: the field is keyed by its ID only.
func unlabeledOTPItem() map[string]string {
	return map[string]string{
		"email":        "agent@example.com",
		"password":     "fake-pass-9999",
		unlabeledOTPID: unlabeledOTPSeed,
	}
}

// approve applies the approval-time field filter the server uses before the
// daemon caches the item.
func approve(item map[string]string, fields []string) map[string]string {
	cached := map[string]string{}
	for _, f := range fields {
		if actual, val, ok := ResolveField(item, f); ok {
			cached[actual] = val
		}
	}
	return cached
}

func TestUnlabeledOTPApproveAndUse(t *testing.T) {
	fixed := time.Unix(59, 0)
	wantCode, _, _ := otp.Generate(unlabeledOTPSeed, fixed)
	for _, wanted := range []string{"otp", "one-time password", unlabeledOTPID} {
		cached := approve(unlabeledOTPItem(), []string{"email", "password", wanted})
		if cached[unlabeledOTPID] != unlabeledOTPSeed {
			t.Fatalf("approve %q: OTP not cached, keys %v", wanted, FieldNames(cached))
		}
		svc, _ := newTestService(map[string]map[string]string{"bank": cached})
		svc.Now = func() time.Time { return fixed }
		for _, field := range []string{"", wanted} {
			got, err := svc.GetOTP("bank", "", field)
			if err != nil {
				t.Fatalf("GetOTP(%q) after approving %q: %v", field, wanted, err)
			}
			if got.Code != wantCode || got.SecretUsed != "bank/"+unlabeledOTPID {
				t.Fatalf("GetOTP(%q) = %+v", field, got)
			}
		}
	}
}

func TestTwoUnlabeledOTPFieldsAreAmbiguous(t *testing.T) {
	second := "TOTP_AAAA0000000000000000000000000000"
	item := map[string]string{unlabeledOTPID: unlabeledOTPSeed, second: "JBSWY3DPEHPK3PXP"}
	if _, _, ok := ResolveField(item, "otp"); ok {
		t.Fatal("alias resolved despite two OTP fields")
	}
	if got := approve(item, []string{second}); got[second] != "JBSWY3DPEHPK3PXP" || len(got) != 1 {
		t.Fatalf("approve by ID = keys %v", FieldNames(got))
	}

	svc, _ := newTestService(map[string]map[string]string{"bank": item})
	_, err := svc.GetOTP("bank", "", "one-time password")
	if CodeOf(err) != ErrValidation || !strings.Contains(err.Error(), unlabeledOTPID) || !strings.Contains(err.Error(), second) {
		t.Fatalf("GetOTP alias err = %v", err)
	}
	if _, err := svc.GetOTP("bank", "", second); err != nil {
		t.Fatalf("GetOTP by ID: %v", err)
	}
}
