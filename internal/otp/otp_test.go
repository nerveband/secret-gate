package otp

import (
	"testing"
	"time"
)

func TestGenerateRFC6238(t *testing.T) {
	code, _, err := Generate("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "94287082" {
		t.Fatalf("code = %s, want 94287082", code)
	}
}
