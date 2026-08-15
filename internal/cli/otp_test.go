package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/otp"
)

const demoSeed = "GEZDGNBVGEZDGNBVGEZDGNBVGEZDGNBV" // RFC 6238 demo seed

func expectedOTP(t *testing.T) string {
	t.Helper()
	code, _, err := otp.Generate(demoSeed, time.Unix(59, 0)) // matches newTestApp's fixed clock
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestOTPShowRequiresReveal(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["github"] = map[string]string{"one-time password": demoSeed}
	if code := ta.app.Run([]string{"otp", "show", "--item", "github"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if ta.stdout.Len() != 0 {
		t.Fatalf("OTP leaked without --reveal: %q", ta.stdout.String())
	}
}

func TestOTPShowWithReveal(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["github"] = map[string]string{"one-time password": demoSeed}
	if code := ta.app.Run([]string{"otp", "show", "--item", "github", "--reveal"}); code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["code"] != expectedOTP(t) {
		t.Fatalf("code = %v, want %s", data["code"], expectedOTP(t))
	}
	if env["meta"].(map[string]interface{})["visibility"] != "model-visible" {
		t.Fatal("otp show must be model-visible")
	}
}

func TestOTPExecInjectsAndRedacts(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["github"] = map[string]string{"one-time password": demoSeed}
	code := ta.app.Run([]string{"otp", "exec", "--item", "github", "--env", "OTP_CODE",
		"--shell", "echo code=$OTP_CODE"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	out := ta.stdout.String()
	if strings.Contains(out, expectedOTP(t)) {
		t.Fatalf("OTP code leaked to stdout: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:github/otp]") {
		t.Fatalf("missing redaction marker: %q", out)
	}
}

func TestOTPNoSeedExitSix(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["plain"] = map[string]string{"password": "fake-pass-9999"}
	if code := ta.app.Run([]string{"otp", "show", "--item", "plain", "--reveal"}); code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
}
