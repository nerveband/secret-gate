package core

import (
	"context"
	"strings"
	"testing"
)

// cachedCard is a card as the server releases it: values under ID, label,
// and section keys, plus the process-only marker.
func cachedCard() map[string]map[string]string {
	return map[string]map[string]string{
		"Visa travel": {
			"ccnum": "4111111111111111", "number": "4111111111111111",
			"cvv": "7319", "verification number": "7319",
			"expiry": "08/2027", "expiry date": "08/2027",
			"cardholder": "Test Holder",
			ProcessOnlyKey: "ccnum,cvv,number,verification number",
		},
	}
}

func TestCardNumberAndCVVNeverEnterModelContext(t *testing.T) {
	svc, _ := newTestService(cachedCard())
	all, err := svc.ReadFields("Visa travel", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range all {
		if v == "4111111111111111" || v == "7319" || k == ProcessOnlyKey {
			t.Fatalf("full read returned process-only key %q", k)
		}
	}
	if all["expiry"] != "08/2027" || all["cardholder"] != "Test Holder" {
		t.Fatalf("non-sensitive fields missing: %v", all)
	}
	for _, name := range []string{"number", "ccnum", "CVV", "verification-number"} {
		_, err := svc.ReadFields("Visa travel", "", []string{name})
		if CodeOf(err) != ErrValidation || strings.Contains(err.Error(), "7319") || strings.Contains(err.Error(), "4111111111111111") {
			t.Fatalf("read %q: err = %v", name, err)
		}
	}
	if _, err := svc.ReadFields("Visa travel", "", []string{ProcessOnlyKey}); err == nil {
		t.Fatal("the marker itself is readable")
	}
	for _, name := range FieldNames(cachedCard()["Visa travel"]) {
		if name == ProcessOnlyKey {
			t.Fatal("FieldNames lists the marker")
		}
	}
}

func TestExecGetsTheCardNumberButOutputIsRedacted(t *testing.T) {
	svc, _ := newTestService(cachedCard())
	out, err := svc.Exec(context.Background(), ExecRequest{
		SecretName: "Visa travel", Field: "number", EnvVar: "CC",
		ShellCommand: `echo "raw=$CC"; echo "$CC" | sed -E 's/(....)/\1 /g'; echo "$CC" | sed -E 's/(....)(....)(....)(....)/\1-\2-\3-\4/'`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"} {
		if strings.Contains(out.Stdout, leak) {
			t.Fatalf("stdout leaks %q: %q", leak, out.Stdout)
		}
	}
	if strings.Count(out.Stdout, "[REDACTED:Visa travel/") < 3 {
		t.Fatalf("stdout = %q", out.Stdout)
	}
}

func TestFillSpecAndExpiryFormats(t *testing.T) {
	spec, err := ParseFillSpec(`expiry:MM/YY=input[name="exp"]`)
	if err != nil || spec.Field != "expiry" || spec.Format != "MM/YY" || spec.Selector != `input[name="exp"]` {
		t.Fatalf("spec = %+v, %v", spec, err)
	}
	if _, err := ParseFillSpec("number"); err == nil {
		t.Fatal("a spec without a selector parsed")
	}
	cases := map[string]string{"MM": "08", "M": "8", "YY": "27", "YYYY": "2027", "MM/YY": "08/27", "MM/YYYY": "08/2027", "MMYY": "0827", "MM-YY": "08-27", "YYYY-MM": "2027-08"}
	for format, want := range cases {
		for _, stored := range []string{"08/2027", "202708", "8/27"} {
			if got, err := formatMonthYear(stored, format); err != nil || got != want {
				t.Errorf("%s from %s = %q, %v; want %q", format, stored, got, err, want)
			}
		}
	}
	if _, err := formatMonthYear("Test Holder", "MM"); err == nil {
		t.Fatal("a non-date value was formatted")
	}
}

func TestBrowserFillRequiresAnApprovedField(t *testing.T) {
	svc, _ := newTestService(cachedCard())
	_, err := svc.BrowserFill(context.Background(), BrowserFillRequest{
		SecretName: "Visa travel", Target: PasskeyTarget{Endpoint: "9222"},
		Fields: []FillSpec{{Field: "pin", Selector: "#pin"}},
	})
	if CodeOf(err) != ErrNotFound {
		t.Fatalf("err = %v", err)
	}
}
