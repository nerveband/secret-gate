package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nerveband/secret-gate/internal/core"
)

func cachedTestCard() map[string]string {
	return map[string]string{
		"ccnum": "4111111111111111", "number": "4111111111111111", "cvv": "7319",
		"expiry": "08/2027", "cardholder": "Test Holder",
		core.ProcessOnlyKey: "ccnum,cvv,number",
	}
}

func TestItemReadRevealRefusesCardNumberAndCVV(t *testing.T) {
	for _, args := range [][]string{
		{"item", "read", "--item", "Visa travel", "--fields", "number", "--reveal"},
		{"item", "read", "--item", "Visa travel", "--fields", "cvv", "--reveal"},
		{"item", "read", "--item", "Visa travel", "--reveal"},
	} {
		ta := newTestApp(t)
		ta.daemon.data["Visa travel"] = cachedTestCard()
		ta.app.Run(args)
		out := ta.stdout.String() + ta.stderr.String()
		if strings.Contains(out, "4111111111111111") || strings.Contains(out, "7319") {
			t.Fatalf("%v printed a card value", args)
		}
	}
}

func TestOwnerFieldWriteNeedsNoStdinAndSendsLabelsOnly(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"write", "update", "--item", "Visa travel", "--vault", "AI Agents", "--owner-fields", "cvv", "--reason", "add the CVV", "--no-wait"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	items := ta.proxy.batchItems[0]
	if len(items) != 1 || len(items[0].Fields) != 0 || strings.Join(items[0].OwnerFields, ",") != "cvv" {
		t.Fatalf("submitted = %+v", items)
	}
}

func TestCardCreateFromStdinNeverEchoesValues(t *testing.T) {
	ta := newTestApp(t)
	ta.app.Stdin = bytes.NewBufferString(`{"fields":{"number":"4111111111111111","cvv":"7319","expiry":"08/27"}}`)
	code := ta.app.Run([]string{"write", "create", "--item", "Visa travel", "--vault", "AI Agents", "--category", "card", "--reason", "store the card", "--stdin"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if out := ta.stdout.String() + ta.stderr.String(); strings.Contains(out, "4111111111111111") || strings.Contains(out, "7319") {
		t.Fatalf("output echoes a value: %s", out)
	}
}
