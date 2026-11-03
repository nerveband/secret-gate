package passkey

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestFillTypesValuesAndReportsOnlySelectors(t *testing.T) {
	fb, endpoint := newFakeBrowser(t,
		pageTarget{TargetID: "T1", Type: "page", URL: "https://example.com/"},
		pageTarget{TargetID: "T2", Type: "page", URL: "https://www.aa.com/checkout"})
	page, results, err := Fill(context.Background(), FillTarget{Target: Target{Endpoint: endpoint, PageURL: "aa.com"}, RequireHTTPS: true}, []FillStep{
		{Field: "number", Selector: "#cardNumber", Value: "4111111111111111"},
		{Field: "cvv", Selector: "#missing", Value: "7319"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.TargetID != "T2" || fb.attached != "T2" {
		t.Fatalf("filled %q, want the aa.com tab", page.TargetID)
	}
	if len(fb.typed) != 1 || fb.typed[0] != "4111111111111111" {
		t.Fatalf("typed %d values", len(fb.typed))
	}
	if !results[0].Filled || results[1].Filled || results[1].Error != "no element matches the selector" {
		t.Fatalf("results = %+v", results)
	}
	raw, _ := json.Marshal(results)
	if strings.Contains(string(raw), "4111111111111111") || strings.Contains(string(raw), "7319") {
		t.Fatalf("results carry a value: %s", raw)
	}
}

func TestFillRefusesCardValuesOnPlainHTTP(t *testing.T) {
	fb, endpoint := newFakeBrowser(t, pageTarget{TargetID: "T1", Type: "page", URL: "http://shop.example.com/pay"})
	_, _, err := Fill(context.Background(), FillTarget{Target: Target{Endpoint: endpoint}, RequireHTTPS: true}, []FillStep{{Field: "number", Selector: "#cc", Value: "4111111111111111"}})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err = %v", err)
	}
	if len(fb.typed) != 0 {
		t.Fatal("a value was typed into an http page")
	}
}
