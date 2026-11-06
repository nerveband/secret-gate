package core

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/johnuopini/secret-gate/internal/passkey"
)

// FillSpec maps one cached field (optionally reformatted) to a CSS selector.
// Spec syntax: "<field>[:<format>]=<css selector>", for example
// "number=#cardnumber" or "expiry:MM/YY=input[name=exp]".
type FillSpec struct {
	Field    string `json:"field" jsonschema:"item field label, ID, or section.label (for example number, cvv, expiry)"`
	Format   string `json:"format,omitempty" jsonschema:"for expiry dates: MM, YY, YYYY, MM/YY, MM/YYYY, MMYY, or MM-YY"`
	Selector string `json:"selector" jsonschema:"CSS selector of the form field"`
}

// ParseFillSpec parses "<field>[:<format>]=<selector>". Field names never
// contain "=", so the first one separates the selector.
func ParseFillSpec(s string) (FillSpec, error) {
	left, selector, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(left) == "" || strings.TrimSpace(selector) == "" {
		return FillSpec{}, E(ErrValidation, fmt.Sprintf("fill spec %q must be <field>=<css selector>", s),
			`example: --field "number=#cardnumber" --field "expiry:MM/YY=#exp"`)
	}
	field, format, _ := strings.Cut(left, ":")
	return FillSpec{Field: strings.TrimSpace(field), Format: strings.TrimSpace(format), Selector: strings.TrimSpace(selector)}, nil
}

// BrowserFillRequest types cached values of one item into a browser tab.
type BrowserFillRequest struct {
	SecretName string
	Vault      string
	Target     PasskeyTarget
	FrameURL   string
	Fields     []FillSpec
}

// BrowserFillOutcome reports what was filled, never the values.
type BrowserFillOutcome struct {
	Page    passkey.FillPage     `json:"page"`
	Results []passkey.FillResult `json:"results"`
	Filled  int                  `json:"filled"`
	Item    string               `json:"secret_used"`
}

var monthYearValue = regexp.MustCompile(`^(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})$|^(\d{4})[\-/]?(\d{2})$`)

// formatMonthYear rewrites an expiry such as 08/2027 into a form layout.
func formatMonthYear(value, format string) (string, error) {
	m := monthYearValue.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return "", E(ErrValidation, "the field is not a month and year, so a date format cannot be applied", "drop the :format suffix")
	}
	var month, year int
	if m[1] != "" {
		month, _ = strconv.Atoi(m[1])
		year, _ = strconv.Atoi(m[2])
	} else {
		year, _ = strconv.Atoi(m[3])
		month, _ = strconv.Atoi(m[4])
	}
	if year < 100 {
		year += 2000
	}
	mm, yy, yyyy := fmt.Sprintf("%02d", month), fmt.Sprintf("%02d", year%100), fmt.Sprintf("%04d", year)
	switch strings.ToUpper(format) {
	case "MM":
		return mm, nil
	case "M":
		return strconv.Itoa(month), nil
	case "YY":
		return yy, nil
	case "YYYY":
		return yyyy, nil
	case "MM/YY":
		return mm + "/" + yy, nil
	case "MM/YYYY":
		return mm + "/" + yyyy, nil
	case "MMYY":
		return mm + yy, nil
	case "MM-YY":
		return mm + "-" + yy, nil
	case "YYYY-MM":
		return yyyy + "-" + mm, nil
	}
	return "", E(ErrValidation, fmt.Sprintf("unknown date format %q", format), "use MM, M, YY, YYYY, MM/YY, MM/YYYY, MMYY, MM-YY, or YYYY-MM")
}

// BrowserFill types approved, cached values into form fields of a browser
// tab over a loopback DevTools session. Values never enter model context.
// Pages receiving card numbers, CVVs, or PINs must be https.
func (s *Service) BrowserFill(ctx context.Context, req BrowserFillRequest) (*BrowserFillOutcome, error) {
	if len(req.Fields) == 0 {
		return nil, E(ErrValidation, "at least one --field <field>=<selector> is required", `example: --field "number=#cardnumber"`)
	}
	values, err := s.CachedFields(req.SecretName, req.Vault)
	if err != nil {
		return nil, err
	}
	protected := ProcessOnlyKeys(values)
	steps := make([]passkey.FillStep, 0, len(req.Fields))
	sensitive := false
	for _, f := range req.Fields {
		if strings.HasPrefix(f.Field, AttachmentPrefix) {
			return nil, E(ErrValidation, "attachments cannot be typed into a page", "")
		}
		actual, value, ok := ResolveField(values, f.Field)
		if !ok {
			if err := FieldAmbiguity(values, f.Field); err != nil {
				return nil, err
			}
			return nil, E(ErrNotFound, fmt.Sprintf("field %q not found in item %q", f.Field, req.SecretName),
				"available fields: "+strings.Join(FieldNames(values), ", "))
		}
		if protected[actual] {
			sensitive = true
		}
		if f.Format != "" {
			if value, err = formatMonthYear(value, f.Format); err != nil {
				return nil, err
			}
		}
		steps = append(steps, passkey.FillStep{Field: actual, Selector: f.Selector, Value: value})
	}
	page, results, err := passkey.Fill(ctx, passkey.FillTarget{
		Target:       passkey.Target{Endpoint: req.Target.Endpoint, PageURL: req.Target.PageURL, TargetID: req.Target.TargetID},
		FrameURL:     req.FrameURL,
		RequireHTTPS: sensitive,
	}, steps)
	if err != nil {
		return nil, E(ErrValidation, "browser fill failed: "+err.Error(), "check --cdp, --page-url, and --frame-url")
	}
	filled := 0
	for _, r := range results {
		if r.Filled {
			filled++
		}
	}
	return &BrowserFillOutcome{Page: page, Results: results, Filled: filled, Item: req.SecretName}, nil
}
