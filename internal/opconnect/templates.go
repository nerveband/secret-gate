package opconnect

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

// templateField maps friendly labels onto a field of a native 1Password
// category, so typed items look and behave like ones made in the app.
type templateField struct {
	ID      string
	Label   string
	Type    string
	Section *Section
	Aliases []string // normalized label aliases (see normalizeLabel)
	// ProcessOnly values may reach a child process or a browser field, never
	// model context.
	ProcessOnly bool
}

var (
	cardDetails  = &Section{ID: "details", Label: "Additional Details"}
	cardContact  = &Section{ID: "contactInfo", Label: "Contact Information"}
	cardBilling  = &Section{ID: "billing", Label: "Billing Address"}
	apiDetails   = &Section{ID: "details", Label: "Details"}
	templateList = map[string][]templateField{
		"CREDIT_CARD": {
			{ID: "cardholder", Label: "cardholder name", Type: "STRING", Aliases: []string{"cardholder", "cardholdername", "nameoncard", "holder", "name"}},
			{ID: "type", Label: "type", Type: "CREDIT_CARD_TYPE", Aliases: []string{"type", "cardtype", "brand", "network"}},
			{ID: "ccnum", Label: "number", Type: "CREDIT_CARD_NUMBER", ProcessOnly: true, Aliases: []string{"number", "ccnum", "cardnumber", "pan", "ccnumber"}},
			{ID: "cvv", Label: "verification number", Type: "CONCEALED", ProcessOnly: true, Aliases: []string{"cvv", "cvc", "cvv2", "cvc2", "csc", "securitycode", "verificationnumber"}},
			{ID: "expiry", Label: "expiry date", Type: "MONTH_YEAR", Aliases: []string{"expiry", "expirydate", "expiration", "expirationdate", "exp", "expires"}},
			{ID: "validFrom", Label: "valid from", Type: "MONTH_YEAR", Aliases: []string{"validfrom"}},
			{ID: "bank", Label: "issuing bank", Type: "STRING", Section: cardContact, Aliases: []string{"bank", "issuingbank", "issuer"}},
			{ID: "pin", Label: "PIN", Type: "CONCEALED", Section: cardDetails, ProcessOnly: true, Aliases: []string{"pin"}},
			{ID: "billing_address", Label: "billing address", Type: "STRING", Section: cardBilling, Aliases: []string{"billingaddress", "address", "street"}},
			{ID: "billing_city", Label: "city", Type: "STRING", Section: cardBilling, Aliases: []string{"city", "billingcity"}},
			{ID: "billing_state", Label: "state", Type: "STRING", Section: cardBilling, Aliases: []string{"state", "region", "billingstate"}},
			{ID: "zip", Label: "zip", Type: "STRING", Section: cardBilling, Aliases: []string{"zip", "zipcode", "postalcode", "postcode", "billingzip"}},
			{ID: "billing_country", Label: "country", Type: "STRING", Section: cardBilling, Aliases: []string{"country", "billingcountry"}},
		},
		"API_CREDENTIAL": {
			{ID: "username", Label: "username", Type: "STRING", Aliases: []string{"username", "keyid", "accesskeyid", "clientid", "user"}},
			{ID: "credential", Label: "credential", Type: "CONCEALED", Aliases: []string{"credential", "secret", "apikey", "key", "token", "secretkey", "clientsecret", "secretaccesskey", "accesstoken"}},
			{ID: "hostname", Label: "hostname", Type: "STRING", Aliases: []string{"hostname", "host", "baseurl", "url", "endpoint", "server"}},
			{ID: "validFrom", Label: "valid from", Type: "DATE", Aliases: []string{"validfrom"}},
			{ID: "expires", Label: "expires", Type: "DATE", Aliases: []string{"expires", "expiry", "expiration", "expiresat", "expirydate"}},
			{ID: "scopes", Label: "scopes", Type: "STRING", Section: apiDetails, Aliases: []string{"scopes", "scope", "permissions"}},
		},
	}
)

// categoryAliases accepts the names agents and people use for categories.
var categoryAliases = map[string]string{
	"card": "CREDIT_CARD", "creditcard": "CREDIT_CARD", "cc": "CREDIT_CARD",
	"api": "API_CREDENTIAL", "apikey": "API_CREDENTIAL", "apicredential": "API_CREDENTIAL",
	"note": "SECURE_NOTE", "securenote": "SECURE_NOTE",
	"login": "LOGIN", "password": "PASSWORD",
	"bank": "BANK_ACCOUNT", "bankaccount": "BANK_ACCOUNT",
	"identity": "IDENTITY", "passport": "PASSPORT", "sshkey": "SSH_KEY",
}

func normalizeLabel(label string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", ".", "").Replace(strings.ToLower(strings.TrimSpace(label)))
}

// templateFieldFor finds the native field a label stands for in category.
func templateFieldFor(category, label string) (templateField, bool) {
	n := normalizeLabel(label)
	for _, f := range templateList[category] {
		if normalizeLabel(f.ID) == n || normalizeLabel(f.Label) == n {
			return f, true
		}
		for _, a := range f.Aliases {
			if a == n {
				return f, true
			}
		}
	}
	return templateField{}, false
}

// Card types use the codes 1Password stores for the CREDIT_CARD_TYPE field.
var cardTypeNames = map[string]string{
	"visa": "Visa", "mc": "Mastercard", "amex": "American Express", "discover": "Discover",
	"diners": "Diners Club", "jcb": "JCB", "unionpay": "UnionPay", "maestro": "Maestro",
}

var cardTypeAliases = map[string]string{
	"visa": "visa", "mc": "mc", "mastercard": "mc", "master": "mc",
	"amex": "amex", "americanexpress": "amex", "discover": "discover",
	"diners": "diners", "dinersclub": "diners", "jcb": "jcb",
	"unionpay": "unionpay", "chinaunionpay": "unionpay", "maestro": "maestro",
}

// CardTypeName returns the display name of a stored card type code.
func CardTypeName(code string) string {
	if name, ok := cardTypeNames[strings.ToLower(code)]; ok {
		return name
	}
	return code
}

// detectCardType infers the network from the number's prefix.
func detectCardType(digits string) string {
	prefix := func(n int) int {
		if len(digits) < n {
			return -1
		}
		v, _ := strconv.Atoi(digits[:n])
		return v
	}
	switch p2, p3, p4, p6 := prefix(2), prefix(3), prefix(4), prefix(6); {
	case strings.HasPrefix(digits, "4"):
		return "visa"
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return "mc"
	case p2 == 34 || p2 == 37:
		return "amex"
	case p4 == 6011, p2 == 65, p3 >= 644 && p3 <= 649, p6 >= 622126 && p6 <= 622925:
		return "discover"
	case p4 >= 3528 && p4 <= 3589:
		return "jcb"
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38:
		return "diners"
	case p2 == 62:
		return "unionpay"
	case p2 == 50, p2 >= 56 && p2 <= 58, p2 == 63, p2 == 67:
		return "maestro"
	}
	return ""
}

func luhnValid(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

var (
	monthYearPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})$`), // MM/YY, MM/YYYY
		regexp.MustCompile(`^(\d{4})[\-/](\d{1,2})$`),                // YYYY-MM
		regexp.MustCompile(`^(\d{4})(\d{2})$`),                       // YYYYMM (stored form)
		regexp.MustCompile(`^(\d{2})(\d{2})$`),                       // MMYY
	}
	digitsOnly = regexp.MustCompile(`^\d+$`)
)

// parseMonthYear accepts MM/YY, MM/YYYY, YYYY-MM, YYYYMM, and MMYY.
func parseMonthYear(value string) (month, year int, ok bool) {
	v := strings.TrimSpace(value)
	for i, re := range monthYearPatterns {
		m := re.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		month, year = a, b
		if i == 1 || i == 2 {
			month, year = b, a
		}
		if year < 100 {
			year += 2000
		}
		if month >= 1 && month <= 12 && year >= 1900 && year <= 2200 {
			return month, year, true
		}
	}
	return 0, 0, false
}

// normalizeTypedValue converts a value into the form Connect stores for a
// native field. Errors name the field, never the value.
func normalizeTypedValue(f templateField, value string) (string, error) {
	v := strings.TrimSpace(value)
	switch f.Type {
	case "CREDIT_CARD_NUMBER":
		digits := strings.NewReplacer(" ", "", "-", "").Replace(v)
		if !digitsOnly.MatchString(digits) || len(digits) < 12 || len(digits) > 19 {
			return "", fmt.Errorf("card number must be 12 to 19 digits (spaces and dashes are allowed)")
		}
		if !luhnValid(digits) {
			return "", fmt.Errorf("card number fails the Luhn checksum; check for a typo")
		}
		return digits, nil
	case "CREDIT_CARD_TYPE":
		code, ok := cardTypeAliases[normalizeLabel(v)]
		if !ok {
			return "", fmt.Errorf("card type must be one of: visa, mastercard, amex, discover, diners, jcb, unionpay, maestro")
		}
		return code, nil
	case "MONTH_YEAR":
		month, year, ok := parseMonthYear(v)
		if !ok {
			return "", fmt.Errorf("%s must be a month and year such as 08/27, 08/2027, or 2027-08", f.Label)
		}
		return fmt.Sprintf("%04d%02d", year, month), nil
	case "DATE":
		if digitsOnly.MatchString(v) && len(v) >= 9 {
			return v, nil // Unix seconds, as Connect returns them
		}
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return "", fmt.Errorf("%s must be a date as YYYY-MM-DD", f.Label)
		}
		return v, nil
	}
	if f.ID == "cvv" && (!digitsOnly.MatchString(v) || len(v) < 3 || len(v) > 4) {
		return "", fmt.Errorf("CVV must be 3 or 4 digits")
	}
	if f.ID == "pin" && (!digitsOnly.MatchString(v) || len(v) < 4 || len(v) > 12) {
		return "", fmt.Errorf("PIN must be 4 to 12 digits")
	}
	return v, nil
}

// ValidateTypedFields checks values against the category's native fields.
// Messages name fields, never values. Empty values are skipped: they are
// owner-entered fields that are checked once the approver types them.
func ValidateTypedFields(category string, values map[string]string) error {
	category = NormalizeCategory(category)
	seen := map[string]string{}
	for _, label := range sortedKeys(values) {
		f, ok := templateFieldFor(category, label)
		if !ok {
			continue
		}
		if other, dup := seen[f.ID]; dup {
			return &ValidationError{Message: fmt.Sprintf("fields %q and %q both set the %s", other, label, f.Label)}
		}
		seen[f.ID] = label
		if values[label] == "" {
			continue
		}
		if _, err := normalizeTypedValue(f, values[label]); err != nil {
			return &ValidationError{Message: err.Error()}
		}
	}
	return nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// typedField builds a Connect field for label in a native category.
func typedField(category, label, value string) (Field, bool, error) {
	f, ok := templateFieldFor(category, label)
	if !ok {
		return Field{}, false, nil
	}
	v, err := normalizeTypedValue(f, value)
	if err != nil {
		return Field{}, true, &ValidationError{Message: err.Error()}
	}
	field := Field{ID: f.ID, Label: f.Label, Type: f.Type, Value: v}
	if f.Section != nil {
		s := *f.Section
		field.Section = &s
	}
	return field, true, nil
}

// FieldType returns the Connect field type a label gets in category
// (CREDIT_CARD_NUMBER, CONCEALED, MONTH_YEAR, DATE, STRING, ...).
func FieldType(category, label string) string {
	if f, ok := templateFieldFor(NormalizeCategory(category), label); ok {
		return f.Type
	}
	f, _ := newField(category, label, "")
	return f.Type
}

// fillCardType sets the card type from the number when a new card has none.
func fillCardType(item *Item) {
	if item.Category != "CREDIT_CARD" {
		return
	}
	number := ""
	for _, f := range item.Fields {
		if f.ID == "type" && f.Value != "" {
			return
		}
		if f.Type == "CREDIT_CARD_NUMBER" {
			number = f.Value
		}
	}
	if code := detectCardType(number); code != "" {
		item.Fields = append(item.Fields, Field{ID: "type", Label: "type", Type: "CREDIT_CARD_TYPE", Value: code})
	}
}

// ensureSections declares every section a field refers to, so Connect
// accepts custom sections such as a card's billing address.
func ensureSections(item *Item) {
	have := make(map[string]bool, len(item.Sections))
	for _, s := range item.Sections {
		have[s.ID] = true
	}
	for _, f := range item.Fields {
		if f.Section != nil && f.Section.ID != "" && !have[f.Section.ID] {
			item.Sections = append(item.Sections, Section{ID: f.Section.ID, Label: f.Section.Label})
			have[f.Section.ID] = true
		}
	}
}

// CardSummary is the masked view of a card: no number beyond the last four
// digits, no CVV, no PIN. It is shown without approval.
type CardSummary struct {
	Type   string `json:"type,omitempty"`
	Last4  string `json:"last4,omitempty"`
	Expiry string `json:"expiry,omitempty"` // MM/YYYY
}

// String is the approver-facing description: "Mastercard ending 1100, expires 08/2027".
func (c *CardSummary) String() string {
	if c == nil {
		return ""
	}
	s := firstNonEmptyString(c.Type, "Card")
	if c.Last4 != "" {
		s += " ending " + c.Last4
	}
	if c.Expiry != "" {
		s += ", expires " + c.Expiry
	}
	return s
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// summarizeCard builds the masked view of a CREDIT_CARD item, or nil.
func summarizeCard(item *Item) *CardSummary {
	if item == nil || item.Category != "CREDIT_CARD" {
		return nil
	}
	c := &CardSummary{}
	code := ""
	for _, f := range item.Fields {
		switch {
		case f.Type == "CREDIT_CARD_NUMBER":
			digits := strings.NewReplacer(" ", "", "-", "").Replace(f.Value)
			if len(digits) >= 4 {
				c.Last4 = digits[len(digits)-4:]
			}
			if code == "" {
				code = detectCardType(digits)
			}
		case f.Type == "CREDIT_CARD_TYPE" && f.Value != "":
			code = f.Value
		case f.ID == "expiry":
			c.Expiry = presentMonthYear(f.Value)
		}
	}
	c.Type = CardTypeName(code)
	return c
}

func presentMonthYear(value string) string {
	month, year, ok := parseMonthYear(value)
	if !ok {
		return value
	}
	return fmt.Sprintf("%02d/%04d", month, year)
}

func presentDate(value string) string {
	secs, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return value
	}
	return time.Unix(secs, 0).UTC().Format("2006-01-02")
}

// isProcessOnly reports whether a field of item must never enter model context.
func isProcessOnly(category string, f Field) bool {
	if f.Type == "CREDIT_CARD_NUMBER" {
		return true
	}
	if category != "CREDIT_CARD" {
		return false
	}
	tf, ok := templateFieldFor(category, f.ID)
	return ok && tf.ID == f.ID && tf.ProcessOnly
}

// processOnlyMarker lists the value keys of item's process-only fields.
func processOnlyMarker(item *Item, keys map[string][]string) string {
	var out []string
	for _, f := range item.Fields {
		if isProcessOnly(item.Category, f) {
			out = append(out, keys[f.ID]...)
		}
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// SensitiveWriteCategory reports categories whose writes always need a tap
// on the request itself. Secure notes are not listed: SECURE_NOTE is the
// default for untyped writes, so they keep the write window and follow-up
// rules every other write has.
func SensitiveWriteCategory(category string) bool {
	switch category {
	case "CREDIT_CARD", "BANK_ACCOUNT":
		return true
	}
	return false
}

// ProcessOnlyFieldRequested reports whether a read of a card item releases
// a process-only value. An empty selection releases every field.
func ProcessOnlyFieldRequested(meta *ItemMeta, selectors []string) bool {
	if meta == nil || meta.Category != "CREDIT_CARD" {
		return false
	}
	var protected []FieldInfo
	for _, f := range meta.Fields {
		if isProcessOnly(meta.Category, Field{ID: f.ID, Type: f.Type}) {
			protected = append(protected, f)
		}
	}
	if len(protected) == 0 {
		return false
	}
	for _, s := range selectors {
		if strings.HasPrefix(s, models.AttachmentPrefix) {
			continue
		}
		n := normalizeLabel(s)
		for _, f := range protected {
			if n == normalizeLabel(f.ID) || n == normalizeLabel(f.Label) || (f.Section != "" && n == normalizeLabel(f.Section+"."+f.Label)) {
				return true
			}
			if tf, ok := templateFieldFor(meta.Category, s); ok && tf.ID == f.ID {
				return true
			}
		}
	}
	return len(selectors) == 0
}
