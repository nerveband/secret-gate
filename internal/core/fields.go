package core

import (
	"sort"
	"strings"

	"github.com/johnuopini/secret-gate/internal/models"
)

// OTPFieldKeyPrefix marks the key of a 1Password OTP-type field. Fields keep
// their stable ID as a key, and the server guarantees every OTP-type field
// is reachable under a key with this prefix, whatever its label.
const OTPFieldKeyPrefix = "TOTP_"

// ResolveField finds a field by label, ignoring case, spaces, hyphens,
// and underscores. OTP aliases (otp/totp/mfa/2fa/one-time password) and
// note aliases (note/notes/notesPlain/secure note) are interchangeable.
// OTP aliases that match no label fall back to the item's single OTP-type
// field; with several, resolution fails and OTPFieldIDs lists them.
func ResolveField(values map[string]string, wanted string) (string, string, bool) {
	w := normalizeFieldName(wanted)
	aliases := map[string]bool{}
	otpAlias := false
	switch w {
	case "otp", "totp", "mfa", "2fa", "onetimepassword":
		otpAlias = true
		for _, a := range []string{"otp", "totp", "mfa", "2fa", "onetimepassword"} {
			aliases[a] = true
		}
	case "note", "notes", "notesplain", "securenote":
		for _, a := range []string{"note", "notes", "notesplain", "securenote"} {
			aliases[a] = true
		}
	default:
		aliases[w] = true
	}
	for name, value := range values {
		if aliases[normalizeFieldName(name)] {
			return name, value, true
		}
	}
	if otpAlias {
		if ids := OTPFieldIDs(values); len(ids) == 1 {
			return ids[0], values[ids[0]], true
		}
	}
	return "", "", false
}

// OTPFieldIDs returns the sorted keys of the item's distinct OTP-type fields.
func OTPFieldIDs(values map[string]string) []string {
	var ids []string
	for k := range values {
		if strings.HasPrefix(k, OTPFieldKeyPrefix) {
			ids = append(ids, k)
		}
	}
	sort.Strings(ids)
	return ids
}

func normalizeFieldName(s string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// FieldNames returns the sorted field labels of a cached item, for use in
// error hints. Values and the reserved process-only marker are never included.
func FieldNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for k := range values {
		if k != ProcessOnlyKey {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	return names
}

// ProcessOnlyKey is the reserved key under which the server lists the
// value keys that must never enter model context (card number, CVV, PIN).
const ProcessOnlyKey = models.ProcessOnlyKey

// ProcessOnlyKeys returns the keys of values that may reach a child process
// or a browser field but never model context.
func ProcessOnlyKeys(values map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, k := range strings.Split(values[ProcessOnlyKey], ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = true
		}
	}
	return out
}
