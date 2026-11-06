package core

import (
	"encoding/json"
	"fmt"
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
//
// When several keys match (a login's password field next to a saved
// web-form "Password" field), a non-empty value beats an empty one, then
// the field with the matching 1Password purpose (PASSWORD, USERNAME, NOTES)
// wins, a CONCEALED field wins for "password", and an exact key wins.
// Matches that still disagree fail; FieldAmbiguity names them.
func ResolveField(values map[string]string, wanted string) (string, string, bool) {
	matches, otpAlias := fieldMatches(values, wanted)
	if key, _, ok := pickField(values, wanted, matches); ok {
		return key, values[key], true
	}
	if len(matches) == 0 && otpAlias {
		if ids := OTPFieldIDs(values); len(ids) == 1 {
			return ids[0], values[ids[0]], true
		}
	}
	return "", "", false
}

// FieldAmbiguity reports a name that matches several fields with different
// values, or an OTP alias that matches several unlabeled OTP fields. It
// returns nil when the name is unknown or resolves.
func FieldAmbiguity(values map[string]string, wanted string) error {
	matches, otpAlias := fieldMatches(values, wanted)
	if _, left, ok := pickField(values, wanted, matches); !ok && len(left) > 1 {
		return E(ErrValidation, fmt.Sprintf("%q matches several fields with different values: %s", wanted, strings.Join(left, ", ")),
			"pass --field with the field ID or section-qualified label (section.label) from: secret-gate item fields")
	}
	if len(matches) == 0 && otpAlias {
		if ids := OTPFieldIDs(values); len(ids) > 1 {
			return E(ErrValidation, fmt.Sprintf("%q matches several OTP fields: %s", wanted, strings.Join(ids, ", ")),
				"pass --field <id> with one of the listed field IDs")
		}
	}
	return nil
}

// fieldMatches returns the non-reserved keys whose normalized name matches
// wanted or one of its aliases, and whether wanted is an OTP alias.
func fieldMatches(values map[string]string, wanted string) ([]string, bool) {
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
	var matches []string
	for name := range values {
		if !models.IsReservedKey(name) && aliases[normalizeFieldName(name)] {
			matches = append(matches, name)
		}
	}
	sort.Strings(matches)
	return matches, otpAlias
}

// pickField narrows sorted matches to one key. Without a single answer it
// returns the remaining candidates.
func pickField(values map[string]string, wanted string, matches []string) (string, []string, bool) {
	if len(matches) == 0 {
		return "", nil, false
	}
	meta := FieldMeta(values)
	c := prefer(matches, func(k string) bool { return values[k] != "" })
	var purpose string
	switch normalizeFieldName(wanted) {
	case "password":
		purpose = "PASSWORD"
	case "username":
		purpose = "USERNAME"
	case "note", "notes", "notesplain", "securenote":
		purpose = "NOTES"
	}
	if purpose != "" {
		c = prefer(c, func(k string) bool { return strings.EqualFold(meta[k].Purpose, purpose) })
	}
	if purpose == "PASSWORD" {
		c = prefer(c, func(k string) bool { return strings.EqualFold(meta[k].Type, "CONCEALED") })
	}
	c = prefer(c, func(k string) bool { return k == wanted })
	for _, k := range c[1:] {
		if values[k] != values[c[0]] {
			return "", c, false
		}
	}
	return c[0], nil, true
}

// prefer keeps the keys that satisfy ok, or all keys when none does.
func prefer(keys []string, ok func(string) bool) []string {
	var kept []string
	for _, k := range keys {
		if ok(k) {
			kept = append(kept, k)
		}
	}
	if len(kept) == 0 {
		return keys
	}
	return kept
}

// FieldMeta returns the field metadata the server attached to an item's
// values, keyed like the values. Items cached before the server sent it,
// or with unreadable metadata, return an empty map.
func FieldMeta(values map[string]string) map[string]models.FieldMeta {
	meta := map[string]models.FieldMeta{}
	if raw := values[models.FieldMetaKey]; raw != "" {
		_ = json.Unmarshal([]byte(raw), &meta)
	}
	return meta
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
// error hints. Values and reserved metadata keys are never included.
func FieldNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for k := range values {
		if !models.IsReservedKey(k) {
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
