package core

import (
	"sort"
	"strings"
)

// ResolveField finds a field by label, ignoring case, spaces, hyphens,
// and underscores. OTP aliases (otp/totp/mfa/2fa/one-time password) and
// note aliases (note/notes/notesPlain/secure note) are interchangeable.
func ResolveField(values map[string]string, wanted string) (string, string, bool) {
	normalize := func(s string) string {
		return strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(s)))
	}
	w := normalize(wanted)
	aliases := map[string]bool{}
	switch w {
	case "otp", "totp", "mfa", "2fa", "onetimepassword":
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
		if aliases[normalize(name)] {
			return name, value, true
		}
	}
	return "", "", false
}

// FieldNames returns the sorted field labels of a cached item, for use in
// error hints. Values are never included.
func FieldNames(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
