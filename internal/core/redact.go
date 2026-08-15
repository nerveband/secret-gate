package core

import (
	"sort"
	"strings"
)

// minRedactLen keeps trivially short field values (e.g. "1", "us") from
// shredding unrelated child-process output.
const minRedactLen = 4

type redaction struct {
	value string
	label string
}

// Redactor replaces exact occurrences of registered secret values in
// captured output with "[REDACTED:<label>]". It is the last line of
// defense when a child process echoes an injected secret.
type Redactor struct {
	entries []redaction
}

func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a secret value under a label such as "item/field".
func (r *Redactor) Add(value, label string) {
	if len(value) < minRedactLen {
		return
	}
	r.entries = append(r.entries, redaction{value: value, label: label})
}

// Redact replaces every exact occurrence of each registered value,
// longest value first so substrings of longer secrets keep the most
// specific label.
func (r *Redactor) Redact(s string) string {
	if len(r.entries) == 0 || s == "" {
		return s
	}
	sorted := make([]redaction, len(r.entries))
	copy(sorted, r.entries)
	sort.SliceStable(sorted, func(i, j int) bool {
		return len(sorted[i].value) > len(sorted[j].value)
	})
	for _, e := range sorted {
		s = strings.ReplaceAll(s, e.value, "[REDACTED:"+e.label+"]")
	}
	return s
}
