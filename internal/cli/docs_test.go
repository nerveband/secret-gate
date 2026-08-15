package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSkillCommandsExistInManifest parses every `secret-gate ...` line in
// fenced code blocks of skills/secret-gate/SKILL.md and asserts the
// command path exists in the live manifest (audit check 8.7).
func TestSkillCommandsExistInManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "skills", "secret-gate", "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md not readable: %v", err)
	}

	valid := map[string]bool{"mcp": true, "daemon run": true}
	for _, c := range Manifest() {
		valid[c.Name] = true
	}

	inFence := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if !inFence {
			continue
		}
		idx := strings.Index(trimmed, "secret-gate ")
		if idx != 0 { // only lines that invoke the binary directly
			continue
		}
		tokens := strings.Fields(trimmed)[1:]
		var path []string
		for _, tok := range tokens {
			if strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "$\"'|<>") {
				break
			}
			path = append(path, tok)
			if len(path) == 2 {
				break
			}
		}
		if len(path) == 0 {
			// A bare `secret-gate --flag ...` line is the removed
			// legacy invocation — docs must never teach it.
			t.Errorf("SKILL.md documents the removed legacy flag invocation: %s", trimmed)
			continue
		}
		// Accept the longest matching prefix (1 or 2 tokens).
		if valid[strings.Join(path, " ")] || valid[path[0]] {
			continue
		}
		t.Errorf("SKILL.md documents unknown command: %q (line: %s)", strings.Join(path, " "), trimmed)
	}
}
