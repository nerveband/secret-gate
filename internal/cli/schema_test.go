package cli

import (
	"strings"
	"testing"
)

func TestSchemaEnvelope(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"schema"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	cmds := data["commands"].([]interface{})
	if len(cmds) < 19 {
		t.Fatalf("manifest has %d commands, want >= 19", len(cmds))
	}
	if data["exit_codes"] == nil {
		t.Fatal("schema missing exit_codes")
	}
}

func TestAgentContextEnvelope(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"agent-context", "--json"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	for _, key := range []string{"binary", "version", "exit_codes", "visibility_classes", "workflow", "commands", "env"} {
		if data[key] == nil {
			t.Errorf("agent-context missing %q", key)
		}
	}
}

func TestManifestCoversRequiredCommands(t *testing.T) {
	names := map[string]bool{}
	for _, c := range Manifest() {
		names[c.Name] = true
	}
	required := []string{
		"item search", "item fields", "item read", "exec", "ssh",
		"otp show", "otp exec", "write create", "write update",
		"request submit", "request status", "request wait", "request cancel",
		"daemon status", "daemon start", "daemon flush", "daemon stop",
		"agent-context", "schema", "version",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("manifest missing command %q", name)
		}
	}
}

// TestManifestVocabulary is the mechanical enforcement of the canonical
// vocabulary (audit check 7.7): banned flags and verbs fail CI.
func TestManifestVocabulary(t *testing.T) {
	bannedFlags := map[string]bool{"force": true, "output": true, "silent": true, "yes": true, "format": true}
	bannedVerbs := map[string]bool{"info": true, "ls": true, "rm": true, "del": true, "delete": true, "get": true}
	for _, c := range Manifest() {
		for _, part := range strings.Fields(c.Name) {
			if bannedVerbs[part] {
				t.Errorf("command %q uses banned verb %q", c.Name, part)
			}
		}
		for _, f := range c.Flags {
			if bannedFlags[f.Name] {
				t.Errorf("command %q uses banned flag --%s", c.Name, f.Name)
			}
		}
		switch c.Visibility {
		case VisibilityMetadataOnly, VisibilityProcessOnly, VisibilityModelVisible, VisibilityValueInput:
		default:
			t.Errorf("command %q has invalid visibility %q", c.Name, c.Visibility)
		}
	}
}

// TestManifestSafetyMetadata: commands with side effects must declare
// dry-run support, and destructive ones must be flagged (audit 4.2, 4.6).
func TestManifestSafetyMetadata(t *testing.T) {
	specs := map[string]CommandSpec{}
	for _, c := range Manifest() {
		specs[c.Name] = c
	}
	for _, name := range []string{"exec", "ssh", "write create", "write update", "request submit", "daemon flush"} {
		if !specs[name].SupportsDryRun {
			t.Errorf("command %q must support --dry-run", name)
		}
	}
	if !specs["daemon flush"].Destructive {
		t.Error("daemon flush must be marked destructive")
	}
	for _, c := range Manifest() {
		if c.Destructive && !c.SupportsDryRun {
			t.Errorf("destructive command %q must support --dry-run", c.Name)
		}
	}
}

// TestManifestMatchesRouterAndHelp: every manifest command is routable
// and has human help with examples (audit checks 1.2, 1.3, 8.7).
func TestManifestMatchesRouterAndHelp(t *testing.T) {
	for _, c := range Manifest() {
		if c.Name == "version" || c.Name == "schema" || c.Name == "agent-context" {
			continue // no flag sets; covered by their own tests
		}
		if _, ok := usageText[c.Name]; !ok {
			t.Errorf("command %q has no usageText entry", c.Name)
			continue
		}
		if !strings.Contains(usageText[c.Name], "secret-gate "+c.Name) {
			t.Errorf("usageText for %q lacks a concrete example", c.Name)
		}
		ta := newTestApp(t)
		args := append(strings.Fields(c.Name), "--help")
		if code := ta.app.Run(args); code != ExitOK {
			t.Errorf("`secret-gate %s --help` exited %d", c.Name, code)
		}
	}
}
