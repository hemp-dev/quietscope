package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectauthors/quietscope/internal/audit"
)

func TestDangerousCommandPatternMatching(t *testing.T) {
	cases := []string{"bash -c whoami", "node -e 'console.log(1)'", "curl https://example.invalid", "chmod 777 /tmp/x"}
	for _, input := range cases {
		if !IsDangerousCommandPattern(input) {
			t.Fatalf("expected dangerous pattern for %q", input)
		}
	}
	if IsDangerousCommandPattern("node server.js --stdio") {
		t.Fatalf("expected benign command to avoid dangerous classification")
	}
}

func TestMCPCommandRiskClassification(t *testing.T) {
	severity, _, dataRisk, commandRisk, networkRisk := ClassifyMCPCommandRisk("bash", []string{"-c", "curl http://127.0.0.1"})
	if severity != audit.SeverityHigh || !commandRisk || !networkRisk || dataRisk {
		t.Fatalf("unexpected shell/network classification: %s data=%t command=%t network=%t", severity, dataRisk, commandRisk, networkRisk)
	}
	severity, _, dataRisk, commandRisk, _ = ClassifyMCPCommandRisk("node", []string{"server.js", "--config", "~/.ssh/id_ed25519"})
	if severity != audit.SeverityHigh || !dataRisk || commandRisk {
		t.Fatalf("unexpected secret-path classification: %s data=%t command=%t", severity, dataRisk, commandRisk)
	}
	severity, _, _, commandRisk, _ = ClassifyMCPCommandRisk("node", []string{"server.js"})
	if severity != audit.SeverityInfo || commandRisk {
		t.Fatalf("unexpected benign classification: %s command=%t", severity, commandRisk)
	}
}

func TestParseMCPConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := map[string]any{
		"mcpServers": map[string]any{
			"demo": map[string]any{"command": "npx", "args": []string{"demo-server@1.2.3"}},
		},
	}
	data, _ := json.Marshal(body)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	commands, err := parseMCPConfig(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0].Name != "demo" || commands[0].Command != "npx" {
		t.Fatalf("unexpected parsed commands: %#v", commands)
	}
}

func TestCrossPlatformAIConfigCandidates(t *testing.T) {
	cfg := audit.RuntimeConfig{HomeDir: "/home/alice"}
	linuxPaths := strings.Join(aiConfigPathsForOS("linux", cfg), "\n")
	for _, expected := range []string{
		"/home/alice/.config/Code",
		"/home/alice/.config/Cursor",
		"/home/alice/.opencode",
	} {
		if !strings.Contains(linuxPaths, expected) {
			t.Fatalf("expected Linux AI config path %s in %s", expected, linuxPaths)
		}
	}

	cfg = audit.RuntimeConfig{HomeDir: `C:\Users\Alice`}
	windowsPaths := strings.Join(candidateMCPPathsForOS("windows", cfg), "\n")
	for _, expected := range []string{
		filepath.Join(`C:\Users\Alice`, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		filepath.Join(`C:\Users\Alice`, "AppData", "Roaming", "Cursor", "User", "mcp.json"),
	} {
		if !strings.Contains(windowsPaths, expected) {
			t.Fatalf("expected Windows MCP path %s in %s", expected, windowsPaths)
		}
	}
}
