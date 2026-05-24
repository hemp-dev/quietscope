package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
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

func TestUnpinnedLauncherDetection(t *testing.T) {
	cases := []struct {
		cmd      string
		args     []string
		expected audit.Severity
	}{
		{"npx", []string{"some-server@latest"}, audit.SeverityHigh},
		{"uvx", []string{"some-server"}, audit.SeverityHigh},       // unpinned
		{"bunx", []string{"some-server@1.2.3"}, audit.SeverityLow}, // pinned
		{"pipx", []string{"run", "some-server@latest"}, audit.SeverityHigh},
	}
	for _, c := range cases {
		sev, _, _, _, _ := ClassifyMCPCommandRisk(c.cmd, c.args)
		if sev != c.expected {
			t.Fatalf("expected %s for %s %v, got %s", c.expected, c.cmd, c.args, sev)
		}
	}
}

func TestClassifyMCPCapability(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		args     []string
		expected string
	}{
		{"bash-launcher", "bash", []string{"-c"}, "Terminal / Shell command execution (Excessive Agency risk)"},
		{"filesystem-server", "node", []string{"fs-server.js"}, "Filesystem write or read access (Excessive Agency risk)"},
		{"playwright", "npx", []string{"playwright-mcp"}, "Browser automation (Indirect prompt injection / Data leak risk)"},
		{"db-accessor", "postgres-server", []string{}, "Database access (Direct file or data tampering risk)"},
	}
	for _, c := range cases {
		capName, _ := ClassifyMCPCapability(c.name, c.cmd, c.args)
		if !strings.Contains(capName, c.expected) {
			t.Fatalf("expected cap containing %q for %s/%s, got %q", c.expected, c.name, c.cmd, capName)
		}
	}
}

func TestScanConfigForAutoApproval(t *testing.T) {
	data := []byte(`{
		"agent": {
			"tool_permissions": {
				"default": "allow"
			}
		},
		"auto_execute": true
	}`)
	reason, sev := scanConfigForAutoApproval("settings.json", data)
	if reason == "" || sev != audit.SeverityHigh {
		t.Fatalf("expected auto-approval warning, got reason=%q sev=%s", reason, sev)
	}
}

func TestDockerComposeScanning(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "docker-compose.yml")
	content := `
version: '3'
services:
  ollama:
    image: ollama/ollama
    ports:
      - "11434:11434"
`
	if err := os.WriteFile(composePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := audit.RuntimeConfig{ProjectRoot: dir}
	findings := inspectDockerComposeAI(cfg)
	if len(findings) != 1 || !strings.Contains(findings[0].Title, "Containerized AI stack") {
		t.Fatalf("expected 1 docker port finding, got %#v", findings)
	}
}
