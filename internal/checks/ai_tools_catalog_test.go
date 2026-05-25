package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func TestAIToolCatalogContainsHermesOpenCodeGeminiAntigravityAndQwen(t *testing.T) {
	defs := AIToolDefinitions("/Users/alice")
	ids := map[string]bool{}
	binaries := map[string][]string{}
	for _, def := range defs {
		ids[def.ID] = true
		binaries[def.ID] = def.BinaryNames
	}
	for _, id := range []string{"hermes-agent", "opencode", "gemini-cli", "google-antigravity", "qwen-code"} {
		if !ids[id] {
			t.Fatalf("expected catalog id %s", id)
		}
	}
	if !containsAnyPattern(strings.Join(binaries["gemini-cli"], ","), []string{"gemini"}) {
		t.Fatal("expected Gemini CLI to own the gemini binary")
	}
	if containsAnyPattern(strings.Join(binaries["google-antigravity"], ","), []string{"gemini"}) {
		t.Fatal("Antigravity should not be detected from the Gemini CLI binary alone")
	}
	if !containsAnyPattern(strings.Join(binaries["google-antigravity"], ","), []string{"agy"}) {
		t.Fatal("expected Antigravity CLI agy binary")
	}
}

func TestHermesPathDetection(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".hermes", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := audit.RuntimeConfig{HomeDir: home, MaxFileSizeMB: 5}
	info := detectHermesAgent(cfg)
	if !info.Detected {
		t.Fatal("expected Hermes to be detected")
	}
	if info.ContextImpact != "high" {
		t.Fatalf("expected high context impact, got %s", info.ContextImpact)
	}
}

func TestOpenCodePathDetection(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".opencode", "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := audit.RuntimeConfig{HomeDir: home, MaxFileSizeMB: 5}
	info := detectOpenCode(cfg)
	if !info.Detected {
		t.Fatal("expected OpenCode to be detected")
	}
	if len(info.AgentPaths) != 1 {
		t.Fatalf("expected one OpenCode agent path, got %d", len(info.AgentPaths))
	}
}

func TestChineseProviderDefinitionsIncludeFamilies(t *testing.T) {
	defs := ChineseProviderDefinitions("/Users/alice")
	foundDeepSeek := false
	foundQwenEnv := false
	for _, def := range defs {
		if def.ID == "deepseek" && containsAnyPattern(strings.Join(def.Families, ","), []string{"deepseek-r1"}) {
			foundDeepSeek = true
		}
		if def.ID == "qwen" && containsAnyPattern(strings.Join(def.APIEnvKeys, ","), []string{"DASHSCOPE_API_KEY"}) {
			foundQwenEnv = true
		}
	}
	if !foundDeepSeek || !foundQwenEnv {
		t.Fatalf("expected DeepSeek family and Qwen env definitions")
	}
}

func TestProviderEnvKeyMasking(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "real-secret-value")
	keys := detectedEnvKeys([]string{"DEEPSEEK_API_KEY"})
	if len(keys) != 1 || keys[0] != "DEEPSEEK_API_KEY=***MASKED***" {
		t.Fatalf("unexpected masked env keys: %v", keys)
	}
}

func TestProviderOriginAloneIsNotRisk(t *testing.T) {
	if got := ClassifyProviderUsageRisk(true, false, false, false, false); got != "info" {
		t.Fatalf("origin alone should be info, got %s", got)
	}
}

func TestRemoteProviderWithBroadToolsIsHighRisk(t *testing.T) {
	if got := ClassifyProviderUsageRisk(false, true, true, true, true); got != "high" {
		t.Fatalf("remote provider plus broad tools should be high, got %s", got)
	}
}

func TestMCPServerRiskCategoryMapping(t *testing.T) {
	cases := map[string]string{
		"desktop-commander": "filesystem_shell",
		"playwright":        "browser_automation",
		"postgres":          "database",
		"aws":               "cloud_infra",
		"github":            "github_git",
	}
	for name, expected := range cases {
		if got := MCPServerRiskCategory(name, "", nil); got != expected {
			t.Fatalf("expected %s for %s, got %s", expected, name, got)
		}
	}
}

func TestLocalModelInventoryNeverAutoClean(t *testing.T) {
	home := t.TempDir()
	modelDir := filepath.Join(home, ".ollama", "models")
	if err := os.MkdirAll(modelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modelDir, "qwen-model.bin"), []byte("model"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := audit.RuntimeConfig{HomeDir: home, MaxFileSizeMB: 5}
	items := detectLocalModelInventory(cfg, nil)
	if len(items) == 0 {
		t.Fatal("expected local model inventory item")
	}
	if items[0].SafeToAutoClean {
		t.Fatal("model caches must never be auto-clean")
	}
}
