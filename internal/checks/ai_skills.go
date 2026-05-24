package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
	"github.com/projectauthors/quietscope/internal/safety"
)

type aiArtifactCandidate struct {
	Path         string
	ArtifactType string
	ToolName     string
	Scope        string
}

type aiDirectoryCandidate struct {
	Path     string
	ToolName string
	Category string
}

func RunAISkillsContext(ctx context.Context, cfg audit.RuntimeConfig) (audit.CheckResult, error) {
	_ = ctx
	artifacts := collectAIContextArtifacts(cfg)
	directories := collectAIRelatedDirectories(cfg)
	skills := filterAISkills(artifacts)
	summary := CalculateAIContextSummary(artifacts, directories)
	findings := aiContextFindings(artifacts, directories, summary)
	return audit.CheckResult{
		Findings:             findings,
		AIContextInventory:   artifacts,
		AIRelatedDirectories: directories,
		AISkills:             skills,
		AIContextSummary:     summary,
	}, nil
}

func collectAIContextArtifacts(cfg audit.RuntimeConfig) []audit.AIContextArtifact {
	candidates := candidateAIArtifacts(cfg)
	seen := map[string]bool{}
	var artifacts []audit.AIContextArtifact
	for _, candidate := range candidates {
		candidate.Path = platform.ExpandHome(candidate.Path, cfg.HomeDir)
		if candidate.Path == "" || seen[candidate.Path] {
			continue
		}
		seen[candidate.Path] = true
		artifact, ok := buildAIContextArtifact(candidate, cfg)
		if ok {
			artifacts = append(artifacts, artifact)
		}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].ContextImpactScore == artifacts[j].ContextImpactScore {
			return artifacts[i].Path < artifacts[j].Path
		}
		return artifacts[i].ContextImpactScore > artifacts[j].ContextImpactScore
	})
	return artifacts
}

func candidateAIArtifacts(cfg audit.RuntimeConfig) []aiArtifactCandidate {
	var out []aiArtifactCandidate
	add := func(path, artifactType, tool, scope string) {
		out = append(out, aiArtifactCandidate{Path: path, ArtifactType: artifactType, ToolName: tool, Scope: scope})
	}

	home := cfg.HomeDir
	add(filepath.Join(home, ".claude", "skills"), "skill", "Claude", "user")
	add(filepath.Join(home, ".claude", "commands"), "instruction", "Claude", "user")
	add(filepath.Join(home, ".claude", "memory"), "memory", "Claude", "user")
	add(filepath.Join(home, ".claude", "settings.json"), "settings", "Claude", "user")
	add(filepath.Join(home, ".claude.json"), "settings", "Claude", "user")
	add(filepath.Join(home, ".codex"), "generic_context", "Codex", "user")
	add(filepath.Join(home, ".codex", "config.toml"), "settings", "Codex", "user")
	add(filepath.Join(home, ".codex", "instructions.md"), "instruction", "Codex", "user")
	add(filepath.Join(home, ".cursor"), "generic_context", "Cursor", "user")
	add(filepath.Join(home, ".cursor", "rules"), "rule", "Cursor", "user")
	add(filepath.Join(home, ".cursor", "mcp.json"), "mcp_config", "Cursor", "user")
	add(filepath.Join(home, ".continue"), "generic_context", "Continue", "user")
	add(filepath.Join(home, ".cline"), "generic_context", "Cline", "user")
	add(filepath.Join(home, ".roo"), "generic_context", "Roo", "user")
	add(filepath.Join(home, ".windsurf"), "generic_context", "Windsurf", "user")
	add(filepath.Join(home, ".open-interpreter"), "generic_context", "Open Interpreter", "user")
	add(filepath.Join(home, ".hermes"), "generic_context", "Hermes", "user")
	add(filepath.Join(home, ".hermes", "skills"), "skill", "Hermes", "user")
	add(filepath.Join(home, ".hermes", "memory"), "memory", "Hermes", "user")
	add(filepath.Join(home, ".hermes", "commands"), "instruction", "Hermes", "user")
	add(filepath.Join(home, ".hermes-agent"), "generic_context", "Hermes", "user")
	add(filepath.Join(home, ".hermes-agent", "skills"), "skill", "Hermes", "user")
	add(filepath.Join(home, ".hermes-agent", "memory"), "memory", "Hermes", "user")
	add(filepath.Join(home, ".hermes-agent", "commands"), "instruction", "Hermes", "user")
	add(filepath.Join(home, ".opencode"), "generic_context", "OpenCode", "user")
	add(filepath.Join(home, ".opencode", "agents"), "agent_manifest", "OpenCode", "user")
	add(filepath.Join(home, ".opencode", "agent"), "agent_manifest", "OpenCode", "user")
	add(filepath.Join(home, ".opencode", "prompts"), "prompt", "OpenCode", "user")
	add(filepath.Join(home, ".opencode", "rules"), "rule", "OpenCode", "user")
	add(filepath.Join(home, ".opencode", "skills"), "skill", "OpenCode", "user")

	for _, root := range projectRoots(cfg) {
		addProjectAIArtifacts(root, &out)
		if cfg.Deep {
			out = append(out, discoverDeepProjectAIArtifacts(root, cfg)...)
		}
	}
	return out
}

func addProjectAIArtifacts(root string, out *[]aiArtifactCandidate) {
	add := func(rel, artifactType, tool string) {
		*out = append(*out, aiArtifactCandidate{Path: filepath.Join(root, rel), ArtifactType: artifactType, ToolName: tool, Scope: "project"})
	}
	add("CLAUDE.md", "instruction", "Claude")
	add(filepath.Join(".claude"), "generic_context", "Claude")
	add(filepath.Join(".claude", "skills"), "skill", "Claude")
	add(filepath.Join(".claude", "commands"), "instruction", "Claude")
	add("AGENTS.md", "instruction", "Codex")
	add(filepath.Join(".codex"), "generic_context", "Codex")
	add(filepath.Join(".codex", "instructions.md"), "instruction", "Codex")
	add(filepath.Join(".cursor"), "generic_context", "Cursor")
	add(filepath.Join(".cursor", "rules"), "rule", "Cursor")
	add(filepath.Join(".cursor", "mcp.json"), "mcp_config", "Cursor")
	add(".cursorrules", "rule", "Cursor")
	add(filepath.Join(".github", "copilot-instructions.md"), "instruction", "Copilot")
	add(filepath.Join(".vscode", "settings.json"), "settings", "VS Code")
	add(filepath.Join(".vscode", "extensions.json"), "settings", "VS Code")
	add(filepath.Join(".vscode", "mcp.json"), "mcp_config", "VS Code")
	add(filepath.Join(".continue"), "generic_context", "Continue")
	add(filepath.Join(".cline"), "generic_context", "Cline")
	add(filepath.Join(".roo"), "generic_context", "Roo")
	add(filepath.Join(".windsurf"), "generic_context", "Windsurf")
	add(".windsurfrules", "rule", "Windsurf")
	add(".aider.conf.yml", "settings", "Aider")
	add(".aiderignore", "settings", "Aider")
	add(filepath.Join(".open-interpreter"), "generic_context", "Open Interpreter")
	add(filepath.Join(".hermes"), "generic_context", "Hermes")
	add(filepath.Join(".hermes-agent"), "generic_context", "Hermes")
	add(filepath.Join(".hermes", "skills"), "skill", "Hermes")
	add(filepath.Join(".hermes-agent", "skills"), "skill", "Hermes")
	add(filepath.Join(".hermes", "memory"), "memory", "Hermes")
	add(filepath.Join(".hermes-agent", "memory"), "memory", "Hermes")
	add(filepath.Join(".hermes", "commands"), "instruction", "Hermes")
	add(filepath.Join(".hermes-agent", "commands"), "instruction", "Hermes")
	add("hermes.json", "settings", "Hermes")
	add("hermes.yaml", "settings", "Hermes")
	add("hermes.yml", "settings", "Hermes")
	add("hermes.toml", "settings", "Hermes")
	add("hermes-agent.json", "settings", "Hermes")
	add("hermes-agent.yaml", "settings", "Hermes")
	add(filepath.Join(".opencode"), "generic_context", "OpenCode")
	add(filepath.Join(".opencode", "agents"), "agent_manifest", "OpenCode")
	add(filepath.Join(".opencode", "agent"), "agent_manifest", "OpenCode")
	add(filepath.Join(".opencode", "prompts"), "prompt", "OpenCode")
	add(filepath.Join(".opencode", "rules"), "rule", "OpenCode")
	add(filepath.Join(".opencode", "skills"), "skill", "OpenCode")
	add("opencode.json", "settings", "OpenCode")
	add("opencode.yaml", "settings", "OpenCode")
	add("opencode.yml", "settings", "OpenCode")
	add("opencode.toml", "settings", "OpenCode")
	add(".opencode.json", "settings", "OpenCode")
	add(".opencode.yaml", "settings", "OpenCode")
	add("AI.md", "generic_context", "Generic")
	add("PROMPTS.md", "prompt", "Generic")
	add("SYSTEM_PROMPT.md", "prompt", "Generic")
	add("instructions.md", "instruction", "Generic")
	add("rules.md", "rule", "Generic")
	add("agent.md", "agent_manifest", "Generic")
	add(filepath.Join("agents"), "generic_context", "Generic")
	add(filepath.Join("skills"), "skill", "Generic")
	add(filepath.Join("prompts"), "prompt", "Generic")
	add(filepath.Join("rules"), "rule", "Generic")
	add(filepath.Join("tools"), "tool_manifest", "Generic")
	add("mcp.json", "mcp_config", "Generic")
	add("tool_manifest.json", "tool_manifest", "Generic")
	add("manifest.json", "agent_manifest", "Generic")
	add("agent.json", "agent_manifest", "Generic")
	add("skill.json", "skill", "Generic")

	if matches, err := filepath.Glob(filepath.Join(root, ".aider*")); err == nil {
		for _, match := range matches {
			*out = append(*out, aiArtifactCandidate{Path: match, ArtifactType: "settings", ToolName: "Aider", Scope: "project"})
		}
	}
	*out = append(*out, discoverVSCodeReferencedInstructions(root)...)
}

func discoverVSCodeReferencedInstructions(root string) []aiArtifactCandidate {
	settingsPath := filepath.Join(root, ".vscode", "settings.json")
	info, err := os.Stat(settingsPath)
	if err != nil || info.IsDir() || info.Size() > 1024*1024 {
		return nil
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var candidates []aiArtifactCandidate
	var walk func(any)
	walk = func(value any) {
		switch x := value.(type) {
		case map[string]any:
			for _, v := range x {
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		case string:
			if !looksLikeInstructionReference(x) {
				return
			}
			path := x
			if !filepath.IsAbs(path) {
				path = filepath.Join(root, path)
			}
			if rel, err := filepath.Rel(root, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				artifactType, tool, ok := classifyAIArtifactPath(path, false)
				if !ok {
					artifactType = "instruction"
					tool = "VS Code"
				}
				candidates = append(candidates, aiArtifactCandidate{Path: path, ArtifactType: artifactType, ToolName: tool, Scope: "project"})
			}
		}
	}
	walk(raw)
	return candidates
}

func looksLikeInstructionReference(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") || strings.Contains(lower, "${") {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	if !(strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".json")) {
		return false
	}
	return strings.Contains(base, "instruction") || strings.Contains(base, "prompt") || strings.Contains(base, "rule") || strings.Contains(base, "agent") || strings.Contains(base, "skill")
}

func discoverDeepProjectAIArtifacts(root string, cfg audit.RuntimeConfig) []aiArtifactCandidate {
	var out []aiArtifactCandidate
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipAIInventoryPath(path, d, cfg.HomeDir) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil || rel == "." {
			return nil
		}
		artifactType, tool, ok := classifyAIArtifactPath(path, d.IsDir())
		if ok {
			out = append(out, aiArtifactCandidate{Path: path, ArtifactType: artifactType, ToolName: tool, Scope: "project"})
		}
		return nil
	})
	return out
}

func buildAIContextArtifact(candidate aiArtifactCandidate, cfg audit.RuntimeConfig) (audit.AIContextArtifact, bool) {
	meta, err := platform.StatMeta(candidate.Path)
	if err != nil {
		return audit.AIContextArtifact{}, false
	}
	info, err := os.Lstat(candidate.Path)
	if err != nil {
		return audit.AIContextArtifact{}, false
	}
	fileCount := 0
	size := meta.Size
	if info.IsDir() {
		stats := aiDirectoryStats(candidate.Path, cfg.HomeDir)
		fileCount = stats.FileCount
		size = stats.SizeBytes
	}
	hasMCPToolExecution := false
	hasMCPNetworkRisk := false
	if candidate.ArtifactType == "mcp_config" && !info.IsDir() {
		if commands, err := parseMCPConfig(candidate.Path, cfg.MaxFileSizeMB); err == nil {
			for _, command := range commands {
				_, _, _, commandRisk, networkRisk := ClassifyMCPCommandRisk(command.Command, command.Args)
				hasMCPToolExecution = hasMCPToolExecution || commandRisk
				hasMCPNetworkRisk = hasMCPNetworkRisk || networkRisk
			}
		}
	}

	var patterns []audit.AIContextPattern
	hasPromptPatterns := false
	hasToolPatterns := hasMCPToolExecution
	hasNetworkPatterns := hasMCPNetworkRisk
	if cfg.Deep && !info.IsDir() && isScannableAIArtifact(candidate.Path, candidate.ArtifactType) {
		patterns = ScanAISuspiciousPromptPatterns(candidate.Path, cfg.MaxFileSizeMB)
		hasPromptPatterns = len(patterns) > 0
		for _, pattern := range patterns {
			if IsAIToolExecutionPattern(pattern.Pattern) {
				hasToolPatterns = true
			}
			if IsAINetworkExfiltrationPattern(pattern.Pattern) {
				hasNetworkPatterns = true
			}
		}
	}

	autoLoaded := EstimateAutoLoadedLikelihood(candidate.Path, candidate.ArtifactType, candidate.ToolName, candidate.Scope)
	impact, score := ClassifyAIContextImpact(candidate.Path, candidate.ArtifactType, candidate.ToolName, candidate.Scope, info.IsDir(), platform.IsWorldWritable(meta.Mode), platform.IsGroupWritable(meta.Mode), hasMCPToolExecution)
	recommendation := AIContextRecommendation(candidate.ArtifactType, candidate.ToolName, impact, info.IsDir(), hasPromptPatterns || hasToolPatterns || hasNetworkPatterns)
	return audit.AIContextArtifact{
		Path:                                candidate.Path,
		ArtifactType:                        candidate.ArtifactType,
		ToolName:                            candidate.ToolName,
		Scope:                               candidate.Scope,
		SizeBytes:                           size,
		FileCount:                           fileCount,
		LastModified:                        meta.ModTime.Format("2006-01-02T15:04:05"),
		Owner:                               fmt.Sprintf("%d:%d", meta.UID, meta.GID),
		Permissions:                         platform.FormatPerm(meta.Mode),
		IsWorldWritable:                     platform.IsWorldWritable(meta.Mode),
		IsGroupWritable:                     platform.IsGroupWritable(meta.Mode),
		IsHidden:                            isHiddenPath(candidate.Path),
		IsProjectLocal:                      candidate.Scope == "project",
		AutoLoadedLikelihood:                autoLoaded,
		ContextImpact:                       impact,
		ContextImpactScore:                  score,
		ContainsSuspiciousPromptPatterns:    hasPromptPatterns,
		ContainsToolExecutionPatterns:       hasToolPatterns,
		ContainsNetworkExfiltrationPatterns: hasNetworkPatterns,
		Recommendation:                      recommendation,
		SuspiciousPatterns:                  patterns,
	}, true
}

func collectAIRelatedDirectories(cfg audit.RuntimeConfig) []audit.AIRelatedDirectory {
	candidates := candidateAIDirectories(cfg.HomeDir)
	seen := map[string]bool{}
	var directories []audit.AIRelatedDirectory
	for _, candidate := range candidates {
		if candidate.Path == "" || seen[candidate.Path] {
			continue
		}
		seen[candidate.Path] = true
		meta, err := platform.StatMeta(candidate.Path)
		if err != nil {
			continue
		}
		stats := aiDirectoryStats(candidate.Path, cfg.HomeDir)
		impact, score := ClassifyAIDirectoryImpact(candidate.Path, candidate.Category)
		cleanupCandidate := candidate.Category == "cache" || candidate.Category == "logs"
		directories = append(directories, audit.AIRelatedDirectory{
			Path:               candidate.Path,
			ToolName:           candidate.ToolName,
			Category:           candidate.Category,
			SizeBytes:          stats.SizeBytes,
			HumanSize:          platform.HumanBytes(stats.SizeBytes),
			FileCount:          stats.FileCount,
			LastModified:       meta.ModTime.Format("2006-01-02T15:04:05"),
			Permissions:        platform.FormatPerm(meta.Mode),
			ContextImpact:      impact,
			ContextImpactScore: score,
			CleanupCandidate:   cleanupCandidate,
			SafeToAutoClean:    false,
			Recommendation:     AIDirectoryRecommendation(candidate.Category, candidate.ToolName),
		})
	}
	sort.Slice(directories, func(i, j int) bool {
		return directories[i].SizeBytes > directories[j].SizeBytes
	})
	return directories
}

func candidateAIDirectories(home string) []aiDirectoryCandidate {
	return []aiDirectoryCandidate{
		{filepath.Join(home, ".claude"), "Claude", "config"},
		{filepath.Join(home, ".claude", "skills"), "Claude", "skills"},
		{filepath.Join(home, ".claude", "commands"), "Claude", "prompts"},
		{filepath.Join(home, ".codex"), "Codex", "config"},
		{filepath.Join(home, ".cursor"), "Cursor", "config"},
		{filepath.Join(home, ".cursor", "rules"), "Cursor", "rules"},
		{filepath.Join(home, ".continue"), "Continue", "config"},
		{filepath.Join(home, ".cline"), "Cline", "config"},
		{filepath.Join(home, ".roo"), "Roo", "config"},
		{filepath.Join(home, ".windsurf"), "Windsurf", "config"},
		{filepath.Join(home, ".hermes"), "Hermes", "config"},
		{filepath.Join(home, ".hermes", "skills"), "Hermes", "skills"},
		{filepath.Join(home, ".hermes", "commands"), "Hermes", "prompts"},
		{filepath.Join(home, ".hermes", "memory"), "Hermes", "prompts"},
		{filepath.Join(home, ".hermes-agent"), "Hermes", "config"},
		{filepath.Join(home, ".hermes-agent", "skills"), "Hermes", "skills"},
		{filepath.Join(home, ".hermes-agent", "commands"), "Hermes", "prompts"},
		{filepath.Join(home, ".hermes-agent", "memory"), "Hermes", "prompts"},
		{filepath.Join(home, ".opencode"), "OpenCode", "config"},
		{filepath.Join(home, ".opencode", "agents"), "OpenCode", "prompts"},
		{filepath.Join(home, ".opencode", "agent"), "OpenCode", "prompts"},
		{filepath.Join(home, ".opencode", "prompts"), "OpenCode", "prompts"},
		{filepath.Join(home, ".opencode", "rules"), "OpenCode", "rules"},
		{filepath.Join(home, ".opencode", "skills"), "OpenCode", "skills"},
		{filepath.Join(home, ".ollama"), "Ollama", "models"},
		{filepath.Join(home, ".ollama", "models"), "Ollama", "models"},
		{filepath.Join(home, ".local", "share", "open-webui"), "Open WebUI", "models"},
		{filepath.Join(home, ".cache", "huggingface"), "Hugging Face", "models"},
		{filepath.Join(home, ".cache", "modelscope"), "ModelScope", "models"},
		{filepath.Join(home, ".cache", "lm-studio"), "LM Studio", "models"},
		{filepath.Join(home, ".cache", "torch"), "Torch", "models"},
		{filepath.Join(home, ".cache", "llama.cpp"), "llama.cpp", "models"},
		{filepath.Join(home, ".cache", "whisper"), "Whisper", "models"},
		{filepath.Join(home, ".cache", "pip"), "pip", "cache"},
		{filepath.Join(home, ".cache", "uv"), "uv", "cache"},
		{filepath.Join(home, "Library", "Application Support", "Cursor"), "Cursor", "config"},
		{filepath.Join(home, "Library", "Application Support", "Claude"), "Claude", "config"},
		{filepath.Join(home, "Library", "Application Support", "Code"), "VS Code", "extensions"},
		{filepath.Join(home, "Library", "Application Support", "Continue"), "Continue", "config"},
		{filepath.Join(home, "Library", "Application Support", "Hermes"), "Hermes", "config"},
		{filepath.Join(home, "Library", "Application Support", "Hermes Agent"), "Hermes", "config"},
		{filepath.Join(home, "Library", "Application Support", "OpenCode"), "OpenCode", "config"},
		{filepath.Join(home, "Library", "Application Support", "opencode"), "OpenCode", "config"},
		{filepath.Join(home, "Library", "Application Support", "Ollama"), "Ollama", "models"},
		{filepath.Join(home, "Library", "Application Support", "LM Studio"), "LM Studio", "models"},
		{filepath.Join(home, "Library", "Application Support", "GPT4All"), "GPT4All", "models"},
		{filepath.Join(home, "Library", "Application Support", "anythingllm-desktop"), "AnythingLLM", "config"},
		{filepath.Join(home, "Library", "Application Support", "Jan"), "Jan", "models"},
		{filepath.Join(home, "Library", "Application Support", "Open WebUI"), "Open WebUI", "models"},
		{filepath.Join(home, "Library", "Application Support", "Pinokio"), "Pinokio", "config"},
		{filepath.Join(home, "Library", "Application Support", "Msty"), "Msty", "config"},
		{filepath.Join(home, "Library", "Application Support", "BoltAI"), "BoltAI", "config"},
		{filepath.Join(home, "Library", "Application Support", "MindMac"), "MindMac", "config"},
		{filepath.Join(home, "Library", "Application Support", "SillyTavern"), "SillyTavern", "config"},
		{filepath.Join(home, "Library", "Caches", "com.todesktop.230313mzl4w4u92"), "Cursor", "cache"},
		{filepath.Join(home, "Library", "Caches", "Cursor"), "Cursor", "cache"},
		{filepath.Join(home, "Library", "Caches", "Claude"), "Claude", "cache"},
		{filepath.Join(home, "Library", "Caches", "LM Studio"), "LM Studio", "cache"},
		{filepath.Join(home, "Library", "Caches", "Hermes"), "Hermes", "cache"},
		{filepath.Join(home, "Library", "Caches", "Hermes Agent"), "Hermes", "cache"},
		{filepath.Join(home, "Library", "Caches", "OpenCode"), "OpenCode", "cache"},
		{filepath.Join(home, "Library", "Caches", "opencode"), "OpenCode", "cache"},
		{filepath.Join(home, "Library", "Logs", "Cursor"), "Cursor", "logs"},
		{filepath.Join(home, "Library", "Logs", "Claude"), "Claude", "logs"},
		{filepath.Join(home, "Library", "Logs", "LM Studio"), "LM Studio", "logs"},
		{filepath.Join(home, "Library", "Logs", "Hermes"), "Hermes", "logs"},
		{filepath.Join(home, "Library", "Logs", "Hermes Agent"), "Hermes", "logs"},
		{filepath.Join(home, "Library", "Logs", "OpenCode"), "OpenCode", "logs"},
		{filepath.Join(home, "Library", "Logs", "opencode"), "OpenCode", "logs"},
	}
}

type aiDirStats struct {
	SizeBytes int64
	FileCount int
}

func aiDirectoryStats(root string, home string) aiDirStats {
	var stats aiDirStats
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path != root && shouldSkipAIInventoryPath(path, d, home) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.IsDir() {
			stats.FileCount++
			stats.SizeBytes += info.Size()
		}
		return nil
	})
	return stats
}

func shouldSkipAIInventoryPath(path string, d fs.DirEntry, home string) bool {
	if platform.ShouldExcludePath(path, home) {
		return true
	}
	name := strings.ToLower(d.Name())
	if d.IsDir() {
		switch name {
		case ".git", "node_modules", "vendor", "dist", "build", ".next", ".cache", "target", "deriveddata":
			return true
		}
		if strings.HasSuffix(name, ".photoslibrary") {
			return true
		}
	}
	if strings.Contains(path, string(filepath.Separator)+".git"+string(filepath.Separator)+"objects") {
		return true
	}
	return false
}

func projectRoots(cfg audit.RuntimeConfig) []string {
	seen := map[string]bool{}
	var roots []string
	add := func(path string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		roots = append(roots, abs)
	}
	add(cfg.ProjectRoot)
	if cwd, err := os.Getwd(); err == nil && looksLikeProjectRoot(cwd) {
		add(cwd)
	}
	return roots
}

func looksLikeProjectRoot(path string) bool {
	markers := []string{".git", "go.mod", "package.json", "pyproject.toml", "Cargo.toml", "README.md", "AGENTS.md", "CLAUDE.md"}
	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(path, marker)); err == nil {
			return true
		}
	}
	return false
}

func classifyAIArtifactPath(path string, isDir bool) (string, string, bool) {
	base := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)
	tool := detectAIToolName(path)
	if isDir {
		switch base {
		case "skills":
			return "skill", tool, true
		case "prompts":
			return "prompt", tool, true
		case "rules":
			return "rule", tool, true
		case "agents":
			return "generic_context", tool, true
		case "tools":
			return "tool_manifest", tool, true
		case ".claude", ".codex", ".cursor", ".continue", ".cline", ".roo", ".windsurf", ".open-interpreter", ".hermes", ".hermes-agent", ".opencode":
			return "generic_context", tool, true
		default:
			return "", "", false
		}
	}
	switch base {
	case "agents.md", "claude.md", "instructions.md", "copilot-instructions.md":
		return "instruction", tool, true
	case "ai.md":
		return "generic_context", tool, true
	case "prompts.md", "system_prompt.md":
		return "prompt", tool, true
	case "rules.md", ".cursorrules", ".windsurfrules":
		return "rule", tool, true
	case "mcp.json":
		return "mcp_config", tool, true
	case "tool_manifest.json":
		return "tool_manifest", tool, true
	case "manifest.json", "agent.json", "agent.md":
		return "agent_manifest", tool, true
	case "skill.json":
		return "skill", tool, true
	case "settings.json", "extensions.json", "config.toml", ".aider.conf.yml", ".aiderignore":
		return "settings", tool, true
	case "hermes.json", "hermes.yaml", "hermes.yml", "hermes.toml", "hermes-agent.json", "hermes-agent.yaml", "opencode.json", "opencode.yaml", "opencode.yml", "opencode.toml", ".opencode.json", ".opencode.yaml":
		return "settings", tool, true
	default:
		if strings.HasPrefix(base, ".aider") {
			return "settings", "Aider", true
		}
		if strings.Contains(lower, string(filepath.Separator)+"prompts"+string(filepath.Separator)) && isTextLikeAIFile(base) {
			return "prompt", tool, true
		}
		if strings.Contains(lower, string(filepath.Separator)+"rules"+string(filepath.Separator)) && isTextLikeAIFile(base) {
			return "rule", tool, true
		}
		if strings.Contains(lower, string(filepath.Separator)+"skills"+string(filepath.Separator)) && isTextLikeAIFile(base) {
			return "skill", tool, true
		}
	}
	return "", "", false
}

func detectAIToolName(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, ".claude") || strings.Contains(lower, "claude"):
		return "Claude"
	case strings.Contains(lower, ".codex") || strings.Contains(lower, "agents.md"):
		return "Codex"
	case strings.Contains(lower, ".cursor") || strings.Contains(lower, ".cursorrules"):
		return "Cursor"
	case strings.Contains(lower, "copilot"):
		return "Copilot"
	case strings.Contains(lower, ".vscode"):
		return "VS Code"
	case strings.Contains(lower, ".continue"):
		return "Continue"
	case strings.Contains(lower, ".cline"):
		return "Cline"
	case strings.Contains(lower, ".roo"):
		return "Roo"
	case strings.Contains(lower, ".windsurf"):
		return "Windsurf"
	case strings.Contains(lower, ".aider"):
		return "Aider"
	case strings.Contains(lower, ".open-interpreter"):
		return "Open Interpreter"
	case strings.Contains(lower, ".hermes") || strings.Contains(lower, "hermes-agent"):
		return "Hermes"
	case strings.Contains(lower, ".opencode") || strings.Contains(lower, "opencode"):
		return "OpenCode"
	default:
		return "Generic"
	}
}

func isTextLikeAIFile(base string) bool {
	base = strings.ToLower(base)
	return strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".txt") || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".toml") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

func EstimateAutoLoadedLikelihood(path string, artifactType string, toolName string, scope string) string {
	base := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)
	if artifactType == "mcp_config" {
		return "high"
	}
	if toolName == "Hermes" || toolName == "OpenCode" {
		if artifactType == "skill" || artifactType == "memory" || artifactType == "agent_manifest" || artifactType == "prompt" || artifactType == "rule" {
			return "high"
		}
	}
	if scope == "project" {
		switch base {
		case "agents.md", "claude.md", ".cursorrules", "system_prompt.md":
			return "critical"
		case "copilot-instructions.md", "instructions.md", "rules.md", ".windsurfrules":
			return "high"
		}
		if strings.Contains(lower, string(filepath.Separator)+".cursor"+string(filepath.Separator)+"rules") {
			return "critical"
		}
		if strings.Contains(lower, string(filepath.Separator)+".continue") || strings.Contains(lower, string(filepath.Separator)+".cline") || strings.Contains(lower, string(filepath.Separator)+".roo") {
			return "high"
		}
	}
	if scope == "user" {
		if toolName == "Claude" || toolName == "Codex" || toolName == "Cursor" {
			if artifactType == "instruction" || artifactType == "rule" || artifactType == "settings" || artifactType == "mcp_config" {
				return "high"
			}
		}
	}
	if artifactType == "skill" || artifactType == "prompt" || artifactType == "agent_manifest" || artifactType == "tool_manifest" {
		return "medium"
	}
	if artifactType == "memory" {
		return "medium"
	}
	if artifactType == "settings" || artifactType == "generic_context" {
		return "low"
	}
	return "none"
}

func ClassifyAIContextImpact(path string, artifactType string, toolName string, scope string, isDir bool, isWorldWritable bool, isGroupWritable bool, hasExecutableTools bool) (string, int) {
	base := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)
	if (isWorldWritable || isGroupWritable) && isAIBehaviorArtifact(artifactType) {
		return "critical", 95
	}
	if base == "system_prompt.md" {
		return "critical", 92
	}
	if artifactType == "mcp_config" && hasExecutableTools {
		return "critical", 90
	}
	if scope == "project" {
		if base == "agents.md" || base == "claude.md" || base == ".cursorrules" {
			return "critical", 88
		}
		if strings.Contains(lower, string(filepath.Separator)+".cursor"+string(filepath.Separator)+"rules") {
			return "critical", 86
		}
		if base == "instructions.md" || base == "rules.md" || base == "copilot-instructions.md" || base == ".windsurfrules" {
			return "high", 75
		}
		if strings.Contains(lower, string(filepath.Separator)+".continue") || strings.Contains(lower, string(filepath.Separator)+".cline") || strings.Contains(lower, string(filepath.Separator)+".roo") {
			return "high", 68
		}
	}
	if scope == "user" && (toolName == "Claude" || toolName == "Codex" || toolName == "Cursor") {
		if artifactType == "instruction" || artifactType == "rule" || artifactType == "settings" || artifactType == "mcp_config" {
			return "critical", 84
		}
	}
	if toolName == "Hermes" || toolName == "OpenCode" {
		if artifactType == "skill" || artifactType == "memory" || artifactType == "agent_manifest" || artifactType == "prompt" || artifactType == "rule" {
			return "high", 72
		}
	}
	if artifactType == "settings" {
		return "high", 62
	}
	if artifactType == "skill" || artifactType == "prompt" || artifactType == "agent_manifest" || artifactType == "tool_manifest" {
		return "medium", 45
	}
	if artifactType == "memory" || artifactType == "generic_context" {
		return "medium", 35
	}
	if isDir {
		return "low", 15
	}
	return "low", 10
}

func isAIBehaviorArtifact(artifactType string) bool {
	switch artifactType {
	case "skill", "rule", "prompt", "instruction", "memory", "mcp_config", "tool_manifest", "agent_manifest", "settings", "generic_context":
		return true
	default:
		return false
	}
}

func AIContextRecommendation(artifactType string, toolName string, impact string, isDir bool, suspicious bool) string {
	if suspicious {
		return "Review this AI " + artifactType + " before enabling agent mode. Treat suspicious patterns as review signals, not proof of malware."
	}
	if impact == "critical" || impact == "high" {
		return "Review this " + toolName + " " + artifactType + " before using AI agents in this scope; restrict write permissions and disable auto-run/auto-approve where possible."
	}
	if isDir {
		return "Inventory this AI-related directory and review files that can affect model context or tool execution."
	}
	return "Review if this artifact is in an untrusted project. Context impact is not a malware verdict."
}

func ClassifyAIDirectoryCategory(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, string(filepath.Separator)+"caches"+string(filepath.Separator)):
		return "cache"
	case strings.Contains(lower, string(filepath.Separator)+"logs"+string(filepath.Separator)):
		return "logs"
	case strings.Contains(lower, "models") || strings.Contains(lower, ".ollama") || strings.Contains(lower, "lm studio") || strings.Contains(lower, "jan"):
		return "models"
	case strings.Contains(lower, "skills"):
		return "skills"
	case strings.Contains(lower, "rules"):
		return "rules"
	case strings.Contains(lower, "prompts") || strings.Contains(lower, "commands"):
		return "prompts"
	case strings.Contains(lower, "mcp"):
		return "mcp"
	case strings.Contains(lower, "extensions") || strings.Contains(lower, "application support/code"):
		return "extensions"
	case strings.Contains(lower, ".claude") || strings.Contains(lower, ".codex") || strings.Contains(lower, ".cursor") || strings.Contains(lower, ".continue") || strings.Contains(lower, ".cline") || strings.Contains(lower, ".roo") || strings.Contains(lower, ".windsurf") || strings.Contains(lower, ".hermes") || strings.Contains(lower, ".opencode"):
		return "config"
	default:
		return "unknown"
	}
}

func ClassifyAIDirectoryImpact(path string, category string) (string, int) {
	if category == "" || category == "unknown" {
		category = ClassifyAIDirectoryCategory(path)
	}
	switch category {
	case "models":
		return "none", 0
	case "cache", "logs":
		return "low", 5
	case "skills", "rules", "prompts", "mcp":
		return "medium", 45
	case "config", "extensions":
		return "medium", 35
	default:
		return "low", 10
	}
}

func AIDirectoryRecommendation(category string, toolName string) string {
	switch category {
	case "models":
		return "Manual review only. Model directories can be large but should not be auto-cleaned."
	case "cache", "logs":
		return "May be cleanup-relevant, but this tool does not auto-clean AI caches/logs by default; review manually."
	case "skills", "rules", "prompts", "mcp", "config":
		return "Review for context inclusion, tool permissions, auto-approval, and project trust before using " + toolName + " agent workflows."
	default:
		return "Review manually if disk usage or context exposure is unexpected."
	}
}

func ScanAISuspiciousPromptPatterns(path string, maxFileSizeMB int) []audit.AIContextPattern {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	limit := int64(maxFileSizeMB)
	if limit <= 0 {
		limit = 5
	}
	maxBytes := limit * 1024 * 1024
	if info.Size() > maxBytes {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	return scanAISuspiciousPromptPatterns(file, maxBytes)
}

func scanAISuspiciousPromptPatterns(r io.Reader, maxBytes int64) []audit.AIContextPattern {
	scanner := bufio.NewScanner(io.LimitReader(r, maxBytes))
	var patterns []audit.AIContextPattern
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, pattern := range MatchAISuspiciousPromptPatterns(line) {
			patterns = append(patterns, audit.AIContextPattern{
				Pattern: pattern,
				Line:    lineNo,
				Snippet: redactAndTrimSnippet(line, 160),
			})
		}
	}
	return patterns
}

func MatchAISuspiciousPromptPatterns(line string) []string {
	lower := strings.ToLower(line)
	patterns := []string{
		"ignore previous instructions",
		"disregard previous instructions",
		"reveal your system prompt",
		"override system instructions",
		"disable safety",
		"send the contents of",
		"read ~/.ssh",
		"read .env",
		"read keychain",
		"exfiltrate",
		"upload to",
		"post to webhook",
		"curl",
		"wget",
		"nc",
		"ncat",
		"base64",
		"osascript",
		"launchctl",
		"chmod 777",
		"rm -rf",
		"sudo",
		"security find-generic-password",
		"security dump-keychain",
	}
	var matches []string
	for _, pattern := range patterns {
		if aiPromptPatternMatches(lower, pattern) {
			matches = append(matches, pattern)
		}
	}
	return matches
}

func aiPromptPatternMatches(lower string, pattern string) bool {
	switch pattern {
	case "curl", "wget", "nc", "ncat", "base64", "osascript", "launchctl", "sudo":
		return containsCommandToken(lower, pattern)
	default:
		return strings.Contains(lower, pattern)
	}
}

func containsCommandToken(lower string, token string) bool {
	replacer := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ", ";", " ", "(", " ", ")", " ", "[", " ", "]", " ", "{", " ", "}", " ", "\"", " ", "'", " ", "`", " ", "|", " ", "&", " ", "<", " ", ">", " ", ",", " ")
	for _, field := range strings.Fields(replacer.Replace(lower)) {
		if field == token {
			return true
		}
	}
	return false
}

func IsAIToolExecutionPattern(pattern string) bool {
	switch pattern {
	case "curl", "wget", "nc", "ncat", "base64", "osascript", "launchctl", "chmod 777", "rm -rf", "sudo", "security find-generic-password", "security dump-keychain":
		return true
	default:
		return false
	}
}

func IsAINetworkExfiltrationPattern(pattern string) bool {
	switch pattern {
	case "curl", "wget", "nc", "ncat", "upload to", "post to webhook", "exfiltrate":
		return true
	default:
		return false
	}
}

func redactAndTrimSnippet(line string, maxLen int) string {
	snippet := strings.TrimSpace(safety.RedactSensitiveText(line))
	if maxLen <= 0 || len(snippet) <= maxLen {
		return snippet
	}
	return snippet[:maxLen] + "..."
}

func isScannableAIArtifact(path string, artifactType string) bool {
	if artifactType == "settings" && !strings.HasSuffix(strings.ToLower(path), ".json") {
		return false
	}
	switch artifactType {
	case "skill", "rule", "prompt", "instruction", "memory", "mcp_config", "tool_manifest", "agent_manifest", "settings", "generic_context":
		base := filepath.Base(path)
		return isTextLikeAIFile(base) || strings.HasPrefix(base, ".aider") || strings.HasPrefix(base, ".cursor") || base == ".windsurfrules"
	default:
		return false
	}
}

func isHiddenPath(path string) bool {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for _, part := range parts {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

func filterAISkills(artifacts []audit.AIContextArtifact) []audit.AIContextArtifact {
	var skills []audit.AIContextArtifact
	for _, artifact := range artifacts {
		if artifact.ArtifactType == "skill" {
			skills = append(skills, artifact)
		}
	}
	return skills
}

func CalculateAIContextSummary(artifacts []audit.AIContextArtifact, directories []audit.AIRelatedDirectory) audit.AIContextSummary {
	var summary audit.AIContextSummary
	summary.TotalAIDirectories = len(directories)
	summary.TotalAIContextArtifacts = len(artifacts)
	for _, dir := range directories {
		summary.TotalAIDirectorySizeBytes += dir.SizeBytes
	}
	for _, artifact := range artifacts {
		switch artifact.ContextImpact {
		case "critical":
			summary.CriticalContextImpactCount++
		case "high":
			summary.HighContextImpactCount++
		}
		if artifact.IsWorldWritable {
			summary.WorldWritableAIArtifactsCount++
		}
		summary.SuspiciousAIPromptPatternsCount += len(artifact.SuspiciousPatterns)
	}
	return summary
}

func aiContextFindings(artifacts []audit.AIContextArtifact, directories []audit.AIRelatedDirectory, summary audit.AIContextSummary) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, newFinding("ai-context-inventory-summary", audit.CategoryAISecurity, "AI Skills & Context Inventory summary", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("directories=%d total_directory_size=%s artifacts=%d critical_context=%d high_context=%d suspicious_patterns=%d", summary.TotalAIDirectories, platform.HumanBytes(summary.TotalAIDirectorySizeBytes), summary.TotalAIContextArtifacts, summary.CriticalContextImpactCount, summary.HighContextImpactCount, summary.SuspiciousAIPromptPatternsCount), "Review critical/high context impact artifacts before using agent mode. Context impact is not a malware verdict.", ""))

	for _, artifact := range artifacts {
		if artifact.ContextImpactScore < 51 && !artifact.IsWorldWritable && len(artifact.SuspiciousPatterns) == 0 && !artifact.ContainsToolExecutionPatterns && !artifact.ContainsNetworkExfiltrationPatterns {
			continue
		}
		status := audit.StatusWarn
		severity := audit.SeverityMedium
		if artifact.ContextImpact == "critical" || artifact.IsWorldWritable || artifact.ContainsToolExecutionPatterns || artifact.ContainsNetworkExfiltrationPatterns {
			severity = audit.SeverityHigh
		}
		title := "AI Context Artifact: " + artifact.ArtifactType
		if artifact.IsWorldWritable {
			title = "AI instruction file is world-writable"
		} else if strings.EqualFold(filepath.Base(artifact.Path), "AGENTS.md") {
			title = "Project-local AGENTS.md may influence AI agent behavior"
		} else if len(artifact.SuspiciousPatterns) > 0 {
			title = "AI skill/prompt contains suspicious review patterns"
		}
		f := newFinding("ai-context-artifact-"+safeID(artifact.Path), audit.CategoryAISecurity, title, status, severity, fmt.Sprintf("path=%s type=%s tool=%s scope=%s auto_loaded=%s context_impact=%s score=%d permissions=%s suspicious_patterns=%d", artifact.Path, artifact.ArtifactType, artifact.ToolName, artifact.Scope, artifact.AutoLoadedLikelihood, artifact.ContextImpact, artifact.ContextImpactScore, artifact.Permissions, len(artifact.SuspiciousPatterns)), artifact.Recommendation, "")
		f.Subtype = "AI Context Artifact"
		f.ContextImpact = artifact.ContextImpact
		f.ContextImpactScore = artifact.ContextImpactScore
		f.DataExposureRisk = artifact.ContainsSuspiciousPromptPatterns
		f.CommandExecutionRisk = artifact.ContainsToolExecutionPatterns
		f.NetworkExfiltrationRisk = artifact.ContainsNetworkExfiltrationPatterns
		findings = append(findings, f)
	}

	for _, dir := range directories {
		if dir.Category != "models" || dir.SizeBytes < 5*1024*1024*1024 {
			continue
		}
		f := newFinding("ai-directory-models-"+safeID(dir.Path), audit.CategoryStorage, "AI model directory consumes significant disk space", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("path=%s tool=%s size=%s files=%d context_impact=%s", dir.Path, dir.ToolName, dir.HumanSize, dir.FileCount, dir.ContextImpact), dir.Recommendation, "")
		f.Subtype = "AI Directory Inventory"
		f.EstimatedSizeBytes = dir.SizeBytes
		f.ContextImpact = dir.ContextImpact
		f.ContextImpactScore = dir.ContextImpactScore
		findings = append(findings, f)
	}
	return findings
}
