package checks

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
)

var dangerousCommandPatterns = []string{
	"bash -c", "sh -c", "zsh -c", "python -c", "node -e", "perl -e", "ruby -e",
	"osascript", "curl", "wget", " nc ", " ncat ", "socat", "ssh ", "scp ", "rsync ",
	"launchctl", "crontab", "chmod 777", "chmod -r 777", "chown", "sudo ", "docker run",
	"npx", "uvx", "pip install", "npm install -g", "base64", "rm -rf",
}

var networkTools = []string{"curl", "wget", " nc ", " ncat ", "socat", "ssh ", "scp ", "rsync ", "post to webhook", "upload to"}

func RunAISecurity(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	var findings []audit.Finding
	var ai audit.AISecuritySummary

	tools := discoverAITools(cfg)
	ai.InstalledTools = tools
	findings = append(findings, aiToolFindings(tools)...)

	configFindings, configs := inspectAIConfigs(cfg)
	findings = append(findings, configFindings...)
	ai.MCPConfigs = append(ai.MCPConfigs, configs...)

	mcpFindings, mcpInfos := inspectMCPConfigs(cfg)
	findings = append(findings, mcpFindings...)
	ai.MCPConfigs = append(ai.MCPConfigs, mcpInfos...)

	permissionFindings := inspectAIPermissions(cfg)
	findings = append(findings, permissionFindings...)

	serverFindings, servers := inspectLocalLLMServers(ctx, runner)
	findings = append(findings, serverFindings...)
	ai.LocalServers = append(ai.LocalServers, servers...)

	artifactFindings, artifacts := scanPromptInjectionArtifacts(cfg)
	findings = append(findings, artifactFindings...)
	ai.PromptArtifacts = append(ai.PromptArtifacts, artifacts...)

	if !cfg.Deep {
		findings = append(findings, newFinding("ai-prompt-artifact-scan-info", audit.CategoryAISecurity, "Deep prompt-injection artifact scan", audit.StatusInfo, audit.SeverityInfo, "Deep scan is disabled. Only key rules files were checked. Use --deep with --project-root to recursively scan all documentation files.", "Review untrusted repositories before opening them in agent mode.", ""))
	}

	dockerFindings := inspectDockerComposeAI(cfg)
	findings = append(findings, dockerFindings...)

	ai.Recommendations = aiHardeningRecommendations()
	findings = append(findings, newFinding("ai-hardening-recommendations", audit.CategoryAISecurity, "AI hardening recommendations", audit.StatusInfo, audit.SeverityInfo, strings.Join(ai.Recommendations, "; "), "Apply the recommendations that match your workflow and risk tolerance.", ""))
	return audit.CheckResult{Findings: findings, AISecurity: ai}, nil
}

func discoverAITools(cfg audit.RuntimeConfig) []audit.AIToolInfo {
	apps := []struct {
		name  string
		paths []string
	}{
		{"Cursor", []string{"/Applications/Cursor.app", filepath.Join(cfg.HomeDir, "Applications", "Cursor.app")}},
		{"Visual Studio Code", []string{"/Applications/Visual Studio Code.app", filepath.Join(cfg.HomeDir, "Applications", "Visual Studio Code.app")}},
		{"Claude Desktop", []string{"/Applications/Claude.app", filepath.Join(cfg.HomeDir, "Applications", "Claude.app")}},
		{"LM Studio", []string{"/Applications/LM Studio.app", filepath.Join(cfg.HomeDir, "Applications", "LM Studio.app")}},
		{"AnythingLLM", []string{"/Applications/AnythingLLM.app", filepath.Join(cfg.HomeDir, "Applications", "AnythingLLM.app")}},
		{"GPT4All", []string{"/Applications/GPT4All.app", filepath.Join(cfg.HomeDir, "Applications", "GPT4All.app")}},
		{"Jan", []string{"/Applications/Jan.app", filepath.Join(cfg.HomeDir, "Applications", "Jan.app")}},
		{"Docker Desktop", []string{"/Applications/Docker.app", filepath.Join(cfg.HomeDir, "Applications", "Docker.app")}},
	}
	var tools []audit.AIToolInfo
	for _, app := range apps {
		for _, p := range app.paths {
			if _, err := os.Stat(p); err == nil {
				tools = append(tools, audit.AIToolInfo{Name: app.name, Kind: "gui_app", Path: p, Detected: true})
				break
			}
		}
	}

	cliNames := []string{"claude", "codex", "aider", "interpreter", "open-interpreter", "ollama", "continue", "cline", "roo", "localai", "llama-cli", "llama-server"}
	for _, name := range cliNames {
		if p := findExecutable(name, cfg); p != "" {
			tools = append(tools, audit.AIToolInfo{Name: name, Kind: "cli", Path: p, Detected: true})
		}
	}
	if p := findExecutable("gh", cfg); p != "" {
		copilotExt := filepath.Join(cfg.HomeDir, ".config", "gh", "extensions", "gh-copilot")
		if _, err := os.Stat(copilotExt); err == nil {
			tools = append(tools, audit.AIToolInfo{Name: "GitHub Copilot CLI", Kind: "cli_extension", Path: p, Detected: true})
		}
	}
	return tools
}

func findExecutable(name string, cfg audit.RuntimeConfig) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	paths := []string{
		"/usr/local/bin",
		"/opt/homebrew/bin",
		filepath.Join(cfg.HomeDir, ".local", "bin"),
		filepath.Join(cfg.HomeDir, "bin"),
		filepath.Join(cfg.HomeDir, ".npm-global", "bin"),
		filepath.Join(cfg.HomeDir, ".bun", "bin"),
		filepath.Join(cfg.HomeDir, ".cargo", "bin"),
		filepath.Join(cfg.HomeDir, "go", "bin"),
	}
	if cfg.ProjectRoot != "" {
		paths = append(paths, filepath.Join(cfg.ProjectRoot, "node_modules", ".bin"))
	}
	for _, dir := range paths {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

func aiToolFindings(tools []audit.AIToolInfo) []audit.Finding {
	if len(tools) == 0 {
		return []audit.Finding{newFinding("ai-tools-discovery", audit.CategoryAISecurity, "AI tools discovery", audit.StatusInfo, audit.SeverityInfo, "No known AI coding or local LLM tools detected in common locations.", "If you use AI tools installed elsewhere, review their permissions and MCP settings manually.", "")}
	}
	var evidence []string
	for _, tool := range tools {
		evidence = append(evidence, fmt.Sprintf("%s (%s) at %s", tool.Name, tool.Kind, tool.Path))
	}
	return []audit.Finding{newFinding("ai-tools-discovery", audit.CategoryAISecurity, "AI tools discovered", audit.StatusWarn, audit.SeverityLow, strings.Join(evidence, "; "), "Review each tool's workspace trust, auto-approve, MCP, shell, file, and network permissions.", "")}
}

func inspectAIConfigs(cfg audit.RuntimeConfig) ([]audit.Finding, []audit.MCPConfigInfo) {
	paths := aiConfigPathsForOS(platform.CurrentOS(), cfg)
	var findings []audit.Finding
	var infos []audit.MCPConfigInfo
	for _, path := range paths {
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		evidence := fmt.Sprintf("path=%s mode=%s size=%d mtime=%s", path, platform.FormatPerm(meta.Mode), meta.Size, meta.ModTime.Format("2006-01-02"))
		if platform.IsWorldWritable(meta.Mode) {
			status = audit.StatusFail
			severity = audit.SeverityHigh
			evidence += "; world-writable"
		} else if platform.IsGroupWritable(meta.Mode) {
			status = audit.StatusWarn
			severity = audit.SeverityMedium
			evidence += "; group-writable"
		}
		findings = append(findings, newFinding("ai-config-"+safeID(path), audit.CategoryAISecurity, "AI tool config path", status, severity, evidence, "Review AI tool configs for auto-approve, shell, MCP, file access, and network permissions. Do not store secrets in project-local AI configs.", ""))
		if strings.HasSuffix(path, "mcp.json") || strings.HasSuffix(path, "claude_desktop_config.json") {
			infos = append(infos, audit.MCPConfigInfo{Path: path, Permission: platform.FormatPerm(meta.Mode), Risk: "metadata", Description: "MCP-related config path exists; parsed by MCP checks when valid JSON."})
		}

		// Parse regular files for auto-approval weakening settings
		if meta.Mode.IsRegular() && meta.Size < 1024*1024 { // < 1MB
			data, err := os.ReadFile(path)
			if err == nil {
				if reason, sev := scanConfigForAutoApproval(path, data); reason != "" {
					findings = append(findings, newFinding(
						"ai-config-weakening-"+safeID(path),
						audit.CategoryAISecurity,
						"AI Agent auto-approval/weakening settings detected",
						audit.StatusWarn,
						sev,
						fmt.Sprintf("path=%s; warning=%s", path, reason),
						"Disable auto-approve settings. AI agents should always prompt for confirmation before running terminal commands, writing files, or accessing the network.",
						"",
					))
				}
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("ai-config-paths", audit.CategoryAISecurity, "AI config paths", audit.StatusInfo, audit.SeverityInfo, "No known AI configuration paths detected in common locations.", "No action needed unless AI tools are installed in custom locations.", ""))
	}
	return findings, infos
}

func aiConfigPathsForOS(osName platform.OS, cfg audit.RuntimeConfig) []string {
	paths := []string{
		filepath.Join(cfg.HomeDir, ".cursor"),
		filepath.Join(cfg.HomeDir, ".continue"),
		filepath.Join(cfg.HomeDir, ".claude"),
		filepath.Join(cfg.HomeDir, ".codex"),
		filepath.Join(cfg.HomeDir, ".ollama"),
		filepath.Join(cfg.HomeDir, ".cline"),
		filepath.Join(cfg.HomeDir, ".roo"),
		filepath.Join(cfg.HomeDir, ".windsurf"),
		filepath.Join(cfg.HomeDir, ".opencode"),
		filepath.Join(cfg.HomeDir, ".hermes"),
		filepath.Join(cfg.HomeDir, ".hermes-agent"),
		filepath.Join(cfg.HomeDir, ".config", "Code"),
		filepath.Join(cfg.HomeDir, ".config", "Cursor"),
		filepath.Join(cfg.HomeDir, ".config", "continue"),
		filepath.Join(cfg.HomeDir, ".config", "claude"),
		filepath.Join(cfg.HomeDir, ".config", "opencode"),
		filepath.Join(cfg.HomeDir, ".config", "hermes"),

		// Specific config files
		filepath.Join(cfg.HomeDir, ".cursor", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".continue", "config.json"),
		filepath.Join(cfg.HomeDir, ".continue", "config.yaml"),
		filepath.Join(cfg.HomeDir, ".claude", "claude.json"),
		filepath.Join(cfg.HomeDir, ".claude.json"),
		filepath.Join(cfg.HomeDir, ".claude_desktop_config.json"),
		filepath.Join(cfg.HomeDir, ".codex", "config.toml"),
		filepath.Join(cfg.HomeDir, ".cline", "settings.json"),
		filepath.Join(cfg.HomeDir, ".cline", "state.json"),
		filepath.Join(cfg.HomeDir, ".roo", "settings.json"),
		filepath.Join(cfg.HomeDir, ".roo", "state.json"),
		filepath.Join(cfg.HomeDir, ".windsurf", "settings.json"),
		filepath.Join(cfg.HomeDir, ".windsurf", "memories.json"),
	}
	if osName.IsDarwin() {
		paths = append(paths,
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Cursor"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Cursor", "User", "settings.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Code"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Code", "User", "settings.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Continue"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Continue", "config.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Continue", "config.yaml"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "LM Studio"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "LM Studio", "settings.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "anythingllm-desktop"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "AnythingLLM"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Jan"),
			filepath.Join(cfg.HomeDir, "Library", "Preferences"),
		)
	}
	if osName.IsWindows() {
		paths = append(paths,
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Claude"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Claude Code"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Code"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Code", "User", "settings.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Cursor"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Cursor", "User", "settings.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Continue"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Continue", "config.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "opencode"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Hermes"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "LM Studio"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "LM Studio", "settings.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Jan"),
			filepath.Join(cfg.HomeDir, "AppData", "Local", "Programs", "Cursor"),
			filepath.Join(cfg.HomeDir, "AppData", "Local", "Programs", "Claude"),
		)
	}
	if cfg.ProjectRoot != "" {
		paths = append(paths,
			filepath.Join(cfg.ProjectRoot, ".cursor"),
			filepath.Join(cfg.ProjectRoot, ".cursor", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, ".vscode"),
			filepath.Join(cfg.ProjectRoot, ".vscode", "settings.json"),
			filepath.Join(cfg.ProjectRoot, ".continue"),
			filepath.Join(cfg.ProjectRoot, ".continue", "config.json"),
			filepath.Join(cfg.ProjectRoot, ".roo"),
			filepath.Join(cfg.ProjectRoot, ".cline"),
			filepath.Join(cfg.ProjectRoot, "mcp.json"),
			filepath.Join(cfg.ProjectRoot, "claude_desktop_config.json"),
		)
	}
	return uniqueSortedStrings(paths)
}

func inspectMCPConfigs(cfg audit.RuntimeConfig) ([]audit.Finding, []audit.MCPConfigInfo) {
	paths := candidateMCPPaths(cfg)
	var findings []audit.Finding
	var infos []audit.MCPConfigInfo
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		parsed, parseErr := parseMCPConfig(path, cfg.MaxFileSizeMB)
		perm := platform.FormatPerm(meta.Mode)
		if parseErr != nil {
			findings = append(findings, newFinding("ai-mcp-parse-"+safeID(path), audit.CategoryAISecurity, "MCP config parse", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("path=%s mode=%s parse_error=%s", path, perm, parseErr), "Review this MCP config manually. This tool never executes MCP commands.", ""))
			infos = append(infos, audit.MCPConfigInfo{Path: path, Permission: perm, Risk: "unknown", Description: "Config exists but could not be parsed as JSON."})
			continue
		}
		if len(parsed) == 0 {
			findings = append(findings, newFinding("ai-mcp-empty-"+safeID(path), audit.CategoryAISecurity, "MCP config", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("path=%s mode=%s no server commands found", path, perm), "Review manually if this config is expected to start MCP servers.", ""))
			continue
		}
		for _, cmd := range parsed {
			if cmd.URL != "" || cmd.Transport != "" {
				severity := audit.SeverityMedium
				status := audit.StatusWarn
				reason := fmt.Sprintf("remote MCP endpoint configured: url=%s transport=%s", cmd.URL, cmd.Transport)
				if cmd.URL != "" && !strings.Contains(cmd.URL, "localhost") && !strings.Contains(cmd.URL, "127.0.0.1") && !strings.Contains(cmd.URL, "::1") {
					severity = audit.SeverityHigh
					reason = fmt.Sprintf("external remote MCP endpoint configured (beyond local machine trust boundary): url=%s", cmd.URL)
				}
				evidence := fmt.Sprintf("path=%s server=%s mode=%s url=%s transport=%s risk=%s", path, cmd.Name, perm, cmd.URL, cmd.Transport, reason)
				f := newFinding("ai-mcp-remote-"+safeID(path+"-"+cmd.Name), audit.CategoryAISecurity, "Remote MCP server endpoint: "+cmd.Name, status, severity, evidence, "Ensure the remote MCP server and its connection are secure. Remote MCP servers expand the trust boundary beyond your local machine.", "")
				f.NetworkExfiltrationRisk = true
				findings = append(findings, f)
				infos = append(infos, audit.MCPConfigInfo{Path: path, ServerName: cmd.Name, Command: cmd.URL, Permission: perm, Risk: string(severity), Description: reason})
				continue
			}

			severity, reason, dataRisk, commandRisk, networkRisk := ClassifyMCPCommandRisk(cmd.Command, cmd.Args)
			status := audit.StatusInfo
			if severity == audit.SeverityHigh || severity == audit.SeverityCritical {
				status = audit.StatusWarn
			} else if severity == audit.SeverityMedium || platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode) || isProjectLocal(path, cfg.ProjectRoot) {
				status = audit.StatusWarn
				if severity == audit.SeverityInfo {
					severity = audit.SeverityMedium
				}
			}

			capabilityRisk, capSeverity := ClassifyMCPCapability(cmd.Name, cmd.Command, cmd.Args)
			if capSeverity > severity {
				severity = capSeverity
				status = audit.StatusWarn
			}
			commandLine := sanitizeCommandLine(cmd.Command, cmd.Args)
			evidence := fmt.Sprintf("path=%s server=%s mode=%s command=%s risk=%s", path, cmd.Name, perm, commandLine, reason)
			if capabilityRisk != "" {
				evidence += "; capability=" + capabilityRisk
				reason += "; " + capabilityRisk
			}
			if isProjectLocal(path, cfg.ProjectRoot) {
				evidence += "; project-local MCP config can be auto-started by some tools after trust prompts/settings"
			}
			f := newFinding("ai-mcp-risk-"+safeID(path+"-"+cmd.Name), audit.CategoryAISecurity, "MCP config command risk: "+cmd.Name, status, severity, evidence, "Review MCP configs before opening repositories in agent mode. Disable auto-run, pin package versions, and require confirmation for shell/network/file operations.", "")
			f.DataExposureRisk = dataRisk
			f.CommandExecutionRisk = commandRisk
			f.NetworkExfiltrationRisk = networkRisk
			findings = append(findings, f)
			infos = append(infos, audit.MCPConfigInfo{Path: path, ServerName: cmd.Name, Command: commandLine, Permission: perm, Risk: string(severity), Description: reason})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("ai-mcp-configs", audit.CategoryAISecurity, "MCP configs", audit.StatusInfo, audit.SeverityInfo, "No MCP configs detected in common locations.", "No action needed unless MCP configs exist in custom locations.", ""))
	}
	return findings, infos
}

type mcpCommand struct {
	Name      string
	Command   string
	Args      []string
	URL       string
	Transport string
}

func candidateMCPPaths(cfg audit.RuntimeConfig) []string {
	return candidateMCPPathsForOS(platform.CurrentOS(), cfg)
}

func candidateMCPPathsForOS(osName platform.OS, cfg audit.RuntimeConfig) []string {
	paths := []string{
		filepath.Join(cfg.HomeDir, ".cursor", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".claude", "claude_desktop_config.json"),
		filepath.Join(cfg.HomeDir, ".config", "claude", "claude_desktop_config.json"),
		filepath.Join(cfg.HomeDir, ".config", "Cursor", "User", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".config", "Code", "User", "mcp.json"),
		filepath.Join(cfg.HomeDir, ".config", "opencode", "mcp.json"),
	}
	if osName.IsDarwin() {
		paths = append(paths,
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Cursor", "User", "mcp.json"),
			filepath.Join(cfg.HomeDir, "Library", "Application Support", "Code", "User", "mcp.json"),
		)
	}
	if osName.IsWindows() {
		paths = append(paths,
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Cursor", "User", "mcp.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "Code", "User", "mcp.json"),
			filepath.Join(cfg.HomeDir, "AppData", "Roaming", "opencode", "mcp.json"),
		)
	}
	if cfg.ProjectRoot != "" {
		paths = append(paths,
			filepath.Join(cfg.ProjectRoot, ".cursor", "mcp.json"),
			filepath.Join(cfg.ProjectRoot, "mcp.json"),
			filepath.Join(cfg.ProjectRoot, "claude_desktop_config.json"),
		)
		walkLimited(cfg.ProjectRoot, cfg.HomeDir, func(path string, d os.DirEntry) {
			if d.IsDir() {
				return
			}
			base := strings.ToLower(filepath.Base(path))
			if base == "mcp.json" || base == "claude_desktop_config.json" {
				paths = append(paths, path)
			}
		})
	}
	if cfg.Deep {
		homeSearchRoots := mcpSearchRootsForOS(osName, cfg.HomeDir)
		for _, root := range homeSearchRoots {
			walkLimited(root, cfg.HomeDir, func(path string, d os.DirEntry) {
				if d.IsDir() {
					return
				}
				base := strings.ToLower(filepath.Base(path))
				if base == "mcp.json" || base == "claude_desktop_config.json" {
					paths = append(paths, path)
				}
			})
		}
	}
	return uniqueSortedStrings(paths)
}

func mcpSearchRootsForOS(osName platform.OS, home string) []string {
	roots := []string{filepath.Join(home, ".cursor"), filepath.Join(home, ".claude"), filepath.Join(home, ".config")}
	if osName.IsDarwin() {
		roots = append(roots, filepath.Join(home, "Library", "Application Support"))
	}
	if osName.IsWindows() {
		roots = append(roots, filepath.Join(home, "AppData", "Roaming"))
	}
	return roots
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func parseMCPConfig(path string, maxFileSizeMB int) ([]mcpCommand, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	limit := int64(maxFileSizeMB)
	if limit <= 0 {
		limit = 5
	}
	if info.Size() > limit*1024*1024 {
		return nil, fmt.Errorf("file exceeds max-file-size-mb")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return extractMCPCommands(root), nil
}

func extractMCPCommands(root any) []mcpCommand {
	var out []mcpCommand
	if m, ok := root.(map[string]any); ok {
		if servers, ok := m["mcpServers"].(map[string]any); ok {
			for name, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					cmd := stringValue(server["command"])
					args := stringSliceValue(server["args"])
					urlStr := stringValue(server["url"])
					transport := stringValue(server["transport"])
					if cmd != "" || len(args) > 0 || urlStr != "" || transport != "" {
						out = append(out, mcpCommand{Name: name, Command: cmd, Args: args, URL: urlStr, Transport: transport})
					}
				}
			}
		}
		if servers, ok := m["servers"].(map[string]any); ok {
			for name, raw := range servers {
				if server, ok := raw.(map[string]any); ok {
					cmd := stringValue(server["command"])
					args := stringSliceValue(server["args"])
					urlStr := stringValue(server["url"])
					transport := stringValue(server["transport"])
					if cmd != "" || len(args) > 0 || urlStr != "" || transport != "" {
						out = append(out, mcpCommand{Name: name, Command: cmd, Args: args, URL: urlStr, Transport: transport})
					}
				}
			}
		}
	}
	if len(out) == 0 {
		recursiveMCPCommandSearch(root, "config", &out)
	}
	return out
}

func recursiveMCPCommandSearch(value any, name string, out *[]mcpCommand) {
	switch x := value.(type) {
	case map[string]any:
		cmd := stringValue(x["command"])
		urlStr := stringValue(x["url"])
		transport := stringValue(x["transport"])
		if cmd != "" || urlStr != "" || transport != "" {
			*out = append(*out, mcpCommand{
				Name:      name,
				Command:   cmd,
				Args:      stringSliceValue(x["args"]),
				URL:       urlStr,
				Transport: transport,
			})
			return
		}
		for k, v := range x {
			recursiveMCPCommandSearch(v, k, out)
		}
	case []any:
		for i, item := range x {
			recursiveMCPCommandSearch(item, fmt.Sprintf("%s[%d]", name, i), out)
		}
	}
}

func ClassifyMCPCapability(name, command string, args []string) (string, audit.Severity) {
	lowerName := strings.ToLower(name)
	lowerCmd := strings.ToLower(command)

	if strings.Contains(lowerName, "terminal") || strings.Contains(lowerName, "shell") || strings.Contains(lowerName, "bash") ||
		strings.Contains(lowerCmd, "bash") || strings.Contains(lowerCmd, "sh") || strings.Contains(lowerCmd, "zsh") ||
		strings.Contains(lowerName, "command") || strings.Contains(lowerName, "execute") {
		return "Terminal / Shell command execution (Excessive Agency risk)", audit.SeverityHigh
	}
	if strings.Contains(lowerName, "filesystem") || strings.Contains(lowerName, "file") || strings.Contains(lowerName, "fs") ||
		strings.Contains(lowerCmd, "fs") || strings.Contains(lowerCmd, "filesystem") {
		return "Filesystem write or read access (Excessive Agency risk)", audit.SeverityHigh
	}
	if strings.Contains(lowerName, "browser") || strings.Contains(lowerName, "playwright") || strings.Contains(lowerName, "puppeteer") ||
		strings.Contains(lowerCmd, "playwright") || strings.Contains(lowerCmd, "puppeteer") || strings.Contains(lowerName, "selenium") {
		return "Browser automation (Indirect prompt injection / Data leak risk)", audit.SeverityHigh
	}
	if strings.Contains(lowerName, "database") || strings.Contains(lowerName, "postgres") || strings.Contains(lowerName, "sqlite") ||
		strings.Contains(lowerName, "db") || strings.Contains(lowerCmd, "postgres") || strings.Contains(lowerCmd, "mysql") {
		return "Database access (Direct file or data tampering risk)", audit.SeverityHigh
	}
	if strings.Contains(lowerName, "aws") || strings.Contains(lowerName, "gcp") || strings.Contains(lowerName, "azure") ||
		strings.Contains(lowerName, "cloud") || strings.Contains(lowerCmd, "aws") || strings.Contains(lowerCmd, "gcloud") {
		return "Cloud console / Infrastructure management (High impact risk)", audit.SeverityCritical
	}
	if strings.Contains(lowerName, "github") || strings.Contains(lowerName, "gitlab") || strings.Contains(lowerName, "git") ||
		strings.Contains(lowerCmd, "git") {
		return "Source control repository access (Git history / Code exfiltration risk)", audit.SeverityHigh
	}
	if strings.Contains(lowerName, "slack") || strings.Contains(lowerName, "gmail") || strings.Contains(lowerName, "drive") ||
		strings.Contains(lowerName, "email") || strings.Contains(lowerName, "jira") {
		return "External communication / Productivity suite integration (Data leak risk)", audit.SeverityMedium
	}
	if strings.Contains(lowerName, "ssh") || strings.Contains(lowerCmd, "ssh") {
		return "SSH / Remote administration (Command execution risk)", audit.SeverityCritical
	}
	return "", audit.SeverityInfo
}

func scanConfigForAutoApproval(path string, data []byte) (string, audit.Severity) {
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "tool_permissions") && (strings.Contains(lower, "allow") || strings.Contains(lower, "default")) {
		return "Zed/Editor tool permissions configured with permissive defaults", audit.SeverityHigh
	}
	if strings.Contains(lower, "auto_execute") || strings.Contains(lower, "\"turbo\"") || strings.Contains(lower, "autoexecution") {
		return "Windsurf auto-execution / Turbo mode enabled with reduced confirmation gates", audit.SeverityHigh
	}
	if strings.Contains(lower, "autoapprove") || strings.Contains(lower, "auto-approve") {
		if strings.Contains(lower, "true") || strings.Contains(lower, "always") {
			return "AI Agent auto-approval policy is set to run commands or tools without manual confirmation", audit.SeverityHigh
		}
	}
	if strings.Contains(lower, "auto_run") && strings.Contains(lower, "true") {
		return "Open Interpreter auto_run is enabled, bypassing approval checkpoints", audit.SeverityHigh
	}
	if strings.Contains(lower, "approval_policy") && (strings.Contains(lower, "never") || strings.Contains(lower, "none") || strings.Contains(lower, "always")) {
		return "Codex approval policy set to a permissive state", audit.SeverityHigh
	}
	return "", audit.SeverityInfo
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func stringSliceValue(v any) []string {
	values, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range values {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func ClassifyMCPCommandRisk(command string, args []string) (audit.Severity, string, bool, bool, bool) {
	line := strings.ToLower(strings.TrimSpace(command + " " + strings.Join(args, " ")))
	line = " " + line + " "
	dataRisk := referencesSecretPath(line)
	networkRisk := containsNetworkTool(line)
	commandRisk := IsDangerousCommandPattern(line)
	if strings.TrimSpace(line) == "" {
		return audit.SeverityInfo, "no command found", dataRisk, commandRisk, networkRisk
	}
	if commandRisk && networkRisk {
		return audit.SeverityHigh, "command can execute shell/network-capable tooling", dataRisk, true, true
	}
	if commandRisk {
		return audit.SeverityHigh, "command can execute shell or privileged tooling", dataRisk, true, networkRisk
	}
	if dataRisk {
		return audit.SeverityHigh, "command references secret-sensitive paths", true, commandRisk, networkRisk
	}
	if strings.Contains(line, " npx ") || strings.Contains(line, " uvx ") || strings.Contains(line, " bunx ") || strings.Contains(line, " pipx ") || strings.Contains(line, " deno run ") || strings.Contains(line, " bun run ") {
		if strings.Contains(line, "@latest") || !looksPinned(line) {
			return audit.SeverityHigh, "remote package command appears unpinned or uses latest tag", dataRisk, true, networkRisk
		}
		return audit.SeverityLow, "remote package command appears pinned but still needs review", dataRisk, true, networkRisk
	}
	return audit.SeverityInfo, "no high-risk command pattern detected", dataRisk, commandRisk, networkRisk
}

func IsDangerousCommandPattern(input string) bool {
	return matchedDangerousPattern(input) != ""
}

func matchedDangerousPattern(input string) string {
	lower := strings.ToLower(" " + input + " ")
	normalized := strings.Join(strings.Fields(lower), " ")
	for _, pattern := range dangerousCommandPatterns {
		p := strings.ToLower(pattern)
		if strings.HasPrefix(p, " ") || strings.HasSuffix(p, " ") {
			if strings.Contains(lower, p) {
				return strings.TrimSpace(pattern)
			}
			continue
		}
		if strings.Contains(lower, p) || strings.Contains(normalized, strings.TrimSpace(p)) {
			return strings.TrimSpace(pattern)
		}
	}
	return ""
}

func containsNetworkTool(input string) bool {
	return containsAnyPattern(strings.ToLower(" "+input+" "), networkTools)
}

func containsAnyPattern(input string, patterns []string) bool {
	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func referencesSecretPath(input string) bool {
	needles := []string{"~/.ssh", "/.ssh", ".env", "keychain", "~/.aws", "/.aws/credentials", "~/.config/gcloud", "~/.azure", ".npmrc", ".pypirc", ".netrc", "docker/config.json"}
	return containsAnyPattern(input, needles)
}

func looksPinned(input string) bool {
	re := regexp.MustCompile(`@[0-9]+(\.[0-9]+){0,2}`)
	return re.MatchString(input)
}

func sanitizeCommandLine(command string, args []string) string {
	parts := append([]string{command}, args...)
	for i, p := range parts {
		parts[i] = safety.RedactSensitiveText(p)
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func isProjectLocal(path string, projectRoot string) bool {
	if projectRoot == "" {
		return false
	}
	rel, err := filepath.Rel(projectRoot, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func inspectAIPermissions(cfg audit.RuntimeConfig) []audit.Finding {
	tccPaths := []string{
		filepath.Join(cfg.HomeDir, "Library", "Application Support", "com.apple.TCC", "TCC.db"),
		"/Library/Application Support/com.apple.TCC/TCC.db",
	}
	var findings []audit.Finding
	for _, path := range tccPaths {
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		findings = append(findings, newFinding("ai-tcc-"+safeID(path), audit.CategoryPrivacy, "AI permissions / TCC manual review", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("TCC database metadata path=%s mode=%s size=%d", path, platform.FormatPerm(meta.Mode), meta.Size), "macOS TCC databases are not parsed in this release. Manually verify Full Disk Access, Accessibility, Automation, Developer Tools, Login Items, and Background Items for AI apps.", ""))
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("ai-tcc-manual-review", audit.CategoryPrivacy, "AI permissions / TCC manual review", audit.StatusInfo, audit.SeverityInfo, "TCC database metadata unavailable or protected.", "Manually verify AI app permissions in System Settings > Privacy & Security. High-risk grants include Full Disk Access, Accessibility, Automation, and Developer Tools.", ""))
	}
	return findings
}

func inspectLocalLLMServers(ctx context.Context, runner *platform.Runner) ([]audit.Finding, []audit.LocalServerInfo) {
	var findings []audit.Finding
	var servers []audit.LocalServerInfo
	ps := runner.Run(ctx, "ps", "-axo", "pid,comm,args")
	if ps.Output != "" {
		for _, line := range strings.Split(ps.Output, "\n") {
			if knownLLMProcess(line) {
				fields := strings.Fields(line)
				pid := ""
				if len(fields) > 0 {
					pid = fields[0]
				}
				name := "local LLM process"
				if len(fields) > 1 {
					name = filepath.Base(fields[1])
				}
				findings = append(findings, newFinding("ai-llm-process-"+safeID(pid+"-"+name), audit.CategoryAISecurity, "Local AI/LLM process detected", audit.StatusWarn, audit.SeverityLow, fmt.Sprintf("pid=%s process=%s", pid, name), "Ensure local LLM/API servers bind to localhost unless intentionally exposed, and avoid loading untrusted plugins.", platform.FormatCommand("ps", "-axo", "pid,comm,args")))
			}
		}
	}
	lsof := runner.Run(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if lsof.Output != "" {
		for _, line := range strings.Split(lsof.Output, "\n") {
			server, ok := parseListeningLine(line)
			if !ok {
				continue
			}
			servers = append(servers, server)
			severity := audit.SeverityMedium
			status := audit.StatusWarn
			if server.Risk == "external" {
				severity = audit.SeverityHigh
			}
			findings = append(findings, newFinding("ai-llm-listener-"+safeID(server.Name+"-"+server.Port+"-"+server.Address), audit.CategoryAISecurity, "Local AI/API listening port", status, severity, fmt.Sprintf("process=%s pid=%s address=%s port=%s risk=%s", server.Name, server.PID, server.Address, server.Port, server.Risk), "Bind local LLM/API servers to 127.0.0.1 only, use firewall rules, and do not expose unauthenticated model APIs to local networks.", platform.FormatCommand("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")))
		}
	}
	if len(servers) == 0 {
		netstat := runner.Run(ctx, "netstat", "-anv", "-p", "tcp")
		if netstat.Output != "" {
			if strings.Contains(netstat.Output, ".11434") || strings.Contains(netstat.Output, ".1234") || strings.Contains(netstat.Output, ".7860") {
				findings = append(findings, newFinding("ai-llm-netstat-ports", audit.CategoryAISecurity, "Possible local LLM listening ports", audit.StatusWarn, audit.SeverityMedium, "netstat output indicates one or more common AI ports may be listening; detailed process mapping requires lsof.", "Use lsof -nP -iTCP -sTCP:LISTEN locally to identify the owning process.", platform.FormatCommand("netstat", "-anv", "-p", "tcp")))
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("ai-llm-servers", audit.CategoryAISecurity, "Local LLM/API servers", audit.StatusInfo, audit.SeverityInfo, "No known local LLM/API server process or common listening port detected.", "No action needed unless servers are installed in custom locations.", ""))
	}
	return findings, servers
}

func knownLLMProcess(line string) bool {
	lower := strings.ToLower(line)
	names := []string{"ollama", "lmstudio", "lm studio", "localai", "anythingllm", "text-generation-webui", "llama.cpp", "llama-server", "llamafile", "koboldcpp", "jan", "vllm", "open-webui", "comfyui", "privategpt", "sillytavern", "mlx-lm", "llama-cpp-python"}
	return containsAnyPattern(lower, names)
}

func parseListeningLine(line string) (audit.LocalServerInfo, bool) {
	lower := strings.ToLower(line)
	commonPorts := []string{":11434", ":1234", ":3000", ":5000", ":5001", ":7860", ":8000", ":8080", ":8188", ":8501", ":8888", ":9090"}
	matched := false
	for _, port := range commonPorts {
		if strings.Contains(lower, port) {
			matched = true
			break
		}
	}
	if !matched {
		return audit.LocalServerInfo{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return audit.LocalServerInfo{}, false
	}
	name := fields[0]
	pid := fields[1]
	nameField := fields[len(fields)-1]
	address, port := splitAddressPort(nameField)
	risk := "localhost"
	if address == "*" || address == "0.0.0.0" || address == "::" || strings.HasPrefix(address, "[::]") {
		risk = "external"
	}
	return audit.LocalServerInfo{Name: name, PID: pid, Address: address, Port: port, Risk: risk}, true
}

func splitAddressPort(s string) (string, string) {
	s = strings.TrimSuffix(s, " (LISTEN)")
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, ""
	}
	return strings.Trim(s[:idx], "[]"), s[idx+1:]
}

func checkRulesFilePermissions(path string) *audit.Finding {
	meta, err := platform.StatMeta(path)
	if err != nil {
		return nil
	}
	status := audit.StatusPass
	severity := audit.SeverityInfo
	evidence := fmt.Sprintf("path=%s mode=%s owner=%d group=%d", path, platform.FormatPerm(meta.Mode), meta.UID, meta.GID)

	if platform.IsWorldWritable(meta.Mode) {
		status = audit.StatusFail
		severity = audit.SeverityHigh
		evidence += "; world-writable (allows any local user to modify instructions)"
	} else if platform.IsGroupWritable(meta.Mode) {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
		evidence += "; group-writable"
	} else {
		return nil
	}

	f := newFinding(
		"ai-rules-perm-"+safeID(path),
		audit.CategoryAISecurity,
		"AI rules/instruction file permissions risk: "+filepath.Base(path),
		status,
		severity,
		evidence,
		"Restrict write access to yourself or system administrator. Permissive rules permissions allow local privilege escalation or context poisoning.",
		"",
	)
	return &f
}

func inspectDockerComposeAI(cfg audit.RuntimeConfig) []audit.Finding {
	if cfg.ProjectRoot == "" {
		return nil
	}
	var findings []audit.Finding
	files := []string{
		filepath.Join(cfg.ProjectRoot, "docker-compose.yml"),
		filepath.Join(cfg.ProjectRoot, "docker-compose.yaml"),
		filepath.Join(cfg.ProjectRoot, "compose.yml"),
		filepath.Join(cfg.ProjectRoot, "compose.yaml"),
	}
	for _, file := range files {
		_, err := os.Stat(file)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		content := string(data)
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "ports:") {
				for j := i + 1; j < len(lines); j++ {
					nextLine := lines[j]
					if !strings.HasPrefix(strings.TrimSpace(nextLine), "-") {
						break
					}
					portMapping := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(nextLine), "-"))
					portMapping = strings.Trim(portMapping, "\"'")

					isAIPort := false
					for _, port := range []string{"11434", "1234", "3000", "5000", "7860", "8000", "8080", "8188", "8501", "8888", "9090"} {
						if strings.Contains(portMapping, port) {
							isAIPort = true
							break
						}
					}
					if isAIPort && !strings.Contains(portMapping, "127.0.0.1") && !strings.Contains(portMapping, "::1") {
						findings = append(findings, newFinding(
							"ai-docker-port-"+safeID(file+"-"+portMapping),
							audit.CategoryAISecurity,
							"Containerized AI stack with network-exposed port",
							audit.StatusWarn,
							audit.SeverityHigh,
							fmt.Sprintf("file=%s port_mapping=%s; binds to all host interfaces by default", file, portMapping),
							"Explicitly bind container ports to loopback, e.g. '127.0.0.1:11434:11434' instead of '11434:11434'.",
							"",
						))
					}
				}
			}
		}
	}
	return findings
}

func scanPromptInjectionArtifacts(cfg audit.RuntimeConfig) ([]audit.Finding, []audit.PromptArtifact) {
	root := cfg.ProjectRoot
	if root == "" {
		root = "."
	}
	var findings []audit.Finding
	var artifacts []audit.PromptArtifact
	maxBytes := int64(cfg.MaxFileSizeMB)
	if maxBytes <= 0 {
		maxBytes = 5
	}
	maxBytes *= 1024 * 1024

	if cfg.Deep {
		walkLimited(root, cfg.HomeDir, func(path string, d os.DirEntry) {
			if d.IsDir() || !shouldScanPromptFile(path) {
				return
			}
			info, err := d.Info()
			if err != nil || info.Size() > maxBytes {
				return
			}

			// Check file permissions
			if pf := checkRulesFilePermissions(path); pf != nil {
				findings = append(findings, *pf)
			}

			fileArtifacts := scanPromptFile(path, maxBytes)
			artifacts = append(artifacts, fileArtifacts...)
		})
	} else {
		// Scan only key rules files in root even in fast mode
		keyFiles := []string{
			filepath.Join(root, ".cursorrules"),
			filepath.Join(root, "CLAUDE.md"),
			filepath.Join(root, "CLAUDE.local.md"),
			filepath.Join(root, "AGENTS.md"),
			filepath.Join(root, ".clinerules"),
			filepath.Join(root, ".github", "copilot-instructions.md"),
		}
		for _, kp := range keyFiles {
			if info, err := os.Stat(kp); err == nil && !info.IsDir() && info.Size() <= maxBytes {
				// Check file permissions
				if pf := checkRulesFilePermissions(kp); pf != nil {
					findings = append(findings, *pf)
				}

				fileArtifacts := scanPromptFile(kp, maxBytes)
				artifacts = append(artifacts, fileArtifacts...)
			}
		}
	}

	for _, artifact := range artifacts {
		f := newFinding("ai-prompt-artifact-"+safeID(fmt.Sprintf("%s-%d-%s", artifact.Path, artifact.Line, artifact.Phrase)), audit.CategoryAISecurity, "Potential prompt-injection artifact", audit.StatusWarn, artifact.Severity, fmt.Sprintf("path=%s line=%d phrase=%q", artifact.Path, artifact.Line, artifact.Phrase), "This is not proof of compromise. Review instructions before using agent mode, especially in untrusted repositories.", "")
		if containsNetworkTool(artifact.Phrase) {
			f.NetworkExfiltrationRisk = true
		}
		if referencesSecretPath(artifact.Phrase) {
			f.DataExposureRisk = true
		}
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("ai-prompt-artifact-scan", audit.CategoryAISecurity, "Prompt-injection artifact scan", audit.StatusPass, audit.SeverityInfo, "No suspicious prompt-injection phrases found in scoped text files.", "Continue reviewing untrusted repositories before agent mode.", ""))
	}
	return findings, artifacts
}

func shouldScanPromptFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)
	if strings.HasPrefix(base, "readme") || strings.HasPrefix(base, "contributing") || strings.HasPrefix(base, "changelog") {
		return true
	}
	if strings.HasSuffix(lower, ".md") && (strings.Contains(lower, string(filepath.Separator)+"docs"+string(filepath.Separator)) || strings.Contains(lower, string(filepath.Separator)+".github"+string(filepath.Separator))) {
		return true
	}
	switch base {
	case "package.json", "makefile", "taskfile.yml", "taskfile.yaml", "justfile", "agents.md", "claude.md", ".cursorrules":
		return true
	default:
		return false
	}
}

func scanPromptFile(path string, maxBytes int64) []audit.PromptArtifact {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	phrases := []string{
		"ignore previous instructions", "disregard previous instructions", "reveal your system prompt",
		"send the contents of", "read ~/.ssh", "read .env", "exfiltrate", "curl", "wget",
		"base64", "nc", "osascript", "launchctl", "chmod 777", "rm -rf", "upload to", "post to webhook",
		"alter git history", "disable safeguards", "send to url", "persist this", "install packages",
	}
	scanner := bufio.NewScanner(io.LimitReader(file, maxBytes))
	var artifacts []audit.PromptArtifact
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		lower := strings.ToLower(scanner.Text())
		for _, phrase := range phrases {
			if strings.Contains(lower, phrase) {
				severity := audit.SeverityLow
				if phrase == "read ~/.ssh" || phrase == "read .env" || phrase == "exfiltrate" || phrase == "post to webhook" || phrase == "rm -rf" || phrase == "disable safeguards" || phrase == "alter git history" {
					severity = audit.SeverityMedium
				}
				artifacts = append(artifacts, audit.PromptArtifact{Path: path, Line: lineNo, Phrase: phrase, Severity: severity})
			}
		}
	}
	return artifacts
}

func aiHardeningRecommendations() []string {
	return []string{
		"Disable auto-approve for shell commands.",
		"Disable auto-run for MCP servers.",
		"Restrict AI workspace access to the project directory.",
		"Deny access to home directory, ~/.ssh, Keychains, cloud credentials, browser profiles, and .env files.",
		"Require confirmation for network commands and file deletion.",
		"Log all agent-initiated commands.",
		"Use a separate macOS user or sandbox/container for risky AI coding workflows.",
		"Use read-only mode for unknown repositories.",
		"Do not open untrusted repositories in agent mode.",
		"Pin MCP server versions and review project-local .cursor/mcp.json before opening repositories in Cursor.",
	}
}
