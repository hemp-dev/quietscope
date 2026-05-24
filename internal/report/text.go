package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

func WriteText(path string, report audit.Report) error {
	var b strings.Builder
	writeHeader(&b, "Executive Summary")
	fmt.Fprintf(&b, "Tool: %s %s\n", report.Metadata.ToolName, report.Metadata.Version)
	fmt.Fprintf(&b, "Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "Output directory: %s\n", report.Metadata.OutputDir)
	fmt.Fprintf(&b, "Defensive local audit only. No telemetry, no report upload, no automatic cleanup.\n")

	writeHeader(&b, "System Overview")
	keys := make([]string, 0, len(report.SystemInfo))
	for k := range report.SystemInfo {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, report.SystemInfo[k])
	}

	writeHeader(&b, "Overall Risk Score")
	fmt.Fprintf(&b, "Score: %d/100\n", report.Summary.OverallRiskScore)
	fmt.Fprintf(&b, "Risk level: %s\n", report.Summary.RiskLevel)
	fmt.Fprintf(&b, "Total findings: %d | PASS: %d | WARN: %d | FAIL: %d | INFO: %d | SKIPPED: %d\n", report.Summary.TotalFindings, report.Summary.PassCount, report.Summary.WarnCount, report.Summary.FailCount, report.Summary.InfoCount, report.Summary.SkippedCount)
	fmt.Fprintf(&b, "Critical: %d | High: %d | Medium: %d | Low: %d\n", report.Summary.CriticalCount, report.Summary.HighCount, report.Summary.MediumCount, report.Summary.LowCount)
	fmt.Fprintf(&b, "Cleanup reclaimable: %s\n", platform.HumanBytes(report.Summary.CleanupReclaimableBytes))
	fmt.Fprintf(&b, "AI risk count: %d | Secrets exposure count: %d\n", report.Summary.AIRiskCount, report.Summary.SecretsExposureCount)

	sections := []struct {
		title      string
		categories []audit.Category
	}{
		{"Security Findings", []audit.Category{audit.CategorySecurity}},
		{"Update Status", []audit.Category{audit.CategoryUpdates}},
		{"Persistence Items", []audit.Category{audit.CategoryPersistence}},
		{"Permissions Issues", []audit.Category{audit.CategoryPermissions}},
		{"Privacy & Secrets", []audit.Category{audit.CategoryPrivacy, audit.CategorySecrets}},
		{"Storage and Caches", []audit.Category{audit.CategoryStorage}},
		{"Cleanup Candidates", []audit.Category{audit.CategoryCleanup}},
		{"AI Local Security", []audit.Category{audit.CategoryAISecurity}},
		{"Local LLM Servers", []audit.Category{audit.CategoryAISecurity}},
		{"MCP Config Risks", []audit.Category{audit.CategoryAISecurity}},
		{"Prompt Injection Artifacts", []audit.Category{audit.CategoryAISecurity}},
	}
	for _, section := range sections {
		writeHeader(&b, section.title)
		writeFindings(&b, report.Findings, section.categories)
	}

	writeAIContextInventory(&b, report)
	writeAIToolCatalog(&b, report)

	writeHeader(&b, "Recommended Next Steps")
	fmt.Fprintln(&b, "1. Review high and medium severity findings first.")
	fmt.Fprintln(&b, "2. Manually verify macOS privacy permissions for AI tools.")
	fmt.Fprintln(&b, "3. Review project-local MCP configs before opening repositories in agent mode.")
	fmt.Fprintln(&b, "4. Run --clean-dry-run before considering --clean-confirm.")
	fmt.Fprintln(&b, "5. Keep audit reports private; they contain local paths and system metadata.")

	writeHeader(&b, "Manual Checks")
	fmt.Fprintln(&b, "- Available macOS updates may require manual softwareupdate --list or System Settings review.")
	fmt.Fprintln(&b, "- TCC permissions are reported as manual review in this release.")
	fmt.Fprintln(&b, "- This tool is not an antivirus, EDR, malware remover, or CIS compliance replacement.")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func writeAIContextInventory(b *strings.Builder, report audit.Report) {
	writeHeader(b, "AI Skills & Context Inventory")
	summary := report.AIContextSummary
	fmt.Fprintf(b, "Total AI-related directories: %d\n", summary.TotalAIDirectories)
	fmt.Fprintf(b, "Total AI-related disk usage: %s\n", platform.HumanBytes(summary.TotalAIDirectorySizeBytes))
	fmt.Fprintf(b, "AI context artifacts: %d\n", summary.TotalAIContextArtifacts)
	fmt.Fprintf(b, "Critical context impact: %d\n", summary.CriticalContextImpactCount)
	fmt.Fprintf(b, "High context impact: %d\n", summary.HighContextImpactCount)
	fmt.Fprintf(b, "World-writable AI artifacts: %d\n", summary.WorldWritableAIArtifactsCount)
	fmt.Fprintf(b, "Suspicious skill/prompt patterns: %d\n", summary.SuspiciousAIPromptPatternsCount)
	fmt.Fprintln(b, "Context impact estimates whether a file or directory may influence AI-agent behavior or enter AI context. It is not a malware verdict.")

	fmt.Fprintln(b, "\nTop largest AI directories:")
	for i, dir := range report.AIRelatedDirectories {
		if i >= 10 {
			break
		}
		fmt.Fprintf(b, "- %s | %s | %s | files=%d | impact=%s | cleanup_candidate=%t\n", dir.ToolName, dir.Path, dir.HumanSize, dir.FileCount, dir.ContextImpact, dir.CleanupCandidate)
	}
	if len(report.AIRelatedDirectories) == 0 {
		fmt.Fprintln(b, "- None found.")
	}

	fmt.Fprintln(b, "\nCritical/high context impact artifacts:")
	foundHigh := false
	for _, artifact := range report.AIContextInventory {
		if artifact.ContextImpact != "critical" && artifact.ContextImpact != "high" {
			continue
		}
		foundHigh = true
		fmt.Fprintf(b, "- %s | %s | %s | %s | auto_loaded=%s | score=%d | permissions=%s\n", artifact.ToolName, artifact.ArtifactType, artifact.Scope, artifact.Path, artifact.AutoLoadedLikelihood, artifact.ContextImpactScore, artifact.Permissions)
	}
	if !foundHigh {
		fmt.Fprintln(b, "- None found.")
	}

	fmt.Fprintln(b, "\nWorld-writable AI instruction/context files:")
	foundWritable := false
	for _, artifact := range report.AIContextInventory {
		if !artifact.IsWorldWritable {
			continue
		}
		foundWritable = true
		fmt.Fprintf(b, "- %s | %s | %s | %s\n", artifact.ToolName, artifact.ArtifactType, artifact.Permissions, artifact.Path)
	}
	if !foundWritable {
		fmt.Fprintln(b, "- None found.")
	}

	fmt.Fprintln(b, "\nSuspicious skill/prompt patterns:")
	foundPatterns := false
	for _, artifact := range report.AIContextInventory {
		for _, pattern := range artifact.SuspiciousPatterns {
			foundPatterns = true
			fmt.Fprintf(b, "- %s:%d | %s | %s\n", artifact.Path, pattern.Line, pattern.Pattern, pattern.Snippet)
		}
	}
	if !foundPatterns {
		fmt.Fprintln(b, "- None found or --deep not enabled.")
	}

	fmt.Fprintln(b, "\nRecommended review steps:")
	fmt.Fprintln(b, "1. Review project-local AGENTS.md, CLAUDE.md, .cursor/rules, .cursorrules, and MCP configs before agent mode.")
	fmt.Fprintln(b, "2. Treat context impact as influence likelihood, not proof of malicious behavior.")
	fmt.Fprintln(b, "3. Restrict write permissions on AI instruction files.")
	fmt.Fprintln(b, "4. Review AI model directories manually; large model files are not cleanup trash.")
}

func writeAIToolCatalog(b *strings.Builder, report audit.Report) {
	writeHeader(b, "AI Tool Catalog")
	summary := report.AIProviderSummary
	fmt.Fprintf(b, "Detected AI tools: %d\n", summary.TotalAIToolsDetected)
	fmt.Fprintf(b, "Detected MCP clients: %d\n", summary.TotalMCPClientsDetected)
	fmt.Fprintf(b, "Configured MCP servers: %d\n", summary.TotalMCPServersDetected)
	fmt.Fprintf(b, "Hermes detected: %t\n", summary.HermesDetected)
	fmt.Fprintf(b, "OpenCode detected: %t\n", summary.OpenCodeDetected)
	fmt.Fprintf(b, "Chinese providers detected: %d\n", summary.ChineseProvidersDetected)
	fmt.Fprintf(b, "Remote provider env keys detected: %d\n", summary.RemoteProviderEnvKeysDetected)
	fmt.Fprintf(b, "Local model/cache size: %s\n", platform.HumanBytes(summary.LocalModelCacheSizeBytes))
	fmt.Fprintf(b, "Non-loopback AI servers: %d\n", summary.NonLoopbackAIServers)
	fmt.Fprintln(b, "Tool detection is not a risk verdict. Risk depends on permissions, context, shell access, MCP tools, remote provider usage, and exposed servers.")

	fmt.Fprintln(b, "\nDetected AI tools:")
	if len(report.AIToolCatalog) == 0 {
		fmt.Fprintln(b, "- None found.")
	}
	for _, tool := range report.AIToolCatalog {
		fmt.Fprintf(b, "- %s | vendor=%s | categories=%s | configs=%d | caches=%d | logs=%d | disk=%s\n", tool.DisplayName, tool.Vendor, strings.Join(tool.Categories, ","), len(tool.ConfigPaths), len(tool.CachePaths), len(tool.LogPaths), platform.HumanBytes(tool.DiskUsageBytes))
	}

	writeHeader(b, "Hermes Agent")
	if report.HermesAgent.Detected {
		fmt.Fprintf(b, "Detected: true\nConfig paths: %s\nSkills: %s\nMemory: %s\nCommands: %s\nEnv keys: %s\nSize: %s\nContext impact: %s\n", strings.Join(report.HermesAgent.ConfigPaths, "; "), strings.Join(report.HermesAgent.SkillPaths, "; "), strings.Join(report.HermesAgent.MemoryPaths, "; "), strings.Join(report.HermesAgent.CommandPaths, "; "), strings.Join(report.HermesAgent.EnvKeysDetected, ", "), platform.HumanBytes(report.HermesAgent.SizeBytes), report.HermesAgent.ContextImpact)
	} else {
		fmt.Fprintln(b, "Detected: false")
	}

	writeHeader(b, "OpenCode / opencode")
	if report.OpenCode.Detected {
		fmt.Fprintf(b, "Detected: true\nApps: %s\nBinaries: %s\nConfigs: %s\nAgents: %s\nPrompts/rules/skills: %s\nEnv keys: %s\nSize: %s\nContext impact: %s\n", strings.Join(report.OpenCode.AppPaths, "; "), strings.Join(report.OpenCode.BinaryPaths, "; "), strings.Join(report.OpenCode.ConfigPaths, "; "), strings.Join(report.OpenCode.AgentPaths, "; "), strings.Join(report.OpenCode.PromptRulePaths, "; "), strings.Join(report.OpenCode.EnvKeysDetected, ", "), platform.HumanBytes(report.OpenCode.SizeBytes), report.OpenCode.ContextImpact)
	} else {
		fmt.Fprintln(b, "Detected: false")
	}

	writeHeader(b, "MCP Servers")
	if len(report.MCPServers) == 0 {
		fmt.Fprintln(b, "No configured MCP servers found.")
	}
	for _, server := range report.MCPServers {
		fmt.Fprintf(b, "- %s | category=%s | scope=%s | config=%s | command=%s | env_keys=%s | risks=cmd:%t fs:%t net:%t cred:%t cloud:%t browser:%t\n", server.ServerName, server.RiskCategory, server.Scope, server.ConfigPath, server.Command, strings.Join(server.EnvKeysOnly, ","), server.CommandExecutionRisk, server.FilesystemAccessRisk, server.NetworkExfiltrationRisk, server.CredentialAccessRisk, server.CloudAccessRisk, server.BrowserAutomationRisk)
	}

	writeHeader(b, "Chinese AI Models & Providers")
	fmt.Fprintln(b, "Provider origin is not a risk by itself. Risk is based on remote API usage, broad context sharing, exposed tokens, unsafe agent permissions, logs/caches, and exposed local servers.")
	if len(report.ChineseAIProviders) == 0 {
		fmt.Fprintln(b, "No Chinese provider/model artifacts detected.")
	}
	for _, provider := range report.ChineseAIProviders {
		fmt.Fprintf(b, "- %s | vendor=%s | env_keys=%s | configs=%d | caches=%d | cli=%s | project_mentions=%d | cache_size=%s | risk=%s\n", provider.DisplayName, provider.Vendor, strings.Join(provider.EnvKeysDetected, ","), len(provider.ConfigPaths), len(provider.CachePaths), strings.Join(provider.CLINamesDetected, ","), len(provider.ProjectMentions), platform.HumanBytes(provider.LocalCacheSizeBytes), provider.RiskLevel)
	}

	writeHeader(b, "Local Model Inventory")
	if len(report.LocalModelInventory) == 0 {
		fmt.Fprintln(b, "No local model/cache directories found in known locations.")
	}
	for _, model := range report.LocalModelInventory {
		fmt.Fprintf(b, "- %s | provider_hint=%s | path=%s | size=%s | files=%d | auto_clean=%t\n", model.ToolName, model.ProviderHint, model.Path, model.HumanSize, model.FileCount, model.SafeToAutoClean)
	}

	writeHeader(b, "AI Security Tools")
	if len(report.AISecurityTools) == 0 {
		fmt.Fprintln(b, "No AI security scanner configs found in scoped project paths.")
	}
	for _, tool := range report.AISecurityTools {
		fmt.Fprintf(b, "- %s | positive_signal=%t | paths=%s\n", tool.Name, tool.PositiveSignal, strings.Join(tool.Paths, "; "))
	}
}

func writeHeader(b *strings.Builder, title string) {
	fmt.Fprintf(b, "\n== %s ==\n", title)
}

func writeFindings(b *strings.Builder, findings []audit.Finding, categories []audit.Category) {
	count := 0
	for _, f := range findings {
		if !categoryIn(f.Category, categories) {
			continue
		}
		count++
		fmt.Fprintf(b, "\n[%s/%s] %s\n", f.Status, f.Severity, f.Title)
		fmt.Fprintf(b, "ID: %s\n", f.ID)
		if f.Evidence != "" {
			fmt.Fprintf(b, "Evidence: %s\n", f.Evidence)
		}
		if f.CommandChecked != "" {
			fmt.Fprintf(b, "Command checked: %s\n", f.CommandChecked)
		}
		if f.Recommendation != "" {
			fmt.Fprintf(b, "Recommendation: %s\n", f.Recommendation)
		}
	}
	if count == 0 {
		fmt.Fprintln(b, "No findings in this section.")
	}
}

func categoryIn(category audit.Category, categories []audit.Category) bool {
	for _, c := range categories {
		if category == c {
			return true
		}
	}
	return false
}
