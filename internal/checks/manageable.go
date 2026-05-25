package checks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/safety"
)

func manageableForAIArtifacts(artifacts []audit.AIContextArtifact, cfg audit.RuntimeConfig) []audit.ManageableArtifact {
	out := make([]audit.ManageableArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		out = append(out, manageableForAIArtifact(artifact, cfg))
	}
	return out
}

func manageableForAIDirectories(dirs []audit.AIRelatedDirectory, cfg audit.RuntimeConfig) []audit.ManageableArtifact {
	out := make([]audit.ManageableArtifact, 0, len(dirs))
	for _, dir := range dirs {
		artifact := audit.ManageableArtifact{
			ID:              "ai-dir-" + safeID(dir.Path),
			Path:            dir.Path,
			Tool:            dir.ToolName,
			Kind:            dir.Category,
			Scope:           scopeForPath(dir.Path, cfg),
			Risk:            dir.ContextImpact,
			LiveOnly:        true,
			BackupAvailable: safety.BackupAvailableForPath(dir.Path, cfg.HomeDir),
		}
		switch dir.Category {
		case "cache", "logs":
			allowed := safety.IsCleanupAllowed(dir.Path, cfg.HomeDir)
			artifact.SafeActions = []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionClean, allowed, disabledReason(allowed, "Not in allowlisted cleanup roots"), true, true),
				actionAvailability(audit.ArtifactActionRestore, artifact.BackupAvailable, disabledReason(artifact.BackupAvailable, "No backup available"), true, true),
			}
		case "models":
			artifact.DisabledReason = "Manual-only model directory"
			artifact.SafeActions = []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionClean, false, "Manual-only model directory", true, true),
				actionAvailability(audit.ArtifactActionDelete, false, "Model deletion is manual-only", true, true),
				actionAvailability(audit.ArtifactActionRestore, artifact.BackupAvailable, disabledReason(artifact.BackupAvailable, "No backup available"), true, true),
			}
		default:
			artifact.SafeActions = []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionRestore, artifact.BackupAvailable, disabledReason(artifact.BackupAvailable, "No backup available"), true, true),
			}
		}
		out = append(out, artifact)
	}
	return out
}

func manageableForCleanupCandidates(candidates []audit.CleanupCandidate, cfg audit.RuntimeConfig) []audit.ManageableArtifact {
	out := make([]audit.ManageableArtifact, 0, len(candidates))
	for _, c := range candidates {
		allowed := c.SafeToAutoFix && safety.IsCleanupAllowed(c.Path, cfg.HomeDir)
		backupAvailable := safety.BackupAvailableForPath(c.Path, cfg.HomeDir)
		out = append(out, audit.ManageableArtifact{
			ID:              "cleanup-" + safeID(c.Path),
			Path:            c.Path,
			Tool:            "quietscope",
			Kind:            "cache",
			Scope:           scopeForPath(c.Path, cfg),
			Risk:            c.Risk,
			LiveOnly:        true,
			BackupAvailable: backupAvailable,
			SafeActions: []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionClean, allowed, disabledReason(allowed, "Not an allowlisted cleanup candidate"), true, true),
				actionAvailability(audit.ArtifactActionRestore, backupAvailable, disabledReason(backupAvailable, "No backup available"), true, true),
			},
		})
	}
	return out
}

func manageableForMCPServers(servers []audit.MCPServerCatalogItem, cfg audit.RuntimeConfig) []audit.ManageableArtifact {
	out := make([]audit.ManageableArtifact, 0, len(servers))
	for _, server := range servers {
		allowed := safety.IsManageablePathAllowed(server.ConfigPath, cfg.HomeDir, cfg.ProjectRoot)
		reason := disabledReason(allowed, "Unsupported or non-allowlisted MCP config path")
		backupAvailable := safety.BackupAvailableForPath(server.ConfigPath, cfg.HomeDir)
		out = append(out, audit.ManageableArtifact{
			ID:              "mcp-" + safeID(server.ConfigPath+"-"+server.ServerName),
			Path:            server.ConfigPath,
			Tool:            server.ServerName,
			Kind:            "mcp_server",
			Scope:           server.Scope,
			Risk:            server.RiskCategory,
			DisabledReason:  reason,
			LiveOnly:        true,
			BackupAvailable: backupAvailable,
			SafeActions: []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionRead, allowed, reason, false, false),
				actionAvailability(audit.ArtifactActionEdit, allowed, reason, true, true),
				actionAvailability(audit.ArtifactActionDisable, allowed, reason, true, true),
				actionAvailability(audit.ArtifactActionEnable, allowed, reason, true, true),
				actionAvailability(audit.ArtifactActionDelete, allowed, reason, true, true),
				actionAvailability(audit.ArtifactActionRestore, backupAvailable, disabledReason(backupAvailable, "No backup available"), true, true),
			},
		})
	}
	return out
}

func manageableForLocalModels(models []audit.LocalModelInventoryItem, cfg audit.RuntimeConfig) []audit.ManageableArtifact {
	out := make([]audit.ManageableArtifact, 0, len(models))
	for _, model := range models {
		backupAvailable := safety.BackupAvailableForPath(model.Path, cfg.HomeDir)
		out = append(out, audit.ManageableArtifact{
			ID:              "model-" + safeID(model.Path),
			Path:            model.Path,
			Tool:            model.ToolName,
			Kind:            "model",
			Scope:           scopeForPath(model.Path, cfg),
			Risk:            "manual-only",
			DisabledReason:  "Manual-only model directory",
			LiveOnly:        true,
			BackupAvailable: backupAvailable,
			SafeActions: []audit.ActionAvailability{
				actionAvailability(audit.ArtifactActionClean, false, "Manual-only model directory", true, true),
				actionAvailability(audit.ArtifactActionDelete, false, "Model deletion is manual-only", true, true),
				actionAvailability(audit.ArtifactActionRestore, backupAvailable, disabledReason(backupAvailable, "No backup available"), true, true),
			},
		})
	}
	return out
}

func manageableForAIArtifact(artifact audit.AIContextArtifact, cfg audit.RuntimeConfig) audit.ManageableArtifact {
	allowed := safety.IsManageablePathAllowed(artifact.Path, cfg.HomeDir, cfg.ProjectRoot)
	reason := disabledReason(allowed, "Unsupported or non-allowlisted artifact path")
	backupAvailable := safety.BackupAvailableForPath(artifact.Path, cfg.HomeDir)
	isDir := artifact.FileCount > 0
	if info, err := os.Lstat(artifact.Path); err == nil {
		isDir = info.IsDir()
	}
	editable := allowed && !isDir && isInlineEditableArtifact(artifact.ArtifactType, artifact.Path)
	fixable := editable && len(artifact.SuspiciousPatterns) > 0
	disableable := allowed && isDisableableArtifact(artifact.ArtifactType, isDir)
	deletable := allowed && !isDir && artifact.ArtifactType != "settings"
	if isDir && (artifact.ArtifactType == "skill" || artifact.ArtifactType == "rule" || artifact.ArtifactType == "prompt") {
		deletable = allowed
	}
	artifactReason := reason
	if allowed && isDir && !disableable && !deletable {
		artifactReason = "Directory actions require manual review"
	}
	return audit.ManageableArtifact{
		ID:              "ai-artifact-" + safeID(artifact.Path),
		Path:            artifact.Path,
		Tool:            artifact.ToolName,
		Kind:            artifact.ArtifactType,
		Scope:           artifact.Scope,
		Risk:            artifact.ContextImpact,
		DisabledReason:  artifactReason,
		LiveOnly:        true,
		BackupAvailable: backupAvailable,
		SafeActions: []audit.ActionAvailability{
			actionAvailability(audit.ArtifactActionRead, editable || (allowed && !isDir), disabledReason(editable || (allowed && !isDir), "Only safe text artifacts can be read"), false, false),
			actionAvailability(audit.ArtifactActionEdit, editable, disabledReason(editable, "Inline edit is limited to safe text guides, skills, prompts, rules, and settings"), true, true),
			actionAvailability(audit.ArtifactActionDisable, disableable, disabledReason(disableable, "Disable is limited to safe behavior artifacts"), true, true),
			actionAvailability(audit.ArtifactActionEnable, strings.HasSuffix(artifact.Path, ".disabled") && allowed, disabledReason(strings.HasSuffix(artifact.Path, ".disabled") && allowed, "Artifact is not disabled"), true, true),
			actionAvailability(audit.ArtifactActionDelete, deletable, disabledReason(deletable, "Delete requires a safe allowlisted artifact, and settings/model directories are manual-only"), true, true),
			actionAvailability(audit.ArtifactActionFix, fixable, disabledReason(fixable, "No suspicious patterns detected or file is not inline-editable"), true, true),
			actionAvailability(audit.ArtifactActionRestore, backupAvailable, disabledReason(backupAvailable, "No backup available"), true, true),
		},
	}
}

func isInlineEditableArtifact(kind string, path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch kind {
	case "instruction", "skill", "rule", "prompt", "memory", "settings", "agent_manifest", "tool_manifest", "generic_context":
		return ext == ".md" || ext == ".markdown" || ext == ".txt" || ext == ".json" || ext == ".toml" || ext == ".yaml" || ext == ".yml" || ext == ""
	default:
		return false
	}
}

func isDisableableArtifact(kind string, isDir bool) bool {
	switch kind {
	case "instruction", "skill", "rule", "prompt", "memory", "agent_manifest", "tool_manifest", "mcp_config":
		return true
	case "generic_context":
		return !isDir
	default:
		return false
	}
}

func actionAvailability(action audit.ArtifactAction, available bool, reason string, preview bool, backup bool) audit.ActionAvailability {
	return audit.ActionAvailability{
		Action:          action,
		Available:       available,
		DisabledReason:  disabledReason(available, reason),
		RequiresPreview: preview,
		RequiresBackup:  backup,
	}
}

func disabledReason(available bool, reason string) string {
	if available {
		return ""
	}
	return reason
}
