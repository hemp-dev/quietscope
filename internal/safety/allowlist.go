package safety

import (
	"os"
	"path/filepath"
	"strings"
)

const CleanupConfirmationPhrase = "DELETE SAFE CACHE FILES"

func IsCleanupAllowed(path string, home string) bool {
	if path == "" || home == "" {
		return false
	}
	clean := filepath.Clean(path)
	home = filepath.Clean(home)
	if isForbiddenCleanupPath(clean, home) {
		return false
	}
	allowedRoots := []string{
		filepath.Join(home, "Library", "Caches"),
		filepath.Join(home, "Library", "Logs"),
		filepath.Join(home, ".Trash"),
		filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"),
	}
	for _, root := range allowedRoots {
		root = filepath.Clean(root)
		if clean != root && strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	userTmp := os.TempDir()
	if userTmp != "" {
		userTmp = filepath.Clean(userTmp)
		if strings.Contains(userTmp, "/var/folders/") && clean != userTmp && strings.HasPrefix(clean, userTmp+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func IsManageablePathAllowed(path string, home string, projectRoot string) bool {
	if path == "" || home == "" {
		return false
	}
	clean := filepath.Clean(path)
	home = filepath.Clean(home)
	if isForbiddenCleanupPath(clean, home) || IsSecretPath(clean, home) {
		return false
	}
	if strings.HasSuffix(clean, ".disabled") {
		return IsManageablePathAllowed(strings.TrimSuffix(clean, ".disabled"), home, projectRoot)
	}
	for _, root := range manageableHomeRoots(home) {
		root = filepath.Clean(root)
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	if projectRoot == "" {
		return false
	}
	projectRoot = filepath.Clean(projectRoot)
	if projectRoot == "/" || projectRoot == filepath.VolumeName(projectRoot) {
		return false
	}
	if clean != projectRoot && !strings.HasPrefix(clean, projectRoot+string(os.PathSeparator)) {
		return false
	}
	rel, err := filepath.Rel(projectRoot, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return false
	}
	return isManageableProjectRel(rel)
}

func IsSecretPath(path string, home string) bool {
	clean := filepath.Clean(path)
	home = filepath.Clean(home)
	secretRoots := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".azure"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, "Library", "Keychains"),
	}
	for _, root := range secretRoots {
		root = filepath.Clean(root)
		if clean == root || strings.HasPrefix(clean, root+string(os.PathSeparator)) {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(clean))
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	if strings.Contains(base, "id_rsa") || strings.Contains(base, "id_ed25519") || strings.Contains(base, "private_key") {
		return true
	}
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") {
		return true
	}
	return false
}

func manageableHomeRoots(home string) []string {
	return []string{
		filepath.Join(home, ".claude", "skills"),
		filepath.Join(home, ".claude", "commands"),
		filepath.Join(home, ".claude", "memory"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude_desktop_config.json"),
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, ".codex", "instructions.md"),
		filepath.Join(home, ".gemini"),
		filepath.Join(home, ".agents"),
		filepath.Join(home, ".antigravity"),
		filepath.Join(home, ".cursor", "rules"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".opencode"),
		filepath.Join(home, ".hermes"),
		filepath.Join(home, ".hermes-agent"),
		filepath.Join(home, ".config", "opencode"),
		filepath.Join(home, ".config", "hermes"),
		filepath.Join(home, ".config", "hermes-agent"),
		filepath.Join(home, ".config", "gemini"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, "Library", "Application Support", "Cursor", "User", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json"),
		filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json"),
	}
}

func isManageableProjectRel(rel string) bool {
	clean := filepath.Clean(rel)
	base := strings.ToLower(filepath.Base(clean))
	lower := strings.ToLower(clean)
	switch base {
	case "agents.md", "claude.md", "gemini.md", ".cursorrules", ".windsurfrules",
		"instructions.md", "rules.md", "prompts.md", "system_prompt.md", "ai.md",
		"mcp.json", "mcp.toml", "mcp.yaml", "mcp.yml", "mcp_config.json", "mcp_config.toml", "mcp_config.yaml", "mcp_config.yml", "claude_desktop_config.json",
		"settings.json", "config.toml", "opencode.json", "opencode.yaml", "opencode.yml", "opencode.toml",
		"hermes.json", "hermes.yaml", "hermes.yml", "hermes.toml",
		".aider.conf.yml", ".aiderignore":
		return !strings.Contains(lower, string(os.PathSeparator)+".git"+string(os.PathSeparator))
	}
	allowedPrefixes := []string{
		".claude", ".codex", ".gemini", ".agents", ".antigravity", ".cursor",
		".continue", ".cline", ".roo", ".windsurf", ".opencode", ".hermes", ".hermes-agent",
		filepath.Join(".github", "copilot-instructions.md"),
		filepath.Join(".vscode", "settings.json"),
		filepath.Join(".vscode", "mcp.json"),
		"agents", "skills", "prompts", "rules",
	}
	for _, prefix := range allowedPrefixes {
		prefix = filepath.Clean(prefix)
		if clean == prefix || strings.HasPrefix(clean, prefix+string(os.PathSeparator)) {
			return !strings.Contains(lower, string(os.PathSeparator)+".git"+string(os.PathSeparator))
		}
	}
	return false
}

func isForbiddenCleanupPath(path string, home string) bool {
	forbidden := []string{
		"/System",
		"/Library",
		filepath.Join(home, "Library", "Keychains"),
		filepath.Join(home, "Library", "Mail"),
		filepath.Join(home, "Library", "Messages"),
		filepath.Join(home, "Library", "Safari"),
		filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
		filepath.Join(home, "Library", "Application Support", "Firefox"),
		filepath.Join(home, "Library", "Application Support", "BraveSoftware"),
		filepath.Join(home, "Pictures", "Photos Library.photoslibrary"),
		filepath.Join(home, "Library", "Mobile Documents"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".azure"),
		filepath.Join(home, ".config", "gcloud"),
	}
	for _, item := range forbidden {
		item = filepath.Clean(item)
		if path == item || strings.HasPrefix(path, item+string(os.PathSeparator)) {
			return true
		}
	}
	base := filepath.Base(path)
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.Contains(strings.ToLower(base), "credential") || strings.Contains(strings.ToLower(base), "secret") {
		return true
	}
	return false
}
