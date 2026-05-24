package safety

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsPathSafeToRemediate determines if the path can be deleted, disabled, or modified.
func IsPathSafeToRemediate(path string, home string, projectRoot string) bool {
	if path == "" || home == "" {
		return false
	}
	clean := filepath.Clean(path)
	home = filepath.Clean(home)

	if isForbiddenCleanupPath(clean, home) {
		return false
	}

	// 1. Check if allowed under standard cleanup roots (caches, logs, trash, Xcode)
	if IsCleanupAllowed(clean, home) {
		return true
	}

	// 2. Check specific AI tool allowed folders in home directory
	allowedSubdirs := []string{
		filepath.Join(".cache", "huggingface"),
		filepath.Join(".cache", "modelscope"),
		filepath.Join(".cache", "lm-studio"),
		filepath.Join(".cache", "llama.cpp"),
		filepath.Join(".cache", "whisper"),
		filepath.Join(".cache", "pip"),
		filepath.Join(".cache", "uv"),
		filepath.Join(".ollama", "models"),
		filepath.Join(".claude", "skills"),
		filepath.Join(".hermes", "skills"),
		filepath.Join(".hermes-agent", "skills"),
		filepath.Join(".opencode", "skills"),
		filepath.Join(".cursor", "rules"),
		filepath.Join("Library", "Caches"),
		filepath.Join("Library", "Logs"),
		filepath.Join("Library", "Application Support", "Cursor"),
		filepath.Join("Library", "Application Support", "LM Studio"),
		filepath.Join("Library", "Application Support", "Ollama"),
		filepath.Join("Library", "Application Support", "anythingllm-desktop"),
	}

	for _, sub := range allowedSubdirs {
		allowedRoot := filepath.Join(home, sub)
		if clean == allowedRoot || strings.HasPrefix(clean, allowedRoot+string(os.PathSeparator)) {
			return true
		}
	}

	// 3. Check if inside projectRoot workspace
	if projectRoot != "" {
		cleanProj := filepath.Clean(projectRoot)
		if cleanProj != "/" && cleanProj != filepath.VolumeName(cleanProj) {
			if clean == cleanProj || strings.HasPrefix(clean, cleanProj+string(os.PathSeparator)) {
				// Ensure it's not a forbidden hidden directory like .git
				if !strings.Contains(clean, string(os.PathSeparator)+".git"+string(os.PathSeparator)) && !strings.HasSuffix(clean, string(os.PathSeparator)+".git") {
					return true
				}
			}
		}
	}

	return false
}

// DeletePath safely removes a file or folder if it is safe to remediate.
func DeletePath(path string, home string, projectRoot string) error {
	if !IsPathSafeToRemediate(path, home, projectRoot) {
		return fmt.Errorf("path %q is not safe/allowlisted for deletion", path)
	}
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q is a symlink; remediation is blocked for security", path)
	}
	return os.RemoveAll(path)
}

// DisablePath renames an AI skill/rules file by appending .disabled or removing it if already disabled.
func DisablePath(path string, home string, projectRoot string) error {
	originalPath := path
	if strings.HasSuffix(path, ".disabled") {
		originalPath = strings.TrimSuffix(path, ".disabled")
	}

	if !IsPathSafeToRemediate(originalPath, home, projectRoot) {
		return fmt.Errorf("path %q is not safe/allowlisted for modification", originalPath)
	}

	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q is a symlink; remediation is blocked for security", path)
	}

	if strings.HasSuffix(path, ".disabled") {
		// Re-enable
		return os.Rename(path, originalPath)
	} else {
		// Disable
		return os.Rename(path, path+".disabled")
	}
}

// FixAISkill comments out lines that contain suspicious prompt/tool patterns.
func FixAISkill(path string, home string, projectRoot string) error {
	if !IsPathSafeToRemediate(path, home, projectRoot) {
		return fmt.Errorf("path %q is not safe/allowlisted for modification", path)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q is a symlink; remediation is blocked for security", path)
	}
	if info.IsDir() {
		return fmt.Errorf("path %q is a directory, cannot fix inline", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var output bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(content))
	ext := strings.ToLower(filepath.Ext(path))

	isJSON := ext == ".json"
	isMarkdown := ext == ".md" || ext == ".markdown" || ext == ".html"

	modified := false
	for scanner.Scan() {
		line := scanner.Text()
		matches := MatchAISuspiciousPromptPatterns(line)
		if len(matches) > 0 {
			modified = true
			if isJSON {
				for _, match := range matches {
					idx := strings.Index(strings.ToLower(line), match)
					if idx != -1 {
						line = line[:idx] + "[BLOCKED PATTERN: " + match + "]" + line[idx+len(match):]
					}
				}
			} else if isMarkdown {
				line = "<!-- BLOCKED SUSPICIOUS PATTERN: " + line + " -->"
			} else {
				line = "# BLOCKED SUSPICIOUS PATTERN: " + line
			}
		}
		output.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if modified {
		return os.WriteFile(path, output.Bytes(), info.Mode())
	}
	return nil
}

// MatchAISuspiciousPromptPatterns matches suspicious prompt patterns case-insensitively.
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
