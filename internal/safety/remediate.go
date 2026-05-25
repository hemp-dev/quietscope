package safety

import (
	"bufio"
	"bytes"
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

	if isForbiddenCleanupPath(clean, home) || IsSecretPath(clean, home) {
		return false
	}

	// 1. Check if allowed under standard cleanup roots (caches, logs, trash, Xcode)
	if IsCleanupAllowed(clean, home) {
		return true
	}

	// 2. Check specific AI tool allowed folders in home directory
	allowedSubdirs := []string{
		filepath.Join(".cache", "pip"),
		filepath.Join(".cache", "uv"),
		filepath.Join("Library", "Caches"),
		filepath.Join("Library", "Logs"),
	}

	for _, sub := range allowedSubdirs {
		allowedRoot := filepath.Join(home, sub)
		if clean == allowedRoot || strings.HasPrefix(clean, allowedRoot+string(os.PathSeparator)) {
			return true
		}
	}

	return IsManageablePathAllowed(clean, home, projectRoot)
}

// DeletePath safely removes a file or folder if it is safe to remediate.
func DeletePath(path string, home string, projectRoot string) error {
	_, err := ExecuteAction(ActionRequest{Action: string(ActionDelete), Path: path, Home: home, ProjectRoot: projectRoot})
	return err
}

// DisablePath renames an AI skill/rules file by appending .disabled or removing it if already disabled.
func DisablePath(path string, home string, projectRoot string) error {
	action := string(ActionDisable)
	if strings.HasSuffix(path, ".disabled") {
		action = string(ActionEnable)
	}
	_, err := ExecuteAction(ActionRequest{Action: action, Path: path, Home: home, ProjectRoot: projectRoot})
	return err
}

// FixAISkill comments out lines that contain suspicious prompt/tool patterns.
func FixAISkill(path string, home string, projectRoot string) error {
	_, err := ExecuteAction(ActionRequest{Action: string(ActionFix), Path: path, Home: home, ProjectRoot: projectRoot})
	return err
}

func fixedAISkillContent(path string, content []byte) ([]byte, bool, error) {
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
		return nil, false, err
	}

	return output.Bytes(), modified, nil
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
