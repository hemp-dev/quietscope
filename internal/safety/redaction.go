package safety

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

var sensitiveNamePattern = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH|CREDENTIAL)`)
var assignmentPattern = regexp.MustCompile(`(?i)((token|secret|password|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)\s*[:=]\s*)(["']?)[^\s"',;]+`)
var flagValuePattern = regexp.MustCompile(`(?i)((--?(token|secret|password|api-key|apikey|key|auth|credential)\s+))([^\s"',;]+)`)

func IsSensitiveEnvName(name string) bool {
	return sensitiveNamePattern.MatchString(name)
}

func MaskSensitiveValue(name string, value string) string {
	if IsSensitiveEnvName(name) && value != "" {
		return "***MASKED***"
	}
	return value
}

func RedactSensitiveText(input string) string {
	redacted := assignmentPattern.ReplaceAllString(input, `${1}${3}***MASKED***`)
	redacted = flagValuePattern.ReplaceAllString(redacted, `${1}***MASKED***`)
	redacted = redactLikelyBearer(redacted)
	return redacted
}

func redactLikelyBearer(input string) string {
	re := regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._~+/=-]{12,}`)
	return re.ReplaceAllString(input, `${1}***MASKED***`)
}

func MaskPath(path string, home string, username string) string {
	if path == "" {
		return ""
	}
	clean := filepath.Clean(path)
	if home != "" {
		homeClean := filepath.Clean(home)
		if clean == homeClean {
			return "~"
		}
		if strings.HasPrefix(clean, homeClean+string(filepath.Separator)) {
			clean = "~" + strings.TrimPrefix(clean, homeClean)
		}
	}
	if username != "" {
		clean = strings.ReplaceAll(clean, "/Users/"+username, "/Users/<user>")
		clean = strings.ReplaceAll(clean, username, "<user>")
	}
	return clean
}

func SafeJSONString(input string) string {
	b, err := json.Marshal(input)
	if err != nil {
		return `""`
	}
	return string(b)
}
