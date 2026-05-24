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
