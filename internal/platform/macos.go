package platform

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func IsMacOS() bool {
	return IsDarwin()
}

func HomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func CurrentUsername() string {
	u, err := user.Current()
	if err == nil && u.Username != "" {
		if idx := strings.LastIndex(u.Username, "\\"); idx >= 0 {
			return u.Username[idx+1:]
		}
		return u.Username
	}
	return os.Getenv("USER")
}

func ExpandHome(path string, home string) string {
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return path
}
