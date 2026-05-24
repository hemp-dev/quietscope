package checks

import (
	"strings"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

func TestUnsupportedPlatformFindingUsesSkippedStatus(t *testing.T) {
	f := unsupportedPlatformFindingForOS(platform.OSLinux, "test-skipped", audit.CategorySecurity, "Skipped", "macOS-only check", "macOS")
	if f.Status != audit.StatusSkipped {
		t.Fatalf("expected skipped status, got %s", f.Status)
	}
	if f.Severity != audit.SeverityInfo {
		t.Fatalf("expected info severity, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "linux") {
		t.Fatalf("expected current platform in evidence, got %q", f.Evidence)
	}
}

func TestStorageTargetsArePlatformSpecific(t *testing.T) {
	linuxTargets := storageTargetsForOS(platform.OSLinux, "/home/alice")
	if containsStorageTitle(linuxTargets, "Time Machine local snapshots") {
		t.Fatal("linux storage targets should not include Time Machine")
	}
	if !containsStorageTitle(linuxTargets, "User cache directory") {
		t.Fatal("linux storage targets should include user cache directory")
	}
	windowsTargets := storageTargetsForOS(platform.OSWindows, `C:\Users\Alice`)
	if !containsStorageTitle(windowsTargets, "User temporary files") {
		t.Fatal("windows storage targets should include user temporary files")
	}
}

func containsStorageTitle(targets []storageTarget, title string) bool {
	for _, target := range targets {
		if target.Title == title {
			return true
		}
	}
	return false
}
