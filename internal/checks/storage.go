package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

func RunStorage(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	var findings []audit.Finding
	targets := storageTargets(cfg.HomeDir)
	for _, target := range targets {
		size, err := platform.DirectorySize(target.Path, cfg.HomeDir)
		if err != nil {
			findings = append(findings, newFinding("storage-"+safeID(target.Path), audit.CategoryStorage, target.Title, audit.StatusInfo, audit.SeverityInfo, err.Error(), target.Recommendation, ""))
			continue
		}
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		if size == 0 {
			status = audit.StatusPass
		} else if size >= target.WarnBytes {
			status = audit.StatusWarn
			severity = audit.SeverityLow
		}
		f := newFinding("storage-"+safeID(target.Path), audit.CategoryStorage, target.Title, status, severity, fmt.Sprintf("path=%s size=%s", target.Path, platform.HumanBytes(size)), target.Recommendation, "")
		f.EstimatedSizeBytes = size
		findings = append(findings, f)
	}
	if platform.IsDarwin() {
		findings = append(findings, timeMachineSnapshots(ctx, runner))
	} else {
		findings = append(findings, unsupportedPlatformFinding("storage-time-machine-skipped", audit.CategoryStorage, "Time Machine local snapshots skipped", "Time Machine local snapshot inspection", "macOS"))
	}
	if cfg.Deep {
		findings = append(findings, deepStorageFindings(cfg.HomeDir)...)
	}
	return audit.CheckResult{Findings: findings}, nil
}

type storageTarget struct {
	Path           string
	Title          string
	WarnBytes      int64
	Recommendation string
}

func storageTargets(home string) []storageTarget {
	return storageTargetsForOS(platform.CurrentOS(), home)
}

func storageTargetsForOS(osName platform.OS, home string) []storageTarget {
	gb := int64(1024 * 1024 * 1024)
	common := []storageTarget{
		{filepath.Join(home, "Downloads"), "Downloads folder", 10 * gb, "Review old installers and archives manually before deleting."},
		{filepath.Join(home, ".npm"), "npm cache/config metadata", 2 * gb, "Prefer npm cache verify/clean after reviewing config files."},
		{filepath.Join(home, ".gradle", "caches"), "Gradle caches", 5 * gb, "Gradle caches are usually regenerable but should be reviewed before cleanup."},
		{filepath.Join(home, ".docker"), "Docker CLI metadata", 1 * gb, "Review Docker config metadata; secret values are not read by this tool."},
	}
	if osName.IsWindows() {
		return append(common,
			storageTarget{filepath.Join(home, "AppData", "Local", "Temp"), "User temporary files", 2 * gb, "Review temporary files with Windows Storage settings or a trusted cleanup tool."},
			storageTarget{filepath.Join(home, "AppData", "Local", "npm-cache"), "npm cache", 2 * gb, "Prefer npm cache verify/clean after reviewing config files."},
			storageTarget{filepath.Join(home, "AppData", "Local", "pip", "Cache"), "pip cache", 2 * gb, "Prefer pip cache purge after review."},
		)
	}
	if osName.IsLinux() {
		return append(common,
			storageTarget{filepath.Join(home, ".cache"), "User cache directory", 5 * gb, "Review cache contents manually or with your distribution's cleanup tooling."},
			storageTarget{filepath.Join(home, ".local", "share", "Trash", "files"), "User Trash", 1 * gb, "Review Trash contents manually before deleting."},
			storageTarget{filepath.Join(home, ".cache", "pip"), "pip cache", 2 * gb, "Prefer pip cache purge after review."},
			storageTarget{filepath.Join(home, ".cache", "yarn"), "Yarn cache", 2 * gb, "Prefer package-manager cleanup commands after review."},
		)
	}
	return append([]storageTarget{
		{filepath.Join(home, "Library", "Caches"), "User caches", 5 * gb, "Use --clean-dry-run to review safe user-cache cleanup candidates."},
		{"/Library/Caches", "System-wide caches", 10 * gb, "Review manually; this tool does not delete /Library/Caches by default."},
		{filepath.Join(home, "Library", "Logs"), "User logs", 2 * gb, "Use --clean-dry-run to review safe user-log cleanup candidates."},
		{"/Library/Logs", "System-wide logs", 5 * gb, "Review manually; this tool does not delete /Library/Logs by default."},
		{filepath.Join(home, ".Trash"), "User Trash", 1 * gb, "Use --clean-dry-run to review Trash cleanup candidates."},
		{filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"), "Xcode DerivedData", 5 * gb, "DerivedData is usually safe to regenerate; review with --clean-dry-run."},
		{filepath.Join(home, "Library", "Developer", "Xcode", "Archives"), "Xcode Archives", 10 * gb, "Review archives before deleting because they may be release artifacts."},
		{filepath.Join(home, "Library", "Developer", "Xcode", "iOS DeviceSupport"), "iOS DeviceSupport", 5 * gb, "Review old device support files manually."},
		{filepath.Join(home, "Library", "Developer", "CoreSimulator"), "CoreSimulator data", 10 * gb, "Review simulator data manually; this tool does not delete simulator devices by default."},
		{filepath.Join(home, "Library", "Caches", "Homebrew"), "Homebrew user cache", 3 * gb, "Use Homebrew's own cleanup commands if installed and desired."},
		{"/opt/homebrew/var/homebrew", "Homebrew Apple Silicon state", 3 * gb, "Review manually; do not delete package-manager state blindly."},
		{"/usr/local/var/homebrew", "Homebrew Intel state", 3 * gb, "Review manually; do not delete package-manager state blindly."},
		{filepath.Join(home, "Library", "Caches", "Yarn"), "Yarn cache", 2 * gb, "Prefer package-manager cleanup commands after review."},
		{filepath.Join(home, "Library", "pnpm"), "pnpm cache/store metadata", 2 * gb, "Prefer pnpm store prune after review."},
		{filepath.Join(home, "Library", "Caches", "pip"), "pip cache", 2 * gb, "Prefer pip cache purge after review."},
		{filepath.Join(home, "Library", "Containers", "com.docker.docker"), "Docker Desktop data", 20 * gb, "Review Docker images/volumes manually; this tool does not delete Docker volumes."},
		{filepath.Join(home, "Library", "Android"), "Android SDK/cache data", 10 * gb, "Review SDK components and emulator data manually before deleting."},
	}, common...)
}

func timeMachineSnapshots(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "tmutil", "listlocalsnapshots", "/")
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	if result.ExitCode == 0 {
		lines := nonEmptyLines(result.Output)
		if len(lines) == 0 {
			status = audit.StatusPass
		} else {
			status = audit.StatusWarn
			severity = audit.SeverityLow
		}
	}
	return newFinding("storage-time-machine-local-snapshots", audit.CategoryStorage, "Time Machine local snapshots", status, severity, commandEvidence(result), "Local snapshots are managed by macOS; use Time Machine/System Settings or tmutil only when you understand the impact.", platform.FormatCommand("tmutil", "listlocalsnapshots", "/"))
}

func deepStorageFindings(home string) []audit.Finding {
	var findings []audit.Finding
	largeFiles, err := platform.FindLargeFiles(home, home, int64(1024*1024*1024), 30)
	if err != nil {
		findings = append(findings, newFinding("storage-deep-large-files", audit.CategoryStorage, "Large files in home directory", audit.StatusInfo, audit.SeverityInfo, err.Error(), "Run a manual disk usage review if needed.", ""))
	} else if len(largeFiles) == 0 {
		findings = append(findings, newFinding("storage-deep-large-files", audit.CategoryStorage, "Large files in home directory", audit.StatusPass, audit.SeverityInfo, "No files over 1 GiB found in non-excluded home paths.", "No action needed.", ""))
	} else {
		var parts []string
		for _, lf := range largeFiles {
			parts = append(parts, fmt.Sprintf("%s (%s)", lf.Path, platform.HumanBytes(lf.Size)))
		}
		findings = append(findings, newFinding("storage-deep-large-files", audit.CategoryStorage, "Top large files in home directory", audit.StatusWarn, audit.SeverityLow, strings.Join(parts, "; "), "Review large files manually. This tool does not delete project files or personal documents.", ""))
	}
	findings = append(findings, oldInstallerFindings(filepath.Join(home, "Downloads"))...)
	return findings
}

func oldInstallerFindings(downloads string) []audit.Finding {
	entries, err := os.ReadDir(downloads)
	if err != nil {
		return nil
	}
	var old []string
	cutoff := time.Now().AddDate(0, 0, -30)
	extensions := []string{".dmg", ".pkg", ".zip", ".rar", ".tar.gz"}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !hasSuffixAny(lower, extensions) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		old = append(old, fmt.Sprintf("%s (%s, modified %s)", filepath.Join(downloads, name), platform.HumanBytes(info.Size()), info.ModTime().Format("2006-01-02")))
	}
	sort.Strings(old)
	if len(old) == 0 {
		return []audit.Finding{newFinding("storage-old-installers", audit.CategoryStorage, "Old installers in Downloads", audit.StatusPass, audit.SeverityInfo, "No old installer/archive files found in Downloads.", "No action needed.", "")}
	}
	return []audit.Finding{newFinding("storage-old-installers", audit.CategoryStorage, "Old installers in Downloads", audit.StatusWarn, audit.SeverityLow, strings.Join(old, "; "), "Review old installers manually before deletion; they are not auto-cleaned.", "")}
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

func hasSuffixAny(s string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}
