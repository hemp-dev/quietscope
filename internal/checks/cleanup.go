package checks

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
)

func RunCleanup(ctx context.Context, cfg audit.RuntimeConfig) (audit.CheckResult, error) {
	_ = ctx
	var candidates []audit.CleanupCandidate
	for _, root := range cleanupRoots(cfg.HomeDir) {
		children, err := platform.ListImmediateChildren(root.Path)
		if err != nil {
			continue
		}
		for _, child := range children {
			if !safety.IsCleanupAllowed(child, cfg.HomeDir) {
				continue
			}
			size, err := platform.DirectorySize(child, cfg.HomeDir)
			if err != nil {
				if info, statErr := os.Lstat(child); statErr == nil && !info.IsDir() {
					size = info.Size()
				} else {
					continue
				}
			}
			if size == 0 {
				continue
			}
			candidates = append(candidates, audit.CleanupCandidate{
				Path:               child,
				Reason:             root.Reason,
				Risk:               "low",
				EstimatedSizeBytes: size,
				SafeToAutoFix:      true,
				FindingID:          "cleanup-" + safeID(child),
			})
		}
	}
	var findings []audit.Finding
	if len(candidates) == 0 {
		findings = append(findings, newFinding("cleanup-candidates", audit.CategoryCleanup, "Safe cleanup candidates", audit.StatusInfo, audit.SeverityInfo, "No allowlisted cleanup candidates with measurable size were found.", "No cleanup action is required.", ""))
	} else {
		var total int64
		for _, c := range candidates {
			total += c.EstimatedSizeBytes
			f := newFinding(c.FindingID, audit.CategoryCleanup, "Cleanup candidate: "+filepath.Base(c.Path), audit.StatusInfo, audit.SeverityLow, fmt.Sprintf("path=%s size=%s reason=%s", c.Path, platform.HumanBytes(c.EstimatedSizeBytes), c.Reason), "Use --clean-dry-run to review. Use --clean-confirm only after reviewing and typing the exact confirmation phrase.", "")
			f.CleanupCandidate = true
			f.SafeToAutoFix = true
			f.EstimatedSizeBytes = c.EstimatedSizeBytes
			findings = append(findings, f)
		}
		findings = append(findings, newFinding("cleanup-summary", audit.CategoryCleanup, "Safe cleanup dry-run summary", audit.StatusInfo, audit.SeverityInfo, fmt.Sprintf("%d safe candidate(s), estimated reclaimable %s", len(candidates), platform.HumanBytes(total)), "Cleanup is never automatic. Review candidates before using --clean-confirm.", ""))
	}
	return audit.CheckResult{Findings: findings, CleanupCandidates: candidates}, nil
}

type cleanupRoot struct {
	Path   string
	Reason string
}

func cleanupRoots(home string) []cleanupRoot {
	return []cleanupRoot{
		{filepath.Join(home, "Library", "Caches"), "User cache contents are generally regenerable."},
		{filepath.Join(home, "Library", "Logs"), "User log contents are generally safe to rotate/delete after review."},
		{filepath.Join(home, ".Trash"), "Trash contents were already moved to Trash by the user."},
		{filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"), "Xcode DerivedData is regenerable."},
	}
}

func ExecuteCleanup(candidates []audit.CleanupCandidate, home string, log io.Writer) (deleted int, skipped int) {
	for _, candidate := range candidates {
		if !candidate.SafeToAutoFix || !safety.IsCleanupAllowed(candidate.Path, home) {
			skipped++
			fmt.Fprintf(log, "SKIP %s: not allowlisted\n", candidate.Path)
			continue
		}
		info, err := os.Lstat(candidate.Path)
		if err != nil {
			skipped++
			fmt.Fprintf(log, "SKIP %s: %v\n", candidate.Path, err)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			skipped++
			fmt.Fprintf(log, "SKIP %s: symlink cleanup is not allowed\n", candidate.Path)
			continue
		}
		if err := os.RemoveAll(candidate.Path); err != nil {
			skipped++
			fmt.Fprintf(log, "SKIP %s: delete failed: %v\n", candidate.Path, err)
			continue
		}
		deleted++
		fmt.Fprintf(log, "DELETE %s\n", candidate.Path)
	}
	return deleted, skipped
}
