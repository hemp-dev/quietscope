package checks

import (
	"context"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

const (
	windowsPlatformName = "Windows"
)

func RunWindowsPersistence(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	_ = ctx
	_ = runner
	if !platform.IsWindows() {
		return audit.CheckResult{Findings: []audit.Finding{
			unsupportedPlatformFinding("windows-persistence-skipped", audit.CategoryPersistence, "Windows persistence checks skipped", "Windows persistence audit", windowsPlatformName),
		}}, nil
	}
	findings := windowsPersistenceFindings(cfg)
	return audit.CheckResult{Findings: findings}, nil
}

func RunWindowsSecurity(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	if !platform.IsWindows() {
		return audit.CheckResult{Findings: []audit.Finding{
			unsupportedPlatformFinding("windows-security-skipped", audit.CategorySecurity, "Windows security checks skipped", "Windows security audit", windowsPlatformName),
		}}, nil
	}
	findings := windowsSecurityFindings(ctx, cfg, runner)
	return audit.CheckResult{Findings: findings}, nil
}
