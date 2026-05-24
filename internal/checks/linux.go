package checks

import (
	"context"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

const (
	linuxPlatformName = "Linux"
	linuxMaxScanBytes = 512 * 1024
)

func RunLinuxPersistence(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	_ = ctx
	_ = runner
	if !platform.IsLinux() {
		return audit.CheckResult{Findings: []audit.Finding{
			unsupportedPlatformFinding("linux-persistence-skipped", audit.CategoryPersistence, "Linux persistence checks skipped", "Linux persistence audit", linuxPlatformName),
		}}, nil
	}
	findings := linuxPersistenceFindings(cfg)
	return audit.CheckResult{Findings: findings}, nil
}

func RunLinuxSecurity(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	if !platform.IsLinux() {
		return audit.CheckResult{Findings: []audit.Finding{
			unsupportedPlatformFinding("linux-security-skipped", audit.CategorySecurity, "Linux security checks skipped", "Linux security audit", linuxPlatformName),
		}}, nil
	}
	findings := linuxSecurityFindings(ctx, cfg, runner)
	return audit.CheckResult{Findings: findings}, nil
}
