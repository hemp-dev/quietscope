package checks

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
	"github.com/projectauthors/quietscope/internal/safety"
)

func RunSystem(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	info := map[string]string{
		"timestamp":        time.Now().Format(time.RFC3339),
		"architecture":     runtime.GOARCH,
		"reports_path":     cfg.OutputDir,
		"platform":         string(platform.CurrentOS()),
		"running_as_root":  fmt.Sprintf("%t", platform.IsRoot()),
		"shell":            os.Getenv("SHELL"),
		"go_runtime_os":    runtime.GOOS,
		"tool_version":     cfg.Version,
		"local_only_note":  "No telemetry, no report upload, no external UI assets.",
		"sudo_policy":      boolPolicy(cfg.NoSudo, "disabled by --no-sudo", "not used by default; best-effort checks degrade gracefully"),
		"ai_audit_enabled": fmt.Sprintf("%t", cfg.AIAudit),
	}
	if platform.IsDarwin() {
		addCommandInfo(ctx, runner, info, "macos_version", "sw_vers", "-productVersion")
		addCommandInfo(ctx, runner, info, "macos_build", "sw_vers", "-buildVersion")
		addCommandInfo(ctx, runner, info, "hardware_model", "sysctl", "-n", "hw.model")
	} else {
		info["macos_version"] = "skipped: supported only on macOS"
		info["macos_build"] = "skipped: supported only on macOS"
		info["hardware_model"] = "skipped: macOS sysctl hardware model is unavailable on this platform"
	}
	addCommandInfo(ctx, runner, info, "kernel_arch", "uname", "-m")
	addCommandInfo(ctx, runner, info, "hostname", "hostname")
	addCommandInfo(ctx, runner, info, "current_user", "whoami")
	addCommandInfo(ctx, runner, info, "uptime", "uptime")
	addCommandInfo(ctx, runner, info, "root_disk_usage", "df", "-h", "/")

	status := audit.StatusPass
	severity := audit.SeverityInfo
	evidence := "System metadata collected with best-effort local commands."
	if !platform.IsMacOS() {
		status = audit.StatusInfo
		evidence = "Not running on macOS. macOS-specific checks are reported as skipped while common local checks still run."
	}
	return audit.CheckResult{
		SystemInfo: info,
		Findings:   []audit.Finding{newFinding("system-overview", audit.CategorySystem, "System overview collected", status, severity, evidence, "Review report metadata before acting on findings.", "")},
	}, nil
}

func unsupportedPlatformFinding(id string, category audit.Category, title string, feature string, supported string) audit.Finding {
	return unsupportedPlatformFindingForOS(platform.CurrentOS(), id, category, title, feature, supported)
}

func unsupportedPlatformFindingForOS(current platform.OS, id string, category audit.Category, title string, feature string, supported string) audit.Finding {
	return newFinding(
		id,
		category,
		title,
		audit.StatusSkipped,
		audit.SeverityInfo,
		fmt.Sprintf("%s is not supported on %s. Supported platform: %s.", feature, current, supported),
		"Run this check on a supported platform. Common local checks remain available on this OS.",
		"",
	)
}

func addCommandInfo(ctx context.Context, runner *platform.Runner, info map[string]string, key string, command string, args ...string) {
	result := runner.Run(ctx, command, args...)
	if result.Output != "" {
		info[key] = safety.RedactSensitiveText(result.Output)
		return
	}
	if result.Error != "" {
		info[key] = "unavailable: " + safety.RedactSensitiveText(result.Error)
		return
	}
	info[key] = "unavailable"
}

func boolPolicy(enabled bool, whenTrue string, whenFalse string) string {
	if enabled {
		return whenTrue
	}
	return whenFalse
}

func newFinding(id string, category audit.Category, title string, status audit.Status, severity audit.Severity, evidence string, recommendation string, command string) audit.Finding {
	return audit.Finding{
		ID:             id,
		Category:       category,
		Title:          title,
		Status:         status,
		Severity:       severity,
		Evidence:       safety.RedactSensitiveText(strings.TrimSpace(evidence)),
		Recommendation: recommendation,
		CommandChecked: command,
	}
}

func commandEvidence(result platform.CommandResult) string {
	if !result.Available {
		return "Command unavailable or intentionally skipped: " + safety.RedactSensitiveText(result.Error)
	}
	if result.TimedOut {
		return "Command timed out: " + platform.FormatCommand(result.Command, result.Args...)
	}
	if result.Output != "" {
		return safety.RedactSensitiveText(result.Output)
	}
	if result.Error != "" {
		return safety.RedactSensitiveText(result.Error)
	}
	return "Command completed without output."
}

func statusFromContains(output string, goodNeedle string, badNeedle string, unknownTitle string) (audit.Status, audit.Severity, string) {
	lower := strings.ToLower(output)
	if goodNeedle != "" && strings.Contains(lower, strings.ToLower(goodNeedle)) {
		return audit.StatusPass, audit.SeverityInfo, ""
	}
	if badNeedle != "" && strings.Contains(lower, strings.ToLower(badNeedle)) {
		return audit.StatusFail, audit.SeverityHigh, ""
	}
	return audit.StatusInfo, audit.SeverityInfo, unknownTitle
}
