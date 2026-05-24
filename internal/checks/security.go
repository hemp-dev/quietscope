package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
)

func RunSecurity(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	if !platform.SupportsMacOSSecuritySettings() {
		return audit.CheckResult{Findings: []audit.Finding{
			unsupportedPlatformFinding("security-macos-settings-skipped", audit.CategorySecurity, "macOS security settings skipped", "SIP, Gatekeeper, FileVault, Application Firewall, Sharing, and XProtect checks", "macOS"),
			unsupportedPlatformFinding("updates-macos-settings-skipped", audit.CategoryUpdates, "macOS update settings skipped", "Software Update and Apple security package checks", "macOS"),
		}}, nil
	}
	var findings []audit.Finding
	findings = append(findings, softwareUpdateFinding())
	findings = append(findings, checkSIP(ctx, runner))
	findings = append(findings, checkGatekeeper(ctx, runner))
	findings = append(findings, checkFileVault(ctx, runner))
	findings = append(findings, checkFirewall(ctx, runner))
	findings = append(findings, checkStealthMode(ctx, runner))
	findings = append(findings, checkAutomaticUpdates(ctx, runner)...)
	findings = append(findings, checkXProtectPackages(ctx, runner)...)
	findings = append(findings, checkRemoteAccess(ctx, runner)...)
	_ = cfg
	return audit.CheckResult{Findings: findings}, nil
}

func softwareUpdateFinding() audit.Finding {
	f := newFinding(
		"updates-softwareupdate-list-local-only",
		audit.CategoryUpdates,
		"Software Update availability requires manual local confirmation",
		audit.StatusInfo,
		audit.SeverityInfo,
		"Available update listing via softwareupdate --list can contact Apple's update service. To preserve local-only defaults, this audit records the check as manual instead of initiating an external request.",
		"Run softwareupdate --list manually when you are comfortable allowing Apple's software update check, then install available security updates from System Settings.",
		"softwareupdate --list (not executed by local-only default)",
	)
	return f
}

func checkSIP(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "csrutil", "status")
	status, severity, _ := statusFromContains(result.Output, "enabled", "disabled", "")
	if !result.Available || result.Output == "" {
		status, severity = audit.StatusInfo, audit.SeverityInfo
	}
	if status == audit.StatusFail {
		severity = audit.SeverityHigh
	}
	return newFinding("security-sip", audit.CategorySecurity, "System Integrity Protection", status, severity, commandEvidence(result), "Keep SIP enabled unless you have a documented, temporary administrative need.", platform.FormatCommand("csrutil", "status"))
}

func checkGatekeeper(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "spctl", "--status")
	status, severity, _ := statusFromContains(result.Output, "assessments enabled", "assessments disabled", "")
	if !result.Available || result.Output == "" {
		status, severity = audit.StatusInfo, audit.SeverityInfo
	}
	if status == audit.StatusFail {
		severity = audit.SeverityHigh
	}
	return newFinding("security-gatekeeper", audit.CategorySecurity, "Gatekeeper assessment status", status, severity, commandEvidence(result), "Keep Gatekeeper enabled to reduce unsigned or untrusted app execution risk.", platform.FormatCommand("spctl", "--status"))
}

func checkFileVault(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "fdesetup", "status")
	lower := strings.ToLower(result.Output)
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	if strings.Contains(lower, "filevault is on") {
		status = audit.StatusPass
	} else if strings.Contains(lower, "filevault is off") {
		status = audit.StatusWarn
		severity = audit.SeverityHigh
	}
	return newFinding("security-filevault", audit.CategorySecurity, "FileVault disk encryption", status, severity, commandEvidence(result), "Enable FileVault for portable Macs and any device that may hold sensitive data.", platform.FormatCommand("fdesetup", "status"))
}

func checkFirewall(ctx context.Context, runner *platform.Runner) audit.Finding {
	cmd := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	result := runner.Run(ctx, cmd, "--getglobalstate")
	lower := strings.ToLower(result.Output)
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	if strings.Contains(lower, "enabled") {
		status = audit.StatusPass
	} else if strings.Contains(lower, "disabled") {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
	}
	return newFinding("security-firewall", audit.CategorySecurity, "Application Firewall", status, severity, commandEvidence(result), "Enable the macOS Application Firewall unless another managed firewall is in place.", platform.FormatCommand(cmd, "--getglobalstate"))
}

func checkStealthMode(ctx context.Context, runner *platform.Runner) audit.Finding {
	cmd := "/usr/libexec/ApplicationFirewall/socketfilterfw"
	result := runner.Run(ctx, cmd, "--getstealthmode")
	lower := strings.ToLower(result.Output)
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	if strings.Contains(lower, "enabled") {
		status = audit.StatusPass
	} else if strings.Contains(lower, "disabled") {
		status = audit.StatusWarn
		severity = audit.SeverityLow
	}
	return newFinding("security-firewall-stealth", audit.CategorySecurity, "Firewall stealth mode", status, severity, commandEvidence(result), "Consider enabling stealth mode on laptops and unmanaged networks.", platform.FormatCommand(cmd, "--getstealthmode"))
}

func checkAutomaticUpdates(ctx context.Context, runner *platform.Runner) []audit.Finding {
	checks := []struct {
		id       string
		title    string
		domain   string
		key      string
		category audit.Category
	}{
		{"updates-automatic-check", "Automatic update checks", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled", audit.CategoryUpdates},
		{"updates-critical", "Critical update installation", "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall", audit.CategoryUpdates},
		{"updates-config-data", "Config data installation", "/Library/Preferences/com.apple.SoftwareUpdate", "ConfigDataInstall", audit.CategoryUpdates},
		{"updates-macos-auto-install", "macOS automatic installation preference", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates", audit.CategoryUpdates},
		{"updates-app-store", "App Store automatic app updates", "com.apple.commerce", "AutoUpdate", audit.CategoryUpdates},
	}
	var findings []audit.Finding
	for _, c := range checks {
		result := runner.Run(ctx, "defaults", "read", c.domain, c.key)
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		output := strings.TrimSpace(result.Output)
		if output == "1" || strings.EqualFold(output, "true") {
			status = audit.StatusPass
		} else if output == "0" || strings.EqualFold(output, "false") {
			status = audit.StatusWarn
			severity = audit.SeverityMedium
		}
		findings = append(findings, newFinding(c.id, c.category, c.title, status, severity, commandEvidence(result), "Keep security content and critical update installation enabled where compatible with your change-management process.", platform.FormatCommand("defaults", "read", c.domain, c.key)))
	}
	return findings
}

func checkXProtectPackages(ctx context.Context, runner *platform.Runner) []audit.Finding {
	packages := []string{
		"com.apple.pkg.XProtectPlistConfigData",
		"com.apple.pkg.XProtectPayloads",
		"com.apple.pkg.MRTConfigData",
	}
	var findings []audit.Finding
	for _, pkg := range packages {
		result := runner.Run(ctx, "pkgutil", "--pkg-info", pkg)
		status := audit.StatusPass
		severity := audit.SeverityInfo
		if !result.Available || result.ExitCode != 0 || result.Output == "" {
			status = audit.StatusInfo
			severity = audit.SeverityLow
		}
		findings = append(findings, newFinding("security-package-"+strings.ToLower(strings.TrimPrefix(pkg, "com.apple.pkg.")), audit.CategorySecurity, "Apple security package: "+pkg, status, severity, commandEvidence(result), "Verify XProtect/MRT payloads are present and updated through Software Update.", platform.FormatCommand("pkgutil", "--pkg-info", pkg)))
	}
	return findings
}

func checkRemoteAccess(ctx context.Context, runner *platform.Runner) []audit.Finding {
	var findings []audit.Finding
	remoteLogin := runner.Run(ctx, "systemsetup", "-getremotelogin")
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	if strings.Contains(strings.ToLower(remoteLogin.Output), "off") {
		status = audit.StatusPass
	} else if strings.Contains(strings.ToLower(remoteLogin.Output), "on") {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
	}
	findings = append(findings, newFinding("security-remote-login", audit.CategorySecurity, "Remote Login / SSH", status, severity, commandEvidence(remoteLogin), "Disable Remote Login unless explicitly needed; restrict users and require key-based authentication if enabled.", platform.FormatCommand("systemsetup", "-getremotelogin")))

	remoteAppleEvents := runner.Run(ctx, "systemsetup", "-getremoteappleevents")
	status = audit.StatusInfo
	severity = audit.SeverityInfo
	if strings.Contains(strings.ToLower(remoteAppleEvents.Output), "off") {
		status = audit.StatusPass
	} else if strings.Contains(strings.ToLower(remoteAppleEvents.Output), "on") {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
	}
	findings = append(findings, newFinding("security-remote-apple-events", audit.CategorySecurity, "Remote Apple Events", status, severity, commandEvidence(remoteAppleEvents), "Disable Remote Apple Events unless required for managed automation.", platform.FormatCommand("systemsetup", "-getremoteappleevents")))

	services := []struct {
		id    string
		title string
		cmd   string
		args  []string
	}{
		{"security-screen-sharing", "Screen Sharing service", "launchctl", []string{"print", "system/com.apple.screensharing"}},
		{"security-smb-sharing", "SMB file sharing service", "launchctl", []string{"print", "system/com.apple.smbd"}},
		{"security-afp-sharing", "AFP file sharing service", "launchctl", []string{"print", "system/com.apple.AppleFileServer"}},
		{"security-internet-sharing", "Internet Sharing preference", "defaults", []string{"read", "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT"}},
	}
	for _, svc := range services {
		result := runner.Run(ctx, svc.cmd, svc.args...)
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		evidence := commandEvidence(result)
		if result.ExitCode == 0 && strings.Contains(strings.ToLower(result.Output), "state = running") {
			status = audit.StatusWarn
			severity = audit.SeverityMedium
		} else if result.ExitCode != 0 {
			evidence = fmt.Sprintf("Unable to determine service state: %s", evidence)
		}
		findings = append(findings, newFinding(svc.id, audit.CategorySecurity, svc.title, status, severity, evidence, "Manually verify Sharing settings in System Settings and disable services you do not use.", platform.FormatCommand(svc.cmd, svc.args...)))
	}
	return findings
}
