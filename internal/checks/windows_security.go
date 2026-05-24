package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
)

func windowsSecurityFindings(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, checkWindowsSSHPermissions(cfg.HomeDir)...)
	findings = append(findings, checkWindowsFirewall(ctx, runner))
	findings = append(findings, checkWindowsDefender(ctx, runner))
	findings = append(findings, checkWindowsUAC(ctx, runner))
	return findings
}

func checkWindowsSSHPermissions(home string) []audit.Finding {
	var findings []findingsGroup
	sshDir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []audit.Finding{newFinding("windows-ssh-dir", audit.CategorySecurity, "Windows user SSH directory", audit.StatusPass, audit.SeverityInfo, "SSH directory does not exist for current user; no risk detected.", "No action needed.", "")}
		}
		return []audit.Finding{newFinding("windows-ssh-dir", audit.CategorySecurity, "Windows user SSH directory", audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review SSH key settings manually.", "")}
	}

	evidence := fmt.Sprintf("SSH directory exists: %s", sshDir)
	findings = append(findings, findingsGroup{
		finding: newFinding("windows-ssh-dir", audit.CategorySecurity, "Windows user SSH directory", audit.StatusInfo, audit.SeverityInfo, evidence, "Ensure SSH keys are only readable by your user account.", ""),
	})

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isLikelySSHPrivateKey(name) && name != "authorized_keys" && name != "config" {
			continue
		}
		path := filepath.Join(sshDir, name)
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		ev := fmt.Sprintf("file=%s size=%d mtime=%s", name, meta.Size, meta.ModTime.Format("2006-01-02"))
		// Standard Windows SSH client requires private keys to have strict ACLs. We report details for review.
		findings = append(findings, findingsGroup{
			finding: newFinding("windows-ssh-key-"+safeID(name), audit.CategorySecurity, "Windows SSH file: "+name, status, severity, ev, "Ensure file permissions are restricted to your user only.", ""),
		})
	}

	var results []audit.Finding
	for _, f := range findings {
		results = append(results, f.finding)
	}
	return results
}

type findingsGroup struct {
	finding audit.Finding
}

func checkWindowsFirewall(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "netsh", "advfirewall", "show", "allprofiles")
	if !result.Available {
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusInfo, audit.SeverityInfo, "netsh command is unavailable: "+result.Error, "Verify Windows firewall status manually.", "")
	}
	if result.ExitCode != 0 {
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusInfo, audit.SeverityInfo, "netsh execution failed: "+commandEvidence(result), "Verify Windows firewall status manually.", "netsh advfirewall show allprofiles")
	}

	output := result.Output
	lower := strings.ToLower(output)

	// netsh advfirewall show allprofiles prints Firewall Policy and State for Domain, Private, and Public profiles.
	// We want to detect if any of them is "State OFF" or "State ON"
	hasState := strings.Contains(lower, "state")
	var offProfiles []string

	if hasState {
		// Split output into sections or check keywords
		if strings.Contains(lower, "state") && strings.Contains(lower, "off") {
			// Find which profiles are off
			lines := strings.Split(output, "\n")
			currentProfile := "Unknown"
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				if strings.HasSuffix(strings.ToLower(trimmed), "profile settings:") {
					currentProfile = strings.TrimSpace(trimmed[:len(trimmed)-17])
				}
				if strings.HasPrefix(strings.ToLower(trimmed), "state") {
					if strings.Contains(strings.ToLower(trimmed), "off") {
						offProfiles = append(offProfiles, currentProfile)
					}
				}
			}
		}
	}

	if len(offProfiles) > 0 {
		evidence := fmt.Sprintf("Disabled firewall profiles detected: %s. Output: %s", strings.Join(offProfiles, ", "), safetySnippet(output, 100))
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusWarn, audit.SeverityMedium, evidence, "Enable firewall profiles for all profiles using Windows Security settings or netsh command.", "netsh advfirewall show allprofiles")
	}

	if hasState && strings.Contains(lower, "on") {
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusPass, audit.SeverityInfo, "All Windows firewall profiles (Domain, Private, Public) are active.", "No action needed.", "netsh advfirewall show allprofiles")
	}

	return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusInfo, audit.SeverityInfo, "Could not interpret firewall state from netsh output: "+safetySnippet(output, 120), "Verify Windows firewall manually.", "netsh advfirewall show allprofiles")
}

func checkWindowsDefender(ctx context.Context, runner *platform.Runner) audit.Finding {
	result := runner.Run(ctx, "sc", "query", "WinDefend")
	if !result.Available {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusInfo, audit.SeverityInfo, "sc command is unavailable: "+result.Error, "Verify Windows Defender status manually in Windows Security.", "")
	}
	if result.ExitCode != 0 {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusInfo, audit.SeverityInfo, "sc query WinDefend failed: "+commandEvidence(result), "Verify Windows Defender status manually in Windows Security.", "sc query WinDefend")
	}

	output := result.Output
	lower := strings.ToLower(output)

	if strings.Contains(lower, "running") {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusPass, audit.SeverityInfo, "Windows Defender Antivirus service (WinDefend) is active and running.", "No action needed.", "sc query WinDefend")
	}

	if strings.Contains(lower, "stopped") {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusWarn, audit.SeverityHigh, "Windows Defender Antivirus service (WinDefend) is stopped.", "Enable real-time security in Windows Security immediately.", "sc query WinDefend")
	}

	return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusInfo, audit.SeverityInfo, "WinDefend service status: "+safetySnippet(output, 100), "Review Windows Defender status manually in Windows Security.", "sc query WinDefend")
}

func checkWindowsUAC(ctx context.Context, runner *platform.Runner) audit.Finding {
	// Query standard registry key for UAC LUA setting
	result := runner.Run(ctx, "reg", "query", `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA")
	if !result.Available {
		return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusInfo, audit.SeverityInfo, "reg command is unavailable: "+result.Error, "Verify UAC settings in Control Panel.", "")
	}
	if result.ExitCode != 0 {
		return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusInfo, audit.SeverityInfo, "Registry lookup failed: "+commandEvidence(result), "Verify UAC settings in Control Panel.", `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`)
	}

	output := result.Output
	lower := strings.ToLower(output)

	if strings.Contains(lower, "enablelua") && strings.Contains(lower, "reg_dword") {
		if strings.Contains(lower, "0x1") {
			return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusPass, audit.SeverityInfo, "UAC is active and enabled (EnableLUA=1).", "No action needed.", `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`)
		}
		if strings.Contains(lower, "0x0") {
			return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusWarn, audit.SeverityMedium, "UAC is disabled (EnableLUA=0).", "Enable User Account Control (UAC) in Control Panel to prevent unauthorized changes.", `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`)
		}
	}

	return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusInfo, audit.SeverityInfo, "Could not parse UAC EnableLUA setting: "+safetySnippet(output, 100), "Review UAC setting manually.", `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`)
}
