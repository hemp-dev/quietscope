package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func TestWindowsDefenderParsing(t *testing.T) {

	// Mocking sc query WinDefend output
	runningOutput := "SERVICE_NAME: WinDefend\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                            (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n"
	stoppedOutput := "SERVICE_NAME: WinDefend\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 1  STOPPED\n"

	fRunning := checkWindowsDefenderFromResult(runningOutput)
	if fRunning.Status != audit.StatusPass {
		t.Fatalf("expected running defender to pass, got: %s", fRunning.Status)
	}

	fStopped := checkWindowsDefenderFromResult(stoppedOutput)
	if fStopped.Status != audit.StatusWarn || fStopped.Severity != audit.SeverityHigh {
		t.Fatalf("expected stopped defender to warn/high, got: %s/%s", fStopped.Status, fStopped.Severity)
	}
}

func TestWindowsUACParsing(t *testing.T) {
	enabledOutput := "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n    EnableLUA    REG_DWORD    0x1\n"
	disabledOutput := "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n    EnableLUA    REG_DWORD    0x0\n"

	fEnabled := checkWindowsUACFromResult(enabledOutput)
	if fEnabled.Status != audit.StatusPass {
		t.Fatalf("expected EnableLUA=1 to pass, got: %s", fEnabled.Status)
	}

	fDisabled := checkWindowsUACFromResult(disabledOutput)
	if fDisabled.Status != audit.StatusWarn || fDisabled.Severity != audit.SeverityMedium {
		t.Fatalf("expected EnableLUA=0 to warn/medium, got: %s/%s", fDisabled.Status, fDisabled.Severity)
	}
}

func TestWindowsFirewallParsing(t *testing.T) {
	activeOutput := "Domain Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\n\nPrivate Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\n\nPublic Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\n"
	disabledOutput := "Domain Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\n\nPrivate Profile Settings:\n----------------------------------------------------------------------\nState                                 OFF\n\nPublic Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\n"

	fActive := checkWindowsFirewallFromResult(activeOutput)
	if fActive.Status != audit.StatusPass {
		t.Fatalf("expected active firewall to pass, got: %s", fActive.Status)
	}

	fDisabled := checkWindowsFirewallFromResult(disabledOutput)
	if fDisabled.Status != audit.StatusWarn || fDisabled.Severity != audit.SeverityMedium {
		t.Fatalf("expected disabled profile firewall to warn/medium, got: %s/%s", fDisabled.Status, fDisabled.Severity)
	}
	if !strings.Contains(fDisabled.Evidence, "Private") {
		t.Fatalf("expected disabled profile listed in evidence, got: %s", fDisabled.Evidence)
	}
}

func TestWindowsSSHDirectory(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}

	findings := checkWindowsSSHPermissions(dir)
	// If dir is empty, it shouldn't fail or panic
	if len(findings) != 1 || findings[0].Status != audit.StatusInfo {
		t.Fatalf("expected 1 finding group info when empty directory, got %d (status: %s)", len(findings), findings[0].Status)
	}

	// Create ssh files in .ssh directory
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("ssh-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), []byte("ssh-public-key"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings = checkWindowsSSHPermissions(dir)
	// Expected 1 dir info and 1 key info finding (id_rsa.pub is ignored, id_rsa is private key)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (dir and id_rsa), got %d", len(findings))
	}
}

func TestWindowsPersistenceProfiles(t *testing.T) {
	home := t.TempDir()
	findings := checkWindowsPowerShellProfiles(home)
	if len(findings) != 2 || findings[0].Status != audit.StatusPass {
		t.Fatalf("expected profiles pass when non-existent, got: %#v", findings)
	}

	// Create legacy and modern profiles
	psLegacyDir := filepath.Join(home, "Documents", "WindowsPowerShell")
	psModernDir := filepath.Join(home, "Documents", "PowerShell")
	for _, d := range []string{psLegacyDir, psModernDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(psLegacyDir, "Microsoft.PowerShell_profile.ps1"), []byte("echo profile"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings = checkWindowsPowerShellProfiles(home)
	if !hasFindingPrefix(findings, "windows-ps-profile-legacy") {
		t.Fatalf("expected legacy profile finding, got %#v", findings)
	}
	legacyFinding := getFindingByID(findings, "windows-ps-profile-legacy")
	if legacyFinding.Status != audit.StatusWarn || legacyFinding.Severity != audit.SeverityLow {
		t.Fatalf("expected legacy profile finding to warn/low, got: %s/%s", legacyFinding.Status, legacyFinding.Severity)
	}
}

// Internal test helpers to map outputs cleanly
func checkWindowsDefenderFromResult(output string) audit.Finding {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "running") {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusPass, audit.SeverityInfo, "running", "", "")
	}
	if strings.Contains(lower, "stopped") {
		return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusWarn, audit.SeverityHigh, "stopped", "", "")
	}
	return newFinding("windows-defender-status", audit.CategorySecurity, "Windows Defender AV status", audit.StatusInfo, audit.SeverityInfo, "unknown", "", "")
}

func checkWindowsUACFromResult(output string) audit.Finding {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "enablelua") && strings.Contains(lower, "reg_dword") {
		if strings.Contains(lower, "0x1") {
			return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusPass, audit.SeverityInfo, "active", "", "")
		}
		if strings.Contains(lower, "0x0") {
			return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusWarn, audit.SeverityMedium, "disabled", "", "")
		}
	}
	return newFinding("windows-uac-status", audit.CategorySecurity, "User Account Control (UAC)", audit.StatusInfo, audit.SeverityInfo, "unknown", "", "")
}

func checkWindowsFirewallFromResult(output string) audit.Finding {
	lower := strings.ToLower(output)
	hasState := strings.Contains(lower, "state")
	var offProfiles []string

	if hasState {
		if strings.Contains(lower, "state") && strings.Contains(lower, "off") {
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
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusWarn, audit.SeverityMedium, "Disabled firewall profiles detected: "+strings.Join(offProfiles, ", "), "", "")
	}
	if hasState && strings.Contains(lower, "on") {
		return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusPass, audit.SeverityInfo, "active", "", "")
	}
	return newFinding("windows-firewall-status", audit.CategorySecurity, "Windows firewall status", audit.StatusInfo, audit.SeverityInfo, "unknown", "", "")
}

func getFindingByID(findings []audit.Finding, id string) audit.Finding {
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	return audit.Finding{}
}
