package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
)

type linuxSecurityPathSet struct {
	home           string
	systemSSHDir   string
	sudoersFile    string
	sudoersDir     string
	updateMetadata []string
}

func linuxSecurityFindings(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) []audit.Finding {
	return linuxSecurityFindingsForPaths(ctx, runner, defaultLinuxSecurityPaths(cfg.HomeDir))
}

func defaultLinuxSecurityPaths(home string) linuxSecurityPathSet {
	return linuxSecurityPathSet{
		home:         home,
		systemSSHDir: "/etc/ssh",
		sudoersFile:  "/etc/sudoers",
		sudoersDir:   "/etc/sudoers.d",
		updateMetadata: []string{
			"/var/lib/apt/periodic/update-success-stamp",
			"/var/lib/apt/lists",
			"/var/cache/dnf",
			"/var/lib/dnf",
			"/var/lib/pacman/sync",
			"/var/lib/zypper",
		},
	}
}

func linuxSecurityFindingsForPaths(ctx context.Context, runner *platform.Runner, paths linuxSecurityPathSet) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, inspectLinuxSSHMetadata(paths.home, paths.systemSSHDir)...)
	findings = append(findings, checkLinuxFirewall(ctx, runner))
	findings = append(findings, inspectLinuxUpdateMetadata(paths.updateMetadata)...)
	findings = append(findings, inspectLinuxSudoersMetadata(paths.sudoersFile, paths.sudoersDir)...)
	return findings
}

func inspectLinuxSSHMetadata(home string, systemSSHDir string) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, checkSSHPermissions(home)...)
	entries, err := os.ReadDir(systemSSHDir)
	if err != nil {
		findings = append(findings, newFinding("linux-ssh-system-dir", audit.CategorySecurity, "Linux system SSH directory", audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review /etc/ssh manually if this host runs an SSH server.", ""))
		return findings
	}
	status, severity, evidence := metadataStatus(systemSSHDir)
	findings = append(findings, newFinding("linux-ssh-system-dir", audit.CategorySecurity, "Linux system SSH directory", status, severity, strings.Join(evidence, "; "), "System SSH configuration and host key paths should not be group/world writable.", ""))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "ssh_host_") && name != "sshd_config" {
			continue
		}
		path := filepath.Join(systemSSHDir, name)
		status, severity, evidence := metadataStatus(path)
		if isLikelySSHPrivateKey(name) {
			meta, err := platform.StatMeta(path)
			if err == nil && meta.Mode.Perm()&0o077 != 0 {
				status = audit.StatusFail
				severity = audit.SeverityHigh
				evidence = append(evidence, "host private key is accessible beyond owner")
			}
		}
		findings = append(findings, newFinding("linux-ssh-metadata-"+safeID(path), audit.CategorySecurity, "Linux SSH metadata: "+name, status, severity, strings.Join(evidence, "; "), "Keep SSH host private keys owner-readable only and review sshd_config permissions.", ""))
	}
	return findings
}

type linuxFirewallProbe struct {
	command string
	args    []string
}

func checkLinuxFirewall(ctx context.Context, runner *platform.Runner) audit.Finding {
	probes := []linuxFirewallProbe{
		{command: "ufw", args: []string{"status"}},
		{command: "firewall-cmd", args: []string{"--state"}},
		{command: "nft", args: []string{"list", "ruleset"}},
		{command: "iptables", args: []string{"-S"}},
	}
	var unavailable []string
	for _, probe := range probes {
		result := runner.Run(ctx, probe.command, probe.args...)
		if !result.Available {
			unavailable = append(unavailable, probe.command+": "+result.Error)
			continue
		}
		if result.ExitCode != 0 && result.Output == "" {
			unavailable = append(unavailable, probe.command+": "+commandEvidence(result))
			continue
		}
		return linuxFirewallFindingFromResult(probe, result, unavailable)
	}
	evidence := "No supported Linux firewall command returned status."
	if len(unavailable) > 0 {
		evidence += " Unavailable probes: " + strings.Join(unavailable, "; ")
	}
	return linuxFirewallUnavailableFinding(evidence)
}

func linuxFirewallUnavailableFinding(evidence string) audit.Finding {
	return newFinding("linux-firewall-status", audit.CategorySecurity, "Linux firewall status", audit.StatusInfo, audit.SeverityInfo, evidence, "Install or enable a host firewall appropriate for this distribution, then rerun the audit. This check never changes firewall state.", "")
}

func linuxFirewallFindingFromResult(probe linuxFirewallProbe, result platform.CommandResult, unavailable []string) audit.Finding {
	status, severity, interpretation := classifyLinuxFirewallOutput(probe.command, result.Output)
	evidence := fmt.Sprintf("command=%s output=%s interpretation=%s", platform.FormatCommand(probe.command, probe.args...), safetySnippet(result.Output, 220), interpretation)
	if len(unavailable) > 0 {
		evidence += "; earlier unavailable probes: " + strings.Join(unavailable, "; ")
	}
	return newFinding("linux-firewall-status", audit.CategorySecurity, "Linux firewall status", status, severity, evidence, "Keep a host firewall enabled where appropriate. Confirm distribution-specific policy manually before changing rules.", platform.FormatCommand(probe.command, probe.args...))
}

func classifyLinuxFirewallOutput(command string, output string) (audit.Status, audit.Severity, string) {
	lower := strings.ToLower(output)
	switch command {
	case "ufw":
		if strings.Contains(lower, "status: active") {
			return audit.StatusPass, audit.SeverityInfo, "ufw reports active"
		}
		if strings.Contains(lower, "status: inactive") {
			return audit.StatusWarn, audit.SeverityMedium, "ufw reports inactive"
		}
	case "firewall-cmd":
		if strings.Contains(lower, "running") && !strings.Contains(lower, "not running") {
			return audit.StatusPass, audit.SeverityInfo, "firewalld reports running"
		}
		if strings.Contains(lower, "not running") {
			return audit.StatusWarn, audit.SeverityMedium, "firewalld reports not running"
		}
	case "nft":
		if strings.Contains(lower, "table ") || strings.Contains(lower, "chain ") {
			return audit.StatusInfo, audit.SeverityInfo, "nft ruleset is present; policy effectiveness requires manual review"
		}
	case "iptables":
		if strings.Contains(lower, "-p input") || strings.Contains(lower, "-a input") || strings.Contains(lower, "-p forward") || strings.Contains(lower, "-a forward") {
			return audit.StatusInfo, audit.SeverityInfo, "iptables rules are present; policy effectiveness requires manual review"
		}
	}
	if strings.TrimSpace(output) == "" {
		return audit.StatusInfo, audit.SeverityInfo, "command returned no firewall status output"
	}
	return audit.StatusInfo, audit.SeverityInfo, "firewall command output requires manual interpretation"
}

func inspectLinuxUpdateMetadata(paths []string) []audit.Finding {
	var findings []audit.Finding
	found := false
	now := time.Now()
	for _, path := range paths {
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		found = true
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		ageDays := int(now.Sub(meta.ModTime).Hours() / 24)
		evidence := fmt.Sprintf("path=%s mode=%s mtime=%s age_days=%d", path, platform.FormatPerm(meta.Mode), meta.ModTime.Format("2006-01-02"), ageDays)
		if ageDays > 30 {
			status = audit.StatusWarn
			severity = audit.SeverityLow
			evidence += "; metadata is older than 30 days"
		}
		findings = append(findings, newFinding("linux-update-metadata-"+safeID(path), audit.CategoryUpdates, "Linux package update metadata", status, severity, evidence, "Use your distribution's package manager to review updates manually. This audit does not trigger network update checks.", ""))
	}
	if !found {
		findings = append(findings, newFinding("linux-update-metadata", audit.CategoryUpdates, "Linux package update metadata", audit.StatusInfo, audit.SeverityInfo, "No known package update metadata paths were readable.", "Review updates manually with your distribution's package manager. This audit does not trigger network update checks.", ""))
	}
	return findings
}

func inspectLinuxSudoersMetadata(sudoersFile string, sudoersDir string) []audit.Finding {
	var findings []audit.Finding
	status, severity, evidence := metadataStatus(sudoersFile)
	findings = append(findings, newFinding("linux-sudoers-file", audit.CategoryPermissions, "Linux sudoers file metadata", status, severity, strings.Join(evidence, "; "), "Keep sudoers metadata tightly permissioned. This audit does not read sudoers contents.", ""))
	entries, err := os.ReadDir(sudoersDir)
	if err != nil {
		findings = append(findings, newFinding("linux-sudoers-dir", audit.CategoryPermissions, "Linux sudoers.d directory", audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review sudoers.d manually if this host uses sudo include files.", ""))
		return findings
	}
	status, severity, evidence = metadataStatus(sudoersDir)
	findings = append(findings, newFinding("linux-sudoers-dir", audit.CategoryPermissions, "Linux sudoers.d directory", status, severity, strings.Join(evidence, "; "), "sudoers.d should not be group/world writable. This audit does not read include file contents.", ""))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(sudoersDir, entry.Name())
		status, severity, evidence := metadataStatus(path)
		findings = append(findings, newFinding("linux-sudoers-entry-"+safeID(path), audit.CategoryPermissions, "Linux sudoers.d entry metadata: "+entry.Name(), status, severity, strings.Join(evidence, "; "), "Review unexpected sudoers include files manually with visudo-compatible tooling.", ""))
	}
	return findings
}

func safetySnippet(value string, limit int) string {
	value = strings.TrimSpace(safety.RedactSensitiveText(value))
	if len(value) > limit {
		value = value[:limit] + "..."
	}
	return value
}
