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

func RunPermissions(ctx context.Context, cfg audit.RuntimeConfig) (audit.CheckResult, error) {
	_ = ctx
	var findings []audit.Finding
	findings = append(findings, checkHomePermissions(cfg.HomeDir))
	findings = append(findings, checkSSHPermissions(cfg.HomeDir)...)
	findings = append(findings, checkShellFilePermissions(cfg.HomeDir)...)
	findings = append(findings, checkWorldWritableConfigFiles(cfg.HomeDir, cfg.ProjectRoot)...)
	if platform.SupportsLaunchdPersistence() {
		findings = append(findings, checkLaunchPermissions(cfg.HomeDir)...)
	} else {
		findings = append(findings, unsupportedPlatformFinding("permissions-launchd-skipped", audit.CategoryPermissions, "LaunchAgent/Daemon plist permissions skipped", "launchd plist permission checks", "macOS"))
	}
	return audit.CheckResult{Findings: findings}, nil
}

func checkHomePermissions(home string) audit.Finding {
	meta, err := platform.StatMeta(home)
	if err != nil {
		return newFinding("permissions-home", audit.CategoryPermissions, "Home directory permissions", audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review home directory permissions manually.", "")
	}
	status := audit.StatusPass
	severity := audit.SeverityInfo
	if platform.IsWorldWritable(meta.Mode) {
		status = audit.StatusFail
		severity = audit.SeverityHigh
	}
	return newFinding("permissions-home", audit.CategoryPermissions, "Home directory permissions", status, severity, fmt.Sprintf("path=%s mode=%s", home, platform.FormatPerm(meta.Mode)), "Home directories should not be world-writable.", "")
}

func checkSSHPermissions(home string) []audit.Finding {
	sshDir := filepath.Join(home, ".ssh")
	meta, err := platform.StatMeta(sshDir)
	if err != nil {
		return []audit.Finding{newFinding("permissions-ssh-dir", audit.CategoryPermissions, "~/.ssh directory", audit.StatusInfo, audit.SeverityInfo, "No ~/.ssh directory found or unreadable.", "No action needed if SSH is not used.", "")}
	}
	var findings []audit.Finding
	status := audit.StatusPass
	severity := audit.SeverityInfo
	if meta.Mode.Perm() != 0o700 {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
	}
	findings = append(findings, newFinding("permissions-ssh-dir", audit.CategoryPermissions, "~/.ssh directory", status, severity, fmt.Sprintf("path=%s mode=%s", sshDir, platform.FormatPerm(meta.Mode)), "Set ~/.ssh to 700 and keep private key files at 600.", ""))

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return findings
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(sshDir, name)
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		if isLikelySSHPrivateKey(name) {
			status := audit.StatusPass
			severity := audit.SeverityInfo
			if meta.Mode.Perm()&0o077 != 0 {
				status = audit.StatusFail
				severity = audit.SeverityHigh
			}
			findings = append(findings, newFinding("permissions-ssh-key-"+safeID(name), audit.CategoryPermissions, "SSH private key permissions: "+name, status, severity, fmt.Sprintf("path=%s mode=%s size=%d mtime=%s", path, platform.FormatPerm(meta.Mode), meta.Size, meta.ModTime.Format("2006-01-02")), "SSH private keys should be readable only by the owner, typically chmod 600.", ""))
		}
	}
	return findings
}

func isLikelySSHPrivateKey(name string) bool {
	if strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".cert") {
		return false
	}
	if strings.HasPrefix(name, "id_") {
		return true
	}
	switch name {
	case "identity", "ssh_host_rsa_key", "ssh_host_ed25519_key", "ssh_host_ecdsa_key":
		return true
	default:
		return false
	}
}

func checkShellFilePermissions(home string) []audit.Finding {
	names := []string{".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"}
	var findings []audit.Finding
	for _, name := range names {
		path := filepath.Join(home, name)
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		status := audit.StatusPass
		severity := audit.SeverityInfo
		if platform.IsWorldWritable(meta.Mode) {
			status = audit.StatusFail
			severity = audit.SeverityHigh
		} else if platform.IsGroupWritable(meta.Mode) {
			status = audit.StatusWarn
			severity = audit.SeverityMedium
		}
		findings = append(findings, newFinding("permissions-shell-"+safeID(name), audit.CategoryPermissions, "Shell startup file permissions: "+name, status, severity, fmt.Sprintf("path=%s mode=%s", path, platform.FormatPerm(meta.Mode)), "Shell startup files should not be group/world writable.", ""))
	}
	return findings
}

func checkWorldWritableConfigFiles(home string, projectRoot string) []audit.Finding {
	var findings []audit.Finding
	roots := []string{filepath.Join(home, ".config"), filepath.Join(home, "Library", "Application Support")}
	if projectRoot != "" {
		roots = append(roots, projectRoot)
	}
	limit := 50
	for _, root := range roots {
		if len(findings) >= limit {
			break
		}
		walkLimited(root, home, func(path string, d os.DirEntry) {
			if len(findings) >= limit || d.IsDir() {
				return
			}
			meta, err := platform.StatMeta(path)
			if err != nil {
				return
			}
			if platform.IsWorldWritable(meta.Mode) {
				findings = append(findings, newFinding("permissions-world-writable-"+safeID(path), audit.CategoryPermissions, "World-writable config file", audit.StatusFail, audit.SeverityHigh, fmt.Sprintf("path=%s mode=%s", path, platform.FormatPerm(meta.Mode)), "Remove world-writable permission from configuration files, especially before opening projects with AI agents.", ""))
			}
		})
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("permissions-world-writable-config", audit.CategoryPermissions, "World-writable user/project config files", audit.StatusPass, audit.SeverityInfo, "No world-writable files found in sampled user/project config directories.", "No action needed.", ""))
	}
	return findings
}

func checkLaunchPermissions(home string) []audit.Finding {
	dirs := []string{
		filepath.Join(home, "Library", "LaunchAgents"),
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
	}
	var findings []audit.Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			meta, err := platform.StatMeta(path)
			if err != nil {
				continue
			}
			if platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode) {
				findings = append(findings, newFinding("permissions-launch-"+safeID(path), audit.CategoryPermissions, "Writable LaunchAgent/Daemon plist", audit.StatusFail, audit.SeverityHigh, fmt.Sprintf("path=%s mode=%s", path, platform.FormatPerm(meta.Mode)), "LaunchAgent/Daemon plists should not be writable by group or world.", ""))
			}
		}
	}
	return findings
}
