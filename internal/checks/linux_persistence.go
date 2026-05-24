package checks

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
	"github.com/projectauthors/quietscope/internal/safety"
)

type linuxPathSet struct {
	systemdDirs       []string
	cronPaths         []string
	userSystemdDirs   []string
	autostartDirs     []string
	shellStartupFiles []string
}

func linuxPersistenceFindings(cfg audit.RuntimeConfig) []audit.Finding {
	return linuxPersistenceFindingsForPaths(cfg.HomeDir, defaultLinuxPersistencePaths(cfg.HomeDir))
}

func defaultLinuxPersistencePaths(home string) linuxPathSet {
	return linuxPathSet{
		systemdDirs: []string{
			"/etc/systemd/system",
			"/usr/local/lib/systemd/system",
			"/usr/lib/systemd/system",
			"/lib/systemd/system",
			"/etc/systemd/user",
		},
		cronPaths: []string{
			"/etc/crontab",
			"/etc/cron.d",
			"/etc/cron.daily",
			"/etc/cron.hourly",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron",
			"/var/spool/cron/crontabs",
		},
		userSystemdDirs: []string{
			filepath.Join(home, ".config", "systemd", "user"),
			filepath.Join(home, ".local", "share", "systemd", "user"),
		},
		autostartDirs: []string{
			filepath.Join(home, ".config", "autostart"),
			"/etc/xdg/autostart",
		},
		shellStartupFiles: []string{
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".bash_profile"),
			filepath.Join(home, ".profile"),
			filepath.Join(home, ".zshrc"),
			filepath.Join(home, ".xprofile"),
		},
	}
}

func linuxPersistenceFindingsForPaths(home string, paths linuxPathSet) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, inspectLinuxSystemdDirs(paths.systemdDirs, home, "system")...)
	findings = append(findings, inspectLinuxSystemdDirs(paths.userSystemdDirs, home, "user")...)
	findings = append(findings, inspectLinuxCronPaths(paths.cronPaths, home)...)
	findings = append(findings, inspectLinuxAutostartDirs(paths.autostartDirs, home)...)
	findings = append(findings, inspectLinuxShellStartupFiles(paths.shellStartupFiles, home)...)
	if len(findings) == 0 {
		findings = append(findings, newFinding("linux-persistence-overview", audit.CategoryPersistence, "Linux persistence metadata", audit.StatusInfo, audit.SeverityInfo, "No Linux persistence locations were readable in the scoped paths.", "No action needed unless this Linux host uses custom persistence locations.", ""))
	}
	return findings
}

func inspectLinuxSystemdDirs(dirs []string, home string, scope string) []audit.Finding {
	var findings []audit.Finding
	readable := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			findings = append(findings, newFinding("linux-systemd-dir-"+safeID(dir), audit.CategoryPersistence, "Linux systemd directory unavailable: "+dir, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Missing or protected systemd directories are expected on some distributions. Review manually if this location should exist.", ""))
			continue
		}
		readable++
		unitCount := 0
		for _, entry := range entries {
			if entry.IsDir() || !isSystemdUnitName(entry.Name()) {
				continue
			}
			unitCount++
			findings = append(findings, inspectLinuxSystemdUnit(filepath.Join(dir, entry.Name()), home, scope))
			if unitCount >= 50 {
				findings = append(findings, newFinding("linux-systemd-dir-limit-"+safeID(dir), audit.CategoryPersistence, "Linux systemd directory sampled: "+dir, audit.StatusInfo, audit.SeverityInfo, "Inspected first 50 service/timer/socket units in this directory.", "Review the full directory manually if unexpected persistence is suspected.", ""))
				break
			}
		}
		if unitCount == 0 {
			findings = append(findings, newFinding("linux-systemd-dir-empty-"+safeID(dir), audit.CategoryPersistence, "Linux systemd directory: "+dir, audit.StatusInfo, audit.SeverityInfo, "Directory is readable and contains no sampled service/timer/socket unit files.", "No action needed unless this location should contain units.", ""))
		}
	}
	if readable == 0 && len(dirs) > 0 {
		findings = append(findings, newFinding("linux-systemd-"+scope+"-unavailable", audit.CategoryPersistence, "Linux "+scope+" systemd units", audit.StatusInfo, audit.SeverityInfo, "No configured "+scope+" systemd directories were readable.", "This can be normal on minimal systems. Review manually if systemd is expected.", ""))
	}
	return findings
}

func isSystemdUnitName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".service") || strings.HasSuffix(lower, ".timer") || strings.HasSuffix(lower, ".socket") || strings.HasSuffix(lower, ".path")
}

func inspectLinuxSystemdUnit(path string, home string, scope string) audit.Finding {
	status, severity, evidenceParts := metadataStatus(path)
	unitInfo := scanLinuxPersistenceFile(path, home, "ExecStart", "ExecStartPre", "ExecStartPost", "OnCalendar", "WantedBy")
	evidenceParts = append(evidenceParts, unitInfo.evidence...)
	if unitInfo.suspicious {
		status = audit.StatusWarn
		if severity != audit.SeverityHigh {
			severity = audit.SeverityHigh
		}
	}
	title := fmt.Sprintf("Linux %s systemd unit: %s", scope, filepath.Base(path))
	f := newFinding("linux-systemd-unit-"+safeID(path), audit.CategoryPersistence, title, status, severity, strings.Join(evidenceParts, "; "), "Review unfamiliar systemd units without executing embedded commands. Validate package ownership, unit path, permissions, and ExecStart values.", "")
	f.CommandExecutionRisk = unitInfo.commandRisk
	f.NetworkExfiltrationRisk = unitInfo.networkRisk
	return f
}

func inspectLinuxCronPaths(paths []string, home string) []audit.Finding {
	var findings []audit.Finding
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			findings = append(findings, newFinding("linux-cron-path-"+safeID(path), audit.CategoryPersistence, "Linux cron path unavailable: "+path, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Missing cron paths are expected on systems using only systemd timers.", ""))
			continue
		}
		if info.IsDir() {
			findings = append(findings, inspectLinuxCronDir(path, home)...)
			continue
		}
		findings = append(findings, inspectLinuxCronFile(path, home, "Linux cron file: "+filepath.Base(path)))
	}
	return findings
}

func inspectLinuxCronDir(dir string, home string) []audit.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []audit.Finding{newFinding("linux-cron-dir-"+safeID(dir), audit.CategoryPersistence, "Linux cron directory unavailable: "+dir, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review manually if this directory should be readable.", "")}
	}
	if len(entries) == 0 {
		return []audit.Finding{newFinding("linux-cron-dir-empty-"+safeID(dir), audit.CategoryPersistence, "Linux cron directory: "+dir, audit.StatusInfo, audit.SeverityInfo, "Directory is readable and empty.", "No action needed.", "")}
	}
	var findings []audit.Finding
	for i, entry := range entries {
		if i >= 50 {
			findings = append(findings, newFinding("linux-cron-dir-limit-"+safeID(dir), audit.CategoryPersistence, "Linux cron directory sampled: "+dir, audit.StatusInfo, audit.SeverityInfo, "Inspected first 50 entries in this directory.", "Review the full directory manually if unexpected persistence is suspected.", ""))
			break
		}
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			status, severity, evidence := metadataStatus(path)
			findings = append(findings, newFinding("linux-cron-entry-"+safeID(path), audit.CategoryPersistence, "Linux cron subdirectory metadata: "+entry.Name(), status, severity, strings.Join(evidence, "; "), "Review unexpected cron subdirectories manually.", ""))
			continue
		}
		findings = append(findings, inspectLinuxCronFile(path, home, "Linux cron entry: "+entry.Name()))
	}
	return findings
}

func inspectLinuxCronFile(path string, home string, title string) audit.Finding {
	status, severity, evidenceParts := metadataStatus(path)
	fileInfo := scanLinuxPersistenceFile(path, home, "", "curl", "wget", "bash -c", "sh -c", "python -c", "node -e")
	evidenceParts = append(evidenceParts, fileInfo.evidence...)
	if fileInfo.suspicious {
		status = audit.StatusWarn
		if severity != audit.SeverityHigh {
			severity = audit.SeverityMedium
		}
	}
	f := newFinding("linux-cron-file-"+safeID(path), audit.CategoryPersistence, title, status, severity, strings.Join(evidenceParts, "; "), "Review unexpected cron entries before editing or removing them. This audit does not execute cron commands.", "")
	f.CommandExecutionRisk = fileInfo.commandRisk
	f.NetworkExfiltrationRisk = fileInfo.networkRisk
	return f
}

func inspectLinuxAutostartDirs(dirs []string, home string) []audit.Finding {
	var findings []audit.Finding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			findings = append(findings, newFinding("linux-autostart-dir-"+safeID(dir), audit.CategoryPersistence, "Linux desktop autostart unavailable: "+dir, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Missing desktop autostart directories are expected on headless systems.", ""))
			continue
		}
		count := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".desktop") {
				continue
			}
			count++
			findings = append(findings, inspectLinuxAutostartFile(filepath.Join(dir, entry.Name()), home))
		}
		if count == 0 {
			findings = append(findings, newFinding("linux-autostart-empty-"+safeID(dir), audit.CategoryPersistence, "Linux desktop autostart: "+dir, audit.StatusInfo, audit.SeverityInfo, "Directory is readable and contains no .desktop entries.", "No action needed.", ""))
		}
	}
	return findings
}

func inspectLinuxAutostartFile(path string, home string) audit.Finding {
	status, severity, evidenceParts := metadataStatus(path)
	fileInfo := scanLinuxPersistenceFile(path, home, "Exec", "TryExec")
	evidenceParts = append(evidenceParts, fileInfo.evidence...)
	if fileInfo.suspicious {
		status = audit.StatusWarn
		if severity != audit.SeverityHigh {
			severity = audit.SeverityHigh
		}
	}
	f := newFinding("linux-autostart-file-"+safeID(path), audit.CategoryPersistence, "Linux desktop autostart entry: "+filepath.Base(path), status, severity, strings.Join(evidenceParts, "; "), "Review unexpected desktop autostart entries before deleting or disabling them.", "")
	f.CommandExecutionRisk = fileInfo.commandRisk
	f.NetworkExfiltrationRisk = fileInfo.networkRisk
	return f
}

func inspectLinuxShellStartupFiles(paths []string, home string) []audit.Finding {
	var findings []audit.Finding
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		findings = append(findings, scanFileForPersistence(path, home, "Linux shell startup file: "+filepath.Base(path)))
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("linux-shell-startup-none", audit.CategoryPersistence, "Linux shell startup files", audit.StatusInfo, audit.SeverityInfo, "No configured Linux shell startup files found in the home directory.", "No action needed.", ""))
	}
	return findings
}

type linuxPersistenceFileInfo struct {
	evidence    []string
	suspicious  bool
	commandRisk bool
	networkRisk bool
}

func scanLinuxPersistenceFile(path string, home string, keys ...string) linuxPersistenceFileInfo {
	file, err := os.Open(path)
	if err != nil {
		return linuxPersistenceFileInfo{evidence: []string{"content_scan=" + err.Error()}}
	}
	defer file.Close()
	info := scanLinuxPersistenceReader(file, home, keys...)
	if len(info.evidence) == 0 {
		info.evidence = append(info.evidence, "content_scan=no matching startup keys or suspicious patterns in sampled text")
	}
	return info
}

func scanLinuxPersistenceReader(r io.Reader, home string, keys ...string) linuxPersistenceFileInfo {
	if linuxMaxScanBytes > 0 {
		r = io.LimitReader(r, linuxMaxScanBytes)
	}
	keySet := map[string]bool{}
	for _, key := range keys {
		keySet[strings.ToLower(key)] = true
	}
	scanner := bufio.NewScanner(r)
	seen := map[string]bool{}
	var info linuxPersistenceFileInfo
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(safety.RedactSensitiveText(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		for key := range keySet {
			if key == "" || strings.HasPrefix(lower, strings.ToLower(key)+"=") || strings.Contains(lower, strings.ToLower(key)+"=") {
				item := fmt.Sprintf("line %d %s", lineNo, redactAndTrimSnippet(line, 180))
				if !seen[item] {
					seen[item] = true
					info.evidence = append(info.evidence, item)
				}
			}
		}
		if IsDangerousCommandPattern(line) || hasSuspiciousPersistencePath(line, home) {
			pattern := matchedDangerousPattern(line)
			if pattern == "" {
				pattern = "suspicious path"
			}
			item := fmt.Sprintf("suspicious line %d: %s", lineNo, pattern)
			if !seen[item] {
				seen[item] = true
				info.evidence = append(info.evidence, item)
			}
			info.suspicious = true
			info.commandRisk = true
			info.networkRisk = info.networkRisk || containsNetworkTool(line)
		}
	}
	sort.Strings(info.evidence)
	return info
}

func metadataStatus(path string) (audit.Status, audit.Severity, []string) {
	meta, err := platform.StatMeta(path)
	if err != nil {
		return audit.StatusInfo, audit.SeverityInfo, []string{"path=" + path, "metadata=" + err.Error()}
	}
	status := audit.StatusPass
	severity := audit.SeverityInfo
	evidence := []string{fmt.Sprintf("path=%s mode=%s uid=%d gid=%d size=%d mtime=%s", path, platform.FormatPerm(meta.Mode), meta.UID, meta.GID, meta.Size, meta.ModTime.Format("2006-01-02"))}
	if platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode) {
		status = audit.StatusFail
		severity = audit.SeverityHigh
		evidence = append(evidence, "group/world writable")
	}
	return status, severity, evidence
}
