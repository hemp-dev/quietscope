package checks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
	"github.com/projectauthors/quietscope/internal/safety"
)

func RunPersistence(ctx context.Context, cfg audit.RuntimeConfig, runner *platform.Runner) (audit.CheckResult, error) {
	var findings []audit.Finding
	if platform.SupportsLaunchdPersistence() {
		paths := []string{
			filepath.Join(cfg.HomeDir, "Library", "LaunchAgents"),
			"/Library/LaunchAgents",
			"/Library/LaunchDaemons",
			"/System/Library/LaunchAgents",
			"/System/Library/LaunchDaemons",
		}
		for _, dir := range paths {
			findings = append(findings, inspectLaunchDirectory(dir, cfg.HomeDir)...)
		}
	} else {
		findings = append(findings, unsupportedPlatformFinding("persistence-launchd-skipped", audit.CategoryPersistence, "LaunchAgents/LaunchDaemons skipped", "launchd persistence directory inspection", "macOS"))
	}
	findings = append(findings, inspectCrontab(ctx, runner)...)
	findings = append(findings, inspectCronFiles(cfg.HomeDir)...)
	findings = append(findings, inspectShellStartupFiles(cfg.HomeDir)...)
	return audit.CheckResult{Findings: findings}, nil
}

func inspectLaunchDirectory(dir string, home string) []audit.Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []audit.Finding{newFinding("persistence-dir-"+safeID(dir), audit.CategoryPersistence, "Persistence directory unavailable: "+dir, audit.StatusInfo, audit.SeverityInfo, err.Error(), "This is expected for missing or protected directories. Review manually if this location should exist.", "")}
	}
	var findings []audit.Finding
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		findings = append(findings, inspectLaunchPlist(path, home))
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("persistence-dir-empty-"+safeID(dir), audit.CategoryPersistence, "No LaunchAgent/Daemon plists found in "+dir, audit.StatusPass, audit.SeverityInfo, "Directory exists and contains no plist items.", "No action needed.", ""))
	}
	return findings
}

func inspectLaunchPlist(path string, home string) audit.Finding {
	meta, metaErr := platform.StatMeta(path)
	status := audit.StatusInfo
	severity := audit.SeverityInfo
	evidenceParts := []string{fmt.Sprintf("path=%s", path)}
	if metaErr == nil {
		evidenceParts = append(evidenceParts, fmt.Sprintf("mode=%s uid=%d gid=%d", platform.FormatPerm(meta.Mode), meta.UID, meta.GID))
		if platform.IsWorldWritable(meta.Mode) || platform.IsGroupWritable(meta.Mode) {
			status = audit.StatusFail
			severity = audit.SeverityHigh
			evidenceParts = append(evidenceParts, "plist is group/world writable")
		}
	}
	plist, err := platform.ParsePlistFile(path, 2*1024*1024)
	if err != nil {
		evidenceParts = append(evidenceParts, "plist_parse="+err.Error())
		return newFinding("persistence-plist-"+safeID(path), audit.CategoryPersistence, "Launch plist metadata: "+filepath.Base(path), status, severity, strings.Join(evidenceParts, "; "), "If this plist is unfamiliar, inspect it manually with plutil or a trusted editor before unloading or deleting anything.", "")
	}
	label := plistScalar(plist["Label"])
	program := plistScalar(plist["Program"])
	args := plistArray(plist["ProgramArguments"])
	runAtLoad := plistScalar(plist["RunAtLoad"])
	keepAlive := plistScalar(plist["KeepAlive"])
	commandText := strings.Join(append([]string{program}, args...), " ")
	evidenceParts = append(evidenceParts,
		"label="+label,
		"program="+program,
		"args="+strings.Join(args, " "),
		"RunAtLoad="+runAtLoad,
		"KeepAlive="+keepAlive,
	)
	if hasSuspiciousPersistencePath(commandText, home) || IsDangerousCommandPattern(commandText) {
		status = audit.StatusWarn
		if severity != audit.SeverityHigh {
			severity = audit.SeverityHigh
		}
		evidenceParts = append(evidenceParts, "suspicious persistence command/path pattern detected")
	}
	finding := newFinding("persistence-plist-"+safeID(path), audit.CategoryPersistence, "Launch plist: "+filepath.Base(path), status, severity, strings.Join(evidenceParts, "; "), "Review unfamiliar LaunchAgents/LaunchDaemons. Do not run embedded commands; validate vendor, path ownership, signature, and necessity first.", "")
	finding.CommandExecutionRisk = IsDangerousCommandPattern(commandText)
	finding.NetworkExfiltrationRisk = containsNetworkTool(commandText)
	return finding
}

func inspectCrontab(ctx context.Context, runner *platform.Runner) []audit.Finding {
	result := runner.Run(ctx, "crontab", "-l")
	if !result.Available || result.ExitCode != 0 || result.Output == "" {
		return []audit.Finding{newFinding("persistence-user-crontab", audit.CategoryPersistence, "User crontab", audit.StatusInfo, audit.SeverityInfo, commandEvidence(result), "If you use cron, inspect your crontab manually. This audit does not execute cron entries.", platform.FormatCommand("crontab", "-l"))}
	}
	count, suspicious := scanReaderForDangerousPatterns(strings.NewReader(result.Output), 0)
	status := audit.StatusPass
	severity := audit.SeverityInfo
	evidence := fmt.Sprintf("crontab entries=%d", count)
	if len(suspicious) > 0 {
		status = audit.StatusWarn
		severity = audit.SeverityHigh
		evidence += "; suspicious patterns: " + strings.Join(suspicious, ", ")
	}
	f := newFinding("persistence-user-crontab", audit.CategoryPersistence, "User crontab", status, severity, evidence, "Review cron entries before removing anything; unexpected network, shell, or launchctl usage may indicate risky persistence.", platform.FormatCommand("crontab", "-l"))
	f.CommandExecutionRisk = len(suspicious) > 0
	f.NetworkExfiltrationRisk = containsAnyPattern(strings.Join(suspicious, " "), []string{"curl", "wget", "nc", "socat"})
	return []audit.Finding{f}
}

func inspectCronFiles(home string) []audit.Finding {
	var findings []audit.Finding
	if _, err := os.Stat("/etc/crontab"); err == nil {
		findings = append(findings, scanFileForPersistence("/etc/crontab", home, "System crontab"))
	} else {
		findings = append(findings, newFinding("persistence-etc-crontab", audit.CategoryPersistence, "System crontab", audit.StatusInfo, audit.SeverityInfo, "No readable /etc/crontab found.", "No action needed unless your environment uses system cron.", ""))
	}
	periodic := "/etc/periodic"
	if entries, err := os.ReadDir(periodic); err == nil {
		findings = append(findings, newFinding("persistence-periodic", audit.CategoryPersistence, "Periodic scripts directory", audit.StatusInfo, audit.SeverityLow, fmt.Sprintf("%s exists with %d top-level entries", periodic, len(entries)), "Review periodic scripts manually if you do not expect this host to use periodic maintenance jobs.", ""))
	}
	_ = home
	return findings
}

func inspectShellStartupFiles(home string) []audit.Finding {
	names := []string{".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"}
	var findings []audit.Finding
	for _, name := range names {
		path := filepath.Join(home, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		findings = append(findings, scanFileForPersistence(path, home, "Shell startup file: "+name))
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("persistence-shell-startup-none", audit.CategoryPersistence, "Shell startup files", audit.StatusInfo, audit.SeverityInfo, "No common shell startup files found in the home directory.", "No action needed.", ""))
	}
	return findings
}

func scanFileForPersistence(path string, home string, title string) audit.Finding {
	file, err := os.Open(path)
	if err != nil {
		return newFinding("persistence-file-"+safeID(path), audit.CategoryPersistence, title, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review manually if this file should be readable.", "")
	}
	defer file.Close()
	count, suspicious := scanReaderForDangerousPatterns(file, 512*1024)
	status := audit.StatusPass
	severity := audit.SeverityInfo
	evidence := fmt.Sprintf("path=%s lines_scanned=%d", path, count)
	if len(suspicious) > 0 {
		status = audit.StatusWarn
		severity = audit.SeverityMedium
		evidence += "; suspicious patterns: " + strings.Join(suspicious, ", ")
	}
	if hasSuspiciousPersistencePath(strings.Join(suspicious, " "), home) {
		severity = audit.SeverityHigh
	}
	f := newFinding("persistence-file-"+safeID(path), audit.CategoryPersistence, title, status, severity, evidence, "Review suspicious shell startup commands before launching AI agents or terminal sessions in untrusted repositories.", "")
	f.CommandExecutionRisk = len(suspicious) > 0
	f.NetworkExfiltrationRisk = containsNetworkTool(strings.Join(suspicious, " "))
	return f
}

func scanReaderForDangerousPatterns(r io.Reader, maxBytes int64) (int, []string) {
	if maxBytes > 0 {
		r = io.LimitReader(r, maxBytes)
	}
	scanner := bufio.NewScanner(r)
	var suspicious []string
	lineNo := 0
	seen := map[string]bool{}
	for scanner.Scan() {
		lineNo++
		line := safety.RedactSensitiveText(scanner.Text())
		if IsDangerousCommandPattern(line) {
			pattern := matchedDangerousPattern(line)
			if pattern == "" {
				pattern = "dangerous command pattern"
			}
			item := fmt.Sprintf("line %d: %s", lineNo, pattern)
			if !seen[item] {
				seen[item] = true
				suspicious = append(suspicious, item)
			}
		}
	}
	return lineNo, suspicious
}

func plistScalar(v any) string {
	switch x := v.(type) {
	case string:
		return safety.RedactSensitiveText(x)
	case bool:
		return fmt.Sprintf("%t", x)
	case map[string]any:
		return "[dict]"
	case []any:
		return strings.Join(plistArray(x), " ")
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

func plistArray(v any) []string {
	values, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, item := range values {
		out = append(out, plistScalar(item))
	}
	return out
}

func hasSuspiciousPersistencePath(commandText string, home string) bool {
	lower := strings.ToLower(commandText)
	suspicious := []string{"/tmp", "/var/tmp", "/private/tmp", "/downloads"}
	if home != "" {
		suspicious = append(suspicious, strings.ToLower(filepath.Join(home, "Downloads")))
	}
	for _, needle := range suspicious {
		if strings.Contains(lower, strings.ToLower(needle)) {
			return true
		}
	}
	parts := strings.Split(commandText, string(os.PathSeparator))
	for _, part := range parts {
		if strings.HasPrefix(part, ".") && len(part) > 1 {
			return true
		}
	}
	return false
}

func safeID(input string) string {
	replacer := strings.NewReplacer("/", "-", " ", "-", ".", "-", "_", "-", ":", "-", "~", "home")
	id := strings.Trim(replacer.Replace(strings.ToLower(input)), "-")
	if len(id) > 120 {
		return id[len(id)-120:]
	}
	if id == "" {
		return "unknown"
	}
	return id
}

func walkLimited(root string, home string, fn func(path string, d fs.DirEntry)) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if platform.ShouldExcludePath(path, home) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		fn(path, d)
		return nil
	})
}
