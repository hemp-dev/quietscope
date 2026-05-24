package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
	"github.com/projectauthors/quietscope/internal/safety"
)

func RunPrivacySecrets(ctx context.Context, cfg audit.RuntimeConfig) (audit.CheckResult, error) {
	_ = ctx
	var findings []audit.Finding
	findings = append(findings, secretFileMetadataFindings(cfg)...)
	findings = append(findings, sensitiveEnvironmentFindings()...)
	return audit.CheckResult{Findings: findings}, nil
}

func secretFileMetadataFindings(cfg audit.RuntimeConfig) []audit.Finding {
	paths := knownSecretMetadataPaths(cfg.HomeDir)
	paths = append(paths, projectSecretMetadataPaths(cfg)...)
	seen := map[string]bool{}
	var findings []audit.Finding
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		meta, err := platform.StatMeta(path)
		if err != nil {
			continue
		}
		status := audit.StatusInfo
		severity := audit.SeverityInfo
		if platform.IsWorldWritable(meta.Mode) {
			status = audit.StatusFail
			severity = audit.SeverityHigh
		} else if platform.IsGroupWritable(meta.Mode) {
			status = audit.StatusWarn
			severity = audit.SeverityMedium
		}
		evidence := fmt.Sprintf("path=%s mode=%s owner=%d:%d size=%d mtime=%s content_read=false", path, platform.FormatPerm(meta.Mode), meta.UID, meta.GID, meta.Size, meta.ModTime.Format("2006-01-02T15:04:05"))
		f := newFinding("secrets-metadata-"+safeID(path), audit.CategorySecrets, "Secret-sensitive file metadata", status, severity, evidence, "Keep secret files owner-readable only. Do not launch AI agents from environments that expose broad credentials.", "")
		f.DataExposureRisk = status != audit.StatusInfo
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		findings = append(findings, newFinding("secrets-metadata", audit.CategorySecrets, "Secret-sensitive file metadata", audit.StatusInfo, audit.SeverityInfo, "No known secret-sensitive files detected in scoped metadata checks.", "No action needed unless credentials are stored in custom locations.", ""))
	}
	return findings
}

func knownSecretMetadataPaths(home string) []string {
	var paths []string
	globs := []string{
		filepath.Join(home, ".ssh", "id_*"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".aws", "config"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".pypirc"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".docker", "config.json"),
	}
	for _, glob := range globs {
		matches, _ := filepath.Glob(glob)
		paths = append(paths, matches...)
	}
	dirs := []string{
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".azure"),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			paths = append(paths, dir)
		}
	}
	return paths
}

func projectSecretMetadataPaths(cfg audit.RuntimeConfig) []string {
	root := cfg.ProjectRoot
	if root == "" {
		return nil
	}
	var paths []string
	walkLimited(root, cfg.HomeDir, func(path string, d os.DirEntry) {
		if d.IsDir() {
			return
		}
		if shouldTreatAsSecretMetadata(path) {
			paths = append(paths, path)
		}
	})
	sort.Strings(paths)
	return paths
}

func shouldTreatAsSecretMetadata(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == ".env" || strings.HasPrefix(base, ".env.") || base == "secrets.json" || base == "credentials.json" {
		return true
	}
	switch base {
	case ".npmrc", ".pypirc", ".netrc", "config.json":
		return strings.Contains(strings.ToLower(path), ".docker") || base != "config.json"
	default:
		return false
	}
}

func sensitiveEnvironmentFindings() []audit.Finding {
	var names []string
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if safety.IsSensitiveEnvName(name) {
			names = append(names, name+"=***MASKED***")
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []audit.Finding{newFinding("secrets-env-vars", audit.CategorySecrets, "Sensitive environment variables", audit.StatusPass, audit.SeverityInfo, "No sensitive environment variable names detected in this process environment.", "Launch AI agents from a sanitized environment when working with untrusted repositories.", "")}
	}
	f := newFinding("secrets-env-vars", audit.CategorySecrets, "Sensitive environment variables present", audit.StatusWarn, audit.SeverityMedium, strings.Join(names, "; "), "Launch AI agents from a sanitized environment. Prefer per-project scoped tokens and avoid exporting broad cloud credentials into agent sessions.", "")
	f.DataExposureRisk = true
	return []audit.Finding{f}
}
