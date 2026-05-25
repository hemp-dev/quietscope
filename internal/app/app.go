package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/checks"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/report"
	"github.com/hemp-dev/quietscope/internal/safety"
	"github.com/hemp-dev/quietscope/internal/ui"
)

type RunOptions struct {
	Stdin                    io.Reader
	Stdout                   io.Writer
	Stderr                   io.Writer
	Progress                 audit.ProgressObserver
	SuppressTerminalProgress bool
}

func Run(ctx context.Context, cfg Config, opts RunOptions) (audit.Report, error) {
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if err := cfg.Normalize(); err != nil {
		return audit.Report{}, err
	}
	if err := ensureOutputDir(cfg.OutputDir); err != nil {
		return audit.Report{}, err
	}

	runner := platform.NewRunner(cfg.NoSudo)
	runtimeCfg := cfg.RuntimeConfig()
	progress := combinedProgressObserver(opts.Stderr, opts.Progress, opts.SuppressTerminalProgress)
	registeredChecks := []audit.NamedCheck{
		{Name: "system", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunSystem(ctx, runtimeCfg, runner)
		}},
		{Name: "security", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunSecurity(ctx, runtimeCfg, runner)
		}},
		{Name: "persistence", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunPersistence(ctx, runtimeCfg, runner)
		}},
		{Name: "permissions", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunPermissions(ctx, runtimeCfg)
		}},
		{Name: "storage", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunStorage(ctx, runtimeCfg, runner)
		}},
		{Name: "cleanup", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunCleanup(ctx, runtimeCfg)
		}},
		{Name: "privacy_secrets", Run: func(ctx context.Context) (audit.CheckResult, error) {
			return checks.RunPrivacySecrets(ctx, runtimeCfg)
		}},
	}
	if platform.IsLinux() {
		registeredChecks = append(registeredChecks,
			audit.NamedCheck{Name: "linux_persistence", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunLinuxPersistence(ctx, runtimeCfg, runner)
			}},
			audit.NamedCheck{Name: "linux_security", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunLinuxSecurity(ctx, runtimeCfg, runner)
			}},
		)
	}
	if platform.IsWindows() {
		registeredChecks = append(registeredChecks,
			audit.NamedCheck{Name: "windows_persistence", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunWindowsPersistence(ctx, runtimeCfg, runner)
			}},
			audit.NamedCheck{Name: "windows_security", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunWindowsSecurity(ctx, runtimeCfg, runner)
			}},
		)
	}
	if cfg.AIAudit {
		registeredChecks = append(registeredChecks,
			audit.NamedCheck{Name: "ai_security", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunAISecurity(ctx, runtimeCfg, runner)
			}},
			audit.NamedCheck{Name: "ai_skills_context", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunAISkillsContext(ctx, runtimeCfg)
			}},
			audit.NamedCheck{Name: "ai_tools_catalog", Run: func(ctx context.Context) (audit.CheckResult, error) {
				return checks.RunAIToolsCatalog(ctx, runtimeCfg, runner)
			}},
		)
	}
	engine := audit.NewEngine(registeredChecks...)

	result := engine.RunWithProgress(ctx, progress)
	metadata := audit.Metadata{
		ToolName:      ToolName,
		Version:       cfg.Version,
		GeneratedAt:   time.Now(),
		OutputDir:     cfg.OutputDir,
		Deep:          cfg.Deep,
		AIAudit:       cfg.AIAudit,
		NoSudo:        cfg.NoSudo,
		CleanDryRun:   cfg.CleanDryRun,
		CleanConfirm:  cfg.CleanConfirm,
		ProjectRoot:   cfg.ProjectRoot,
		MaxFileSizeMB: cfg.MaxFileSizeMB,
	}
	auditReport := audit.Report{
		Metadata:             metadata,
		SystemInfo:           result.SystemInfo,
		Findings:             result.Findings,
		CleanupCandidates:    result.CleanupCandidates,
		ManageableArtifacts:  result.ManageableArtifacts,
		AISecurity:           result.AISecurity,
		AIContextInventory:   result.AIContextInventory,
		AIRelatedDirectories: result.AIRelatedDirectories,
		AISkills:             result.AISkills,
		AIContextSummary:     result.AIContextSummary,
		AIToolCatalog:        result.AIToolCatalog,
		MCPClients:           result.MCPClients,
		MCPServers:           result.MCPServers,
		HermesAgent:          result.HermesAgent,
		OpenCode:             result.OpenCode,
		ChineseAIProviders:   result.ChineseAIProviders,
		LocalModelInventory:  result.LocalModelInventory,
		AISecurityTools:      result.AISecurityTools,
		AIProviderSummary:    result.AIProviderSummary,
		GeneratedAt:          metadata.GeneratedAt,
	}
	auditReport.ManageableArtifacts = audit.DedupeManageableArtifacts(auditReport.ManageableArtifacts)
	auditReport.Summary = audit.CalculateSummary(auditReport.Findings, auditReport.CleanupCandidates)

	if err := ctx.Err(); err != nil {
		return auditReport, err
	}
	if cfg.WantText {
		emitProgress(progress, audit.ProgressReportWriting, "Writing text report: report.txt")
		if err := report.WriteText(filepath.Join(cfg.OutputDir, "report.txt"), auditReport); err != nil {
			return auditReport, err
		}
		emitProgress(progress, audit.ProgressReportWritten, "Text report written: report.txt")
	}
	if cfg.WantJSON {
		emitProgress(progress, audit.ProgressReportWriting, "Writing JSON report: report.json")
		if err := report.WriteJSON(filepath.Join(cfg.OutputDir, "report.json"), auditReport); err != nil {
			return auditReport, err
		}
		emitProgress(progress, audit.ProgressReportWritten, "JSON report written: report.json")
	}
	if cfg.WantHTML {
		emitProgress(progress, audit.ProgressReportWriting, "Writing HTML report: report.html")
		if err := report.WriteHTML(filepath.Join(cfg.OutputDir, "report.html"), auditReport); err != nil {
			return auditReport, err
		}
		emitProgress(progress, audit.ProgressReportWritten, "HTML report written: report.html")
	}

	if cfg.CleanDryRun {
		emitProgress(progress, audit.ProgressCleanup, "Printing cleanup dry-run candidates.")
		printCleanupCandidates(opts.Stdout, auditReport.CleanupCandidates)
	}
	if cfg.CleanConfirm {
		emitProgress(progress, audit.ProgressCleanup, "Waiting for cleanup confirmation.")
		if err := confirmAndClean(opts.Stdin, opts.Stdout, auditReport.CleanupCandidates, runtimeCfg.HomeDir); err != nil {
			return auditReport, err
		}
	}

	fmt.Fprintf(opts.Stdout, "Audit complete. Reports written to: %s\n", cfg.OutputDir)
	if cfg.Serve {
		emitProgress(progress, audit.ProgressServer, "Starting local-only report server.")
		fmt.Fprintln(opts.Stdout, "Starting local-only report server. Press Ctrl+C to stop.")
		if err := ui.Serve(ctx, cfg.OutputDir, opts.Stdout); err != nil {
			return auditReport, err
		}
	}
	return auditReport, nil
}

func emitProgress(observe audit.ProgressObserver, eventType audit.ProgressEventType, message string) {
	if observe == nil {
		return
	}
	now := time.Now()
	observe(audit.ProgressEvent{
		Type:      eventType,
		Message:   message,
		StartedAt: now,
	})
}

func printCleanupCandidates(w io.Writer, candidates []audit.CleanupCandidate) {
	if len(candidates) == 0 {
		fmt.Fprintln(w, "No cleanup candidates found.")
		return
	}
	fmt.Fprintln(w, "Cleanup candidates (dry run only):")
	for _, c := range candidates {
		fmt.Fprintf(w, "- %s | %s | %s | safe=%t\n", c.Path, platform.HumanBytes(c.EstimatedSizeBytes), c.Reason, c.SafeToAutoFix)
	}
}

func confirmAndClean(stdin io.Reader, stdout io.Writer, candidates []audit.CleanupCandidate, home string) error {
	printCleanupCandidates(stdout, candidates)
	fmt.Fprintf(stdout, "\nType exactly %q to delete only allowlisted safe cache files: ", safety.CleanupConfirmationPhrase)
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return err
	}
	if strings.TrimSpace(line) != safety.CleanupConfirmationPhrase {
		fmt.Fprintln(stdout, "Confirmation phrase did not match. No files were deleted.")
		return nil
	}
	deleted, skipped := checks.ExecuteCleanup(candidates, home, stdout)
	fmt.Fprintf(stdout, "Cleanup finished. Deleted %d item(s), skipped %d item(s).\n", deleted, skipped)
	return nil
}
