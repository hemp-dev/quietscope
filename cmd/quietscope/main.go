package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/hemp-dev/quietscope/internal/app"
)

const version = "v0.5.1"

func main() {
	var cfg app.Config
	var showVersion bool
	var allReports bool
	var noAIAudit bool
	var uiMode bool

	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.BoolVar(&cfg.WantJSON, "json", false, "Save JSON report.")
	flags.BoolVar(&cfg.WantHTML, "html", false, "Save self-contained HTML report.")
	flags.BoolVar(&cfg.WantText, "text", false, "Save text report.")
	flags.BoolVar(&allReports, "all-reports", false, "Save text, JSON, and HTML reports.")
	flags.BoolVar(&cfg.Deep, "deep", false, "Enable deeper checks. This may take longer and scans only safe text metadata/content classes.")
	flags.BoolVar(&cfg.AIAudit, "ai-audit", true, "Enable local AI tooling, MCP, local LLM server, and prompt-injection artifact checks.")
	flags.BoolVar(&noAIAudit, "no-ai-audit", false, "Disable AI audit checks.")
	flags.BoolVar(&cfg.CleanDryRun, "clean-dry-run", false, "Show safe cleanup candidates without deleting anything.")
	flags.BoolVar(&cfg.CleanConfirm, "clean-confirm", false, "Delete only allowlisted safe cache files after exact interactive confirmation.")
	flags.BoolVar(&cfg.NoSudo, "no-sudo", false, "Do not use sudo; skip checks requiring elevated privileges.")
	flags.StringVar(&cfg.OutputDir, "output", "", "Directory for reports. Default: ~/Desktop/quietscope-audit-YYYYMMDD-HHMMSS")
	flags.StringVar(&cfg.ProjectRoot, "project-root", "", "Additional project directory for deep AI/prompt-injection scan.")
	flags.IntVar(&cfg.MaxFileSizeMB, "max-file-size-mb", 5, "Maximum text file size for scan in MB.")
	flags.BoolVar(&cfg.Serve, "serve", false, "Serve generated report directory through a temporary 127.0.0.1-only static server.")
	flags.BoolVar(&uiMode, "ui", false, "Start the local 127.0.0.1 audit UI to configure, launch, monitor, cancel, and open audits.")
	flags.BoolVar(&showVersion, "version", false, "Print version and exit.")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "quietscope %s\n\n", version)
		fmt.Fprintln(flags.Output(), "Defensive local audit for security, privacy, storage hygiene, and AI-agent risk surface.")
		fmt.Fprintln(flags.Output(), "This tool is for defensive local auditing only. It does not exploit vulnerabilities, exfiltrate data, or modify system settings. Review all findings before taking action.")
		fmt.Fprintln(flags.Output(), "\nUsage:")
		fmt.Fprintf(flags.Output(), "  %s [flags]\n\n", os.Args[0])
		fmt.Fprintln(flags.Output(), "Flags:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if showVersion {
		fmt.Println(version)
		return
	}
	if allReports {
		cfg.WantText = true
		cfg.WantJSON = true
		cfg.WantHTML = true
	}
	if noAIAudit {
		cfg.AIAudit = false
	}
	cfg.Version = version

	if uiMode {
		if err := app.ServeAuditUI(context.Background(), cfg, app.RunOptions{}); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if _, err := app.Run(context.Background(), cfg, app.RunOptions{}); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
