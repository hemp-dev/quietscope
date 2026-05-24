//go:build desktop
// +build desktop

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/hemp-dev/quietscope/internal/app"
	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// JobSnapshot represents the state of an audit job exposed to the frontend.
type JobSnapshot struct {
	ID         string                `json:"id"`
	Status     string                `json:"status"`
	OutputDir  string                `json:"output_dir"`
	ReportURL  string                `json:"report_url,omitempty"`
	Error      string                `json:"error,omitempty"`
	CreatedAt  time.Time             `json:"created_at"`
	StartedAt  time.Time             `json:"started_at,omitempty"`
	FinishedAt time.Time             `json:"finished_at,omitempty"`
	Summary    audit.Summary         `json:"summary"`
	Events     []audit.ProgressEvent `json:"events"`
}

type activeJob struct {
	id         string
	status     string
	cancel     context.CancelFunc
	config     app.Config
	createdAt  time.Time
	startedAt  time.Time
	finishedAt time.Time
	events     []audit.ProgressEvent
	summary    audit.Summary
	err        string
}

// App struct manages desktop-specific interactions and bridges to the audit engine.
type App struct {
	ctx   context.Context
	mu    sync.Mutex
	jobs  map[string]*activeJob
	order []string
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{
		jobs: make(map[string]*activeJob),
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// shutdown is called when the application is closing.
func (a *App) shutdown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, job := range a.jobs {
		if job.cancel != nil {
			job.cancel()
		}
	}
}

// StartAudit starts a new audit using the provided configuration JSON.
func (a *App) StartAudit(cfgJson string) (string, error) {
	var input struct {
		WantText      bool   `json:"want_text"`
		WantJSON      bool   `json:"want_json"`
		WantHTML      bool   `json:"want_html"`
		Deep          bool   `json:"deep"`
		AIAudit       bool   `json:"ai_audit"`
		NoSudo        bool   `json:"no_sudo"`
		OutputDir     string `json:"output_dir"`
		ProjectRoot   string `json:"project_root"`
		MaxFileSizeMB int    `json:"max_file_size_mb"`
	}

	if err := json.Unmarshal([]byte(cfgJson), &input); err != nil {
		return "", fmt.Errorf("invalid configuration: %w", err)
	}

	now := time.Now()
	jobID := now.UTC().Format("20060102-150405") + "-" + randomHex(4)

	cfg := app.Config{
		Version:       "v0.5.0",
		StartedAt:     now,
		WantText:      input.WantText,
		WantJSON:      true, // Always generate JSON internally for the desktop viewer
		WantHTML:      input.WantHTML,
		Deep:          input.Deep,
		AIAudit:       input.AIAudit,
		CleanDryRun:   false,
		CleanConfirm:  false,
		NoSudo:        input.NoSudo,
		ProjectRoot:   input.ProjectRoot,
		MaxFileSizeMB: input.MaxFileSizeMB,
	}

	if input.OutputDir != "" {
		cfg.OutputDir = input.OutputDir
	} else {
		home := platform.HomeDir()
		if home == "" {
			home = "."
		}
		cfg.OutputDir = filepath.Join(home, "Desktop", fmt.Sprintf("quietscope-desktop-audit-%s-%s", now.Format("20060102-150405"), jobID[len(jobID)-8:]))
	}

	jobCtx, cancel := context.WithCancel(context.Background())

	job := &activeJob{
		id:        jobID,
		status:    "queued",
		cancel:    cancel,
		config:    cfg,
		createdAt: now,
	}

	a.mu.Lock()
	a.jobs[jobID] = job
	a.order = append([]string{jobID}, a.order...)
	a.mu.Unlock()

	// Emit initial state
	wailsRuntime.EventsEmit(a.ctx, "job_added", jobID)

	go a.runAuditJob(jobCtx, job)

	return jobID, nil
}

func (a *App) runAuditJob(ctx context.Context, job *activeJob) {
	a.mu.Lock()
	job.status = "running"
	job.startedAt = time.Now()
	a.mu.Unlock()

	wailsRuntime.EventsEmit(a.ctx, "job_started", job.id)

	report, err := app.Run(ctx, job.config, app.RunOptions{
		Progress: func(event audit.ProgressEvent) {
			a.mu.Lock()
			job.events = append(job.events, event)
			if len(job.events) > 300 {
				job.events = append([]audit.ProgressEvent(nil), job.events[len(job.events)-300:]...)
			}
			a.mu.Unlock()

			// Stream progress event to Wails frontend
			wailsRuntime.EventsEmit(a.ctx, fmt.Sprintf("job_progress:%s", job.id), event)
		},
		SuppressTerminalProgress: true,
	})

	a.mu.Lock()
	job.finishedAt = time.Now()
	job.cancel = nil
	job.summary = report.Summary
	if err == nil {
		job.status = "completed"
	} else if ctx.Err() != nil {
		job.status = "canceled"
		job.err = "Audit canceled by user."
	} else {
		job.status = "failed"
		job.err = err.Error()
	}
	a.mu.Unlock()

	wailsRuntime.EventsEmit(a.ctx, "job_finished", job.id)
}

// CancelAudit requests the cancellation of a running audit.
func (a *App) CancelAudit(jobID string) error {
	a.mu.Lock()
	job, exists := a.jobs[jobID]
	a.mu.Unlock()

	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	a.mu.Lock()
	if job.status == "running" || job.status == "queued" {
		job.status = "canceling"
		if job.cancel != nil {
			job.cancel()
		}
	}
	a.mu.Unlock()

	wailsRuntime.EventsEmit(a.ctx, "job_canceling", jobID)
	return nil
}

// GetJobs returns a JSON-serialized array of all job snapshots.
func (a *App) GetJobs() (string, error) {
	a.mu.Lock()
	ids := append([]string(nil), a.order...)
	a.mu.Unlock()

	snapshots := make([]JobSnapshot, 0, len(ids))
	for _, id := range ids {
		a.mu.Lock()
		job, exists := a.jobs[id]
		if exists {
			reportURL := ""
			if job.status == "completed" && job.config.WantHTML {
				reportURL = filepath.Join(job.config.OutputDir, "report.html")
			}
			snapshots = append(snapshots, JobSnapshot{
				ID:         job.id,
				Status:     job.status,
				OutputDir:  job.config.OutputDir,
				ReportURL:  reportURL,
				Error:      job.err,
				CreatedAt:  job.createdAt,
				StartedAt:  job.startedAt,
				FinishedAt: job.finishedAt,
				Summary:    job.summary,
				Events:     job.events,
			})
		}
		a.mu.Unlock()
	}

	data, err := json.Marshal(snapshots)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// OpenReport safely opens the generated report file in the default web browser.
func (a *App) OpenReport(path string) error {
	if path == "" {
		return fmt.Errorf("empty report path")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	default:
		return fmt.Errorf("unsupported platform for opening reports automatically")
	}

	return cmd.Start()
}

// GetReportJSON reads and returns the generated report.json file content.
func (a *App) GetReportJSON(jobID string) (string, error) {
	a.mu.Lock()
	job, exists := a.jobs[jobID]
	a.mu.Unlock()

	if !exists {
		return "", fmt.Errorf("job %s not found", jobID)
	}

	if job.status != "completed" {
		return "", fmt.Errorf("job %s is not completed", jobID)
	}

	// The JSON report is written as report.json inside output_dir
	jsonPath := filepath.Join(job.config.OutputDir, "report.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return "", fmt.Errorf("failed to read report file: %w", err)
	}

	return string(data), nil
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (a *App) getHomeAndProjectRoot() (string, string) {
	home := platform.HomeDir()
	a.mu.Lock()
	defer a.mu.Unlock()
	projectRoot := ""
	for _, job := range a.jobs {
		if job.config.ProjectRoot != "" {
			projectRoot = job.config.ProjectRoot
			break
		}
	}
	return home, projectRoot
}

// DeletePath safely deletes a file or directory.
func (a *App) DeletePath(path string) error {
	home, proj := a.getHomeAndProjectRoot()
	return safety.DeletePath(path, home, proj)
}

// DisablePath safely disables/enables an AI skill/rules file.
func (a *App) DisablePath(path string) error {
	home, proj := a.getHomeAndProjectRoot()
	return safety.DisablePath(path, home, proj)
}

// FixAISkill safely comments out suspicious patterns in an AI skill file.
func (a *App) FixAISkill(path string) error {
	home, proj := a.getHomeAndProjectRoot()
	return safety.FixAISkill(path, home, proj)
}
