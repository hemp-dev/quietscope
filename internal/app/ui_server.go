package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
	"github.com/hemp-dev/quietscope/internal/safety"
	"github.com/hemp-dev/quietscope/internal/ui"
)

type auditUIRequest struct {
	WantText      bool   `json:"want_text"`
	WantJSON      bool   `json:"want_json"`
	WantHTML      bool   `json:"want_html"`
	Deep          bool   `json:"deep"`
	AIAudit       *bool  `json:"ai_audit"`
	CleanDryRun   bool   `json:"clean_dry_run"`
	NoSudo        bool   `json:"no_sudo"`
	OutputDir     string `json:"output_dir"`
	ProjectRoot   string `json:"project_root"`
	MaxFileSizeMB int    `json:"max_file_size_mb"`
}

type auditUIConfigSnapshot struct {
	WantText      bool   `json:"want_text"`
	WantJSON      bool   `json:"want_json"`
	WantHTML      bool   `json:"want_html"`
	Deep          bool   `json:"deep"`
	AIAudit       bool   `json:"ai_audit"`
	CleanDryRun   bool   `json:"clean_dry_run"`
	NoSudo        bool   `json:"no_sudo"`
	OutputDir     string `json:"output_dir"`
	ProjectRoot   string `json:"project_root,omitempty"`
	MaxFileSizeMB int    `json:"max_file_size_mb"`
}

type auditUIJobSnapshot struct {
	ID         string                `json:"id"`
	Status     string                `json:"status"`
	Config     auditUIConfigSnapshot `json:"config"`
	OutputDir  string                `json:"output_dir"`
	ReportURL  string                `json:"report_url,omitempty"`
	Error      string                `json:"error,omitempty"`
	CreatedAt  time.Time             `json:"created_at"`
	StartedAt  time.Time             `json:"started_at,omitempty"`
	FinishedAt time.Time             `json:"finished_at,omitempty"`
	Summary    audit.Summary         `json:"summary"`
	Events     []audit.ProgressEvent `json:"events"`
}

type auditUIJob struct {
	mu         sync.Mutex
	cancel     context.CancelFunc
	id         string
	status     string
	config     auditUIConfigSnapshot
	outputDir  string
	reportURL  string
	err        string
	createdAt  time.Time
	startedAt  time.Time
	finishedAt time.Time
	summary    audit.Summary
	events     []audit.ProgressEvent
}

type auditUIServer struct {
	base   Config
	stdout io.Writer
	stderr io.Writer
	token  string
	ctx    context.Context

	mu    sync.Mutex
	order []string
	jobs  map[string]*auditUIJob
}

func ServeAuditUI(ctx context.Context, cfg Config, opts RunOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	token := randomHex(18)
	state := &auditUIServer{
		base:   cfg,
		stdout: opts.Stdout,
		stderr: opts.Stderr,
		token:  token,
		ctx:    ctx,
		jobs:   map[string]*auditUIJob{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", state.handleIndex)
	mux.HandleFunc("/api/audits", state.handleAudits)
	mux.HandleFunc("/api/audits/", state.handleAudit)
	mux.HandleFunc("/api/remediate", state.handleRemediate)
	mux.HandleFunc("/reports/", state.handleReports)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	fmt.Fprintf(opts.Stdout, "Local audit UI URL: http://%s/\n", listener.Addr().String())
	fmt.Fprintln(opts.Stdout, "The UI is bound to 127.0.0.1 and can launch read-only audits. Press Ctrl+C to stop.")

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		state.cancelRunning()
		return ctx.Err()
	case err := <-errCh:
		state.cancelRunning()
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *auditUIServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	view := struct {
		Title   string
		Version string
		Token   string
		Notice  string
	}{
		Title:   "macOS Security Audit UI",
		Version: s.base.Version,
		Token:   s.token,
		Notice:  ui.LocalOnlyNotice,
	}
	tpl, err := template.New("audit-ui").Parse(ui.ControlDashboardHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *auditUIServer) handleAudits(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSONResponse(w, http.StatusOK, s.listJobs())
	case http.MethodPost:
		if !s.requireToken(w, r) {
			return
		}
		defer r.Body.Close()
		var req auditUIRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
			http.Error(w, "invalid audit request", http.StatusBadRequest)
			return
		}
		writeJSONResponse(w, http.StatusCreated, s.startAudit(req))
	default:
		methodNotAllowed(w)
	}
}

func (s *auditUIServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/audits/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	job := s.job(id)
	if job == nil {
		http.NotFound(w, r)
		return
	}

	if len(parts) == 2 && parts[1] == "cancel" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if !s.requireToken(w, r) {
			return
		}
		job.requestCancel()
		writeJSONResponse(w, http.StatusOK, job.snapshot())
		return
	}

	if len(parts) > 1 {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSONResponse(w, http.StatusOK, job.snapshot())
	case http.MethodDelete:
		if !s.requireToken(w, r) {
			return
		}
		job.requestCancel()

		snapshot := job.snapshot()
		if snapshot.OutputDir != "" {
			safeDeleteOutputDir(snapshot.OutputDir)
		}

		s.mu.Lock()
		delete(s.jobs, id)
		newOrder := make([]string, 0, len(s.order))
		for _, oid := range s.order {
			if oid != id {
				newOrder = append(newOrder, oid)
			}
		}
		s.order = newOrder
		s.mu.Unlock()

		writeJSONResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		methodNotAllowed(w)
	}
}

func (s *auditUIServer) handleReports(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/reports/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	job := s.job(parts[0])
	if job == nil {
		http.NotFound(w, r)
		return
	}
	snapshot := job.snapshot()
	if snapshot.OutputDir == "" {
		http.NotFound(w, r)
		return
	}
	rel := "report.html"
	if len(parts) == 2 && parts[1] != "" {
		rel = parts[1]
	}
	clean := filepath.Clean("/" + rel)
	filePath := filepath.Join(snapshot.OutputDir, strings.TrimPrefix(clean, "/"))
	http.ServeFile(w, r, filePath)
}

func (s *auditUIServer) handleRemediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.requireToken(w, r) {
		return
	}
	defer r.Body.Close()
	var req struct {
		Action string `json:"action"` // "delete", "disable", "fix"
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	home := platform.HomeDir()
	projectRoot := ""
	s.mu.Lock()
	for _, job := range s.jobs {
		if job.config.ProjectRoot != "" {
			projectRoot = job.config.ProjectRoot
			break
		}
	}
	s.mu.Unlock()

	var err error
	switch req.Action {
	case "delete":
		err = safety.DeletePath(req.Path, home, projectRoot)
	case "disable":
		err = safety.DisablePath(req.Path, home, projectRoot)
	case "fix":
		err = safety.FixAISkill(req.Path, home, projectRoot)
	default:
		http.Error(w, "unknown action: "+req.Action, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]string{"status": "success"})
}

func (s *auditUIServer) startAudit(req auditUIRequest) auditUIJobSnapshot {
	now := time.Now()
	id := now.UTC().Format("20060102-150405") + "-" + randomHex(4)
	cfg := s.base
	cfg.Version = s.base.Version
	cfg.StartedAt = now
	cfg.WantText = req.WantText
	cfg.WantJSON = req.WantJSON
	cfg.WantHTML = req.WantHTML
	if !cfg.WantText && !cfg.WantJSON && !cfg.WantHTML {
		cfg.WantJSON = true
		cfg.WantHTML = true
	}
	cfg.Deep = req.Deep
	cfg.AIAudit = true
	if req.AIAudit != nil {
		cfg.AIAudit = *req.AIAudit
	}
	cfg.CleanDryRun = req.CleanDryRun
	cfg.CleanConfirm = false
	cfg.NoSudo = req.NoSudo
	cfg.ProjectRoot = strings.TrimSpace(req.ProjectRoot)
	cfg.MaxFileSizeMB = req.MaxFileSizeMB
	cfg.Serve = false
	if strings.TrimSpace(req.OutputDir) != "" {
		cfg.OutputDir = strings.TrimSpace(req.OutputDir)
	} else {
		home := platform.HomeDir()
		if home == "" {
			home = "."
		}
		cfg.OutputDir = filepath.Join(home, "Desktop", fmt.Sprintf("macos-audit-%s-ui-%s", now.Format("20060102-150405"), id[len(id)-8:]))
	}

	jobCtx, cancel := context.WithCancel(s.ctx)
	configSnapshot := auditUIConfigSnapshot{
		WantText:      cfg.WantText,
		WantJSON:      cfg.WantJSON,
		WantHTML:      cfg.WantHTML,
		Deep:          cfg.Deep,
		AIAudit:       cfg.AIAudit,
		CleanDryRun:   cfg.CleanDryRun,
		NoSudo:        cfg.NoSudo,
		OutputDir:     cfg.OutputDir,
		ProjectRoot:   cfg.ProjectRoot,
		MaxFileSizeMB: cfg.MaxFileSizeMB,
	}
	job := &auditUIJob{
		cancel:    cancel,
		id:        id,
		status:    "queued",
		config:    configSnapshot,
		outputDir: cfg.OutputDir,
		createdAt: now,
	}
	s.mu.Lock()
	s.jobs[id] = job
	s.order = append([]string{id}, s.order...)
	s.mu.Unlock()

	go s.runAuditJob(jobCtx, job, cfg)
	return job.snapshot()
}

func (s *auditUIServer) runAuditJob(ctx context.Context, job *auditUIJob, cfg Config) {
	job.markRunning(time.Now())
	report, err := Run(ctx, cfg, RunOptions{
		Stdin:    strings.NewReader(""),
		Stdout:   s.stdout,
		Stderr:   s.stderr,
		Progress: job.appendEvent,
	})
	job.finish(report, err)
}

func (s *auditUIServer) listJobs() []auditUIJobSnapshot {
	s.mu.Lock()
	ids := append([]string(nil), s.order...)
	s.mu.Unlock()
	jobs := make([]auditUIJobSnapshot, 0, len(ids))
	for _, id := range ids {
		if job := s.job(id); job != nil {
			jobs = append(jobs, job.snapshot())
		}
	}
	return jobs
}

func (s *auditUIServer) job(id string) *auditUIJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

func (s *auditUIServer) requireToken(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Audit-Token") != s.token {
		http.Error(w, "invalid UI token", http.StatusForbidden)
		return false
	}
	return true
}

func (s *auditUIServer) cancelRunning() {
	s.mu.Lock()
	jobs := make([]*auditUIJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.mu.Unlock()
	for _, job := range jobs {
		job.requestCancel()
	}
}

func (j *auditUIJob) markRunning(startedAt time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status = "running"
	j.startedAt = startedAt
}

func (j *auditUIJob) requestCancel() {
	j.mu.Lock()
	if j.status == "running" || j.status == "queued" {
		j.status = "canceling"
		if j.cancel != nil {
			j.cancel()
		}
	}
	j.mu.Unlock()
}

func (j *auditUIJob) appendEvent(event audit.ProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, event)
	if len(j.events) > 200 {
		j.events = append([]audit.ProgressEvent(nil), j.events[len(j.events)-200:]...)
	}
}

func (j *auditUIJob) finish(report audit.Report, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.summary = report.Summary
	j.outputDir = report.Metadata.OutputDir
	if j.outputDir == "" {
		j.outputDir = j.config.OutputDir
	}
	j.config.OutputDir = j.outputDir
	j.finishedAt = time.Now()
	j.cancel = nil
	switch {
	case err == nil:
		j.status = "completed"
		if j.config.WantHTML {
			j.reportURL = "/reports/" + j.id + "/report.html"
		}
	case errors.Is(err, context.Canceled):
		j.status = "canceled"
		j.err = err.Error()
	default:
		j.status = "failed"
		j.err = err.Error()
	}
}

func (j *auditUIJob) snapshot() auditUIJobSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	events := append([]audit.ProgressEvent(nil), j.events...)
	return auditUIJobSnapshot{
		ID:         j.id,
		Status:     j.status,
		Config:     j.config,
		OutputDir:  j.outputDir,
		ReportURL:  j.reportURL,
		Error:      j.err,
		CreatedAt:  j.createdAt,
		StartedAt:  j.startedAt,
		FinishedAt: j.finishedAt,
		Summary:    j.summary,
		Events:     events,
	}
}

func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, POST, DELETE")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func safeDeleteOutputDir(outputDir string) {
	if outputDir == "" {
		return
	}
	files := []string{"report.txt", "report.json", "report.html"}
	for _, f := range files {
		_ = os.Remove(filepath.Join(outputDir, f))
	}
	_ = os.Remove(outputDir)
}
