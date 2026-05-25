package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func TestHandleIndexRendersControlDashboard(t *testing.T) {
	server := &auditUIServer{
		base:  Config{Version: "test"},
		token: "test-token",
		ctx:   context.Background(),
		jobs:  map[string]*auditUIJob{},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	server.handleIndex(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected OK status, got %v: %s", w.Code, w.Body.String())
	}
	for _, needle := range []string{"Local Web Controller", "AI Control Center", "quietscope_ui_token"} {
		if !bytes.Contains(w.Body.Bytes(), []byte(needle)) {
			t.Fatalf("expected dashboard HTML to contain %q", needle)
		}
	}
}

func TestHandleAuditDeleteAndCancel(t *testing.T) {
	tempDir := t.TempDir()

	// Create dummy report files in a mock output directory
	jobOutputDir := filepath.Join(tempDir, "job-output")
	if err := os.MkdirAll(jobOutputDir, 0755); err != nil {
		t.Fatal(err)
	}
	reportTXT := filepath.Join(jobOutputDir, "report.txt")
	reportJSON := filepath.Join(jobOutputDir, "report.json")
	reportHTML := filepath.Join(jobOutputDir, "report.html")

	_ = os.WriteFile(reportTXT, []byte("txt report"), 0644)
	_ = os.WriteFile(reportJSON, []byte("json report"), 0644)
	_ = os.WriteFile(reportHTML, []byte("html report"), 0644)

	// Verify they exist
	if _, err := os.Stat(reportTXT); os.IsNotExist(err) {
		t.Fatal("report.txt should exist before delete")
	}

	server := &auditUIServer{
		token: "test-token",
		jobs:  map[string]*auditUIJob{},
		order: []string{"job1"},
	}

	job := &auditUIJob{
		id:        "job1",
		status:    "completed",
		outputDir: jobOutputDir,
		createdAt: time.Now(),
	}
	server.jobs["job1"] = job

	// 1. Test POST /api/audits/job1/cancel
	reqCancel := httptest.NewRequest(http.MethodPost, "/api/audits/job1/cancel", nil)
	reqCancel.Header.Set("X-Audit-Token", "test-token")
	wCancel := httptest.NewRecorder()
	server.handleAudit(wCancel, reqCancel)

	if wCancel.Code != http.StatusOK {
		t.Errorf("expected OK status for cancel, got %v", wCancel.Code)
	}

	// 2. Test DELETE /api/audits/job1
	reqDelete := httptest.NewRequest(http.MethodDelete, "/api/audits/job1", nil)
	reqDelete.Header.Set("X-Audit-Token", "test-token")
	wDelete := httptest.NewRecorder()
	server.handleAudit(wDelete, reqDelete)

	if wDelete.Code != http.StatusOK {
		t.Errorf("expected OK status for delete, got %v", wDelete.Code)
	}

	// Verify job was removed from server
	if _, ok := server.jobs["job1"]; ok {
		t.Error("job1 should be removed from s.jobs")
	}
	if len(server.order) != 0 {
		t.Error("job1 should be removed from s.order")
	}

	// Verify files were removed from disk
	if _, err := os.Stat(reportTXT); !os.IsNotExist(err) {
		t.Error("report.txt should be deleted")
	}
	if _, err := os.Stat(reportJSON); !os.IsNotExist(err) {
		t.Error("report.json should be deleted")
	}
	if _, err := os.Stat(reportHTML); !os.IsNotExist(err) {
		t.Error("report.html should be deleted")
	}
	// Verify directory itself was removed since it is now empty
	if _, err := os.Stat(jobOutputDir); !os.IsNotExist(err) {
		t.Error("jobOutputDir should be deleted")
	}
}

func TestManagementAPIArtifactsPreviewExecuteRestore(t *testing.T) {
	tempDir := t.TempDir()
	home := filepath.Join(tempDir, "home")
	project := filepath.Join(home, "project")
	artifactPath := filepath.Join(project, "AGENTS.md")
	if err := os.MkdirAll(project, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}

	server := &auditUIServer{
		token: "test-token",
		jobs:  map[string]*auditUIJob{},
		order: []string{"job1"},
	}
	server.jobs["job1"] = &auditUIJob{
		id:        "job1",
		status:    "completed",
		createdAt: time.Now(),
		config:    auditUIConfigSnapshot{ProjectRoot: project},
		report: audit.Report{ManageableArtifacts: []audit.ManageableArtifact{{
			ID:    "agent-md",
			Path:  artifactPath,
			Tool:  "Codex",
			Kind:  "instruction",
			Scope: "project",
			Risk:  "high",
			SafeActions: []audit.ActionAvailability{{
				Action:          audit.ArtifactActionEdit,
				Available:       true,
				RequiresPreview: true,
				RequiresBackup:  true,
			}, {
				Action:          audit.ArtifactActionRestore,
				Available:       true,
				RequiresPreview: true,
				RequiresBackup:  true,
			}},
		}}},
	}

	t.Setenv("HOME", home)
	reqList := httptest.NewRequest(http.MethodGet, "/api/artifacts?job_id=job1", nil)
	wList := httptest.NewRecorder()
	server.handleArtifacts(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected artifacts OK, got %d", wList.Code)
	}
	if !bytes.Contains(wList.Body.Bytes(), []byte("agent-md")) {
		t.Fatalf("expected artifact payload, got %s", wList.Body.String())
	}

	payload := map[string]any{"job_id": "job1", "action": "edit", "path": artifactPath, "content": "new\n"}
	body, _ := json.Marshal(payload)
	reqPreview := httptest.NewRequest(http.MethodPost, "/api/actions/preview", bytes.NewReader(body))
	reqPreview.Header.Set("X-Audit-Token", "test-token")
	wPreview := httptest.NewRecorder()
	server.handleActionPreview(wPreview, reqPreview)
	if wPreview.Code != http.StatusOK {
		t.Fatalf("expected preview OK, got %d: %s", wPreview.Code, wPreview.Body.String())
	}
	if !bytes.Contains(wPreview.Body.Bytes(), []byte("-old")) {
		t.Fatalf("expected diff payload, got %s", wPreview.Body.String())
	}

	reqExecute := httptest.NewRequest(http.MethodPost, "/api/actions/execute", bytes.NewReader(body))
	reqExecute.Header.Set("X-Audit-Token", "test-token")
	wExecute := httptest.NewRecorder()
	server.handleActionExecute(wExecute, reqExecute)
	if wExecute.Code != http.StatusOK {
		t.Fatalf("expected execute OK, got %d: %s", wExecute.Code, wExecute.Body.String())
	}
	var result struct {
		BackupPath string `json:"backup_path"`
	}
	if err := json.Unmarshal(wExecute.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.BackupPath == "" {
		t.Fatal("expected backup path")
	}
	if got, _ := os.ReadFile(artifactPath); string(got) != "new\n" {
		t.Fatalf("expected edited content, got %q", got)
	}

	restorePayload := map[string]any{"job_id": "job1", "action": "restore", "path": artifactPath, "backup_path": result.BackupPath}
	restoreBody, _ := json.Marshal(restorePayload)
	reqRestore := httptest.NewRequest(http.MethodPost, "/api/actions/restore", bytes.NewReader(restoreBody))
	reqRestore.Header.Set("X-Audit-Token", "test-token")
	wRestore := httptest.NewRecorder()
	server.handleActionRestore(wRestore, reqRestore)
	if wRestore.Code != http.StatusOK {
		t.Fatalf("expected restore OK, got %d: %s", wRestore.Code, wRestore.Body.String())
	}
	if got, _ := os.ReadFile(artifactPath); string(got) != "old\n" {
		t.Fatalf("expected restored content, got %q", got)
	}

	blockedPayload := map[string]any{"job_id": "job1", "action": "delete", "path": artifactPath, "artifact_id": "agent-md"}
	blockedBody, _ := json.Marshal(blockedPayload)
	reqBlocked := httptest.NewRequest(http.MethodPost, "/api/actions/execute", bytes.NewReader(blockedBody))
	reqBlocked.Header.Set("X-Audit-Token", "test-token")
	wBlocked := httptest.NewRecorder()
	server.handleActionExecute(wBlocked, reqBlocked)
	if wBlocked.Code != http.StatusBadRequest {
		t.Fatalf("expected blocked action to be rejected, got %d: %s", wBlocked.Code, wBlocked.Body.String())
	}
}
