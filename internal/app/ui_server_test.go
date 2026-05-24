package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
