package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func TestWriteHTMLEmbedsAuditDataAsJSONObject(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	want := audit.Report{
		Metadata: audit.Metadata{ToolName: "quietscope", Version: "test"},
		Summary:  audit.Summary{TotalFindings: 1, RiskLevel: "Low"},
		Findings: []audit.Finding{{
			ID:       "demo",
			Category: audit.CategorySecurity,
			Title:    "Demo finding",
			Status:   audit.StatusWarn,
			Severity: audit.SeverityLow,
		}},
	}
	if err := WriteHTML(path, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	payload := extractAuditDataPayload(t, string(body))
	if strings.HasPrefix(strings.TrimSpace(payload), `"`) {
		t.Fatalf("audit-data payload was embedded as a JSON string literal: %.40q", payload)
	}
	var got audit.Report
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("audit-data payload should unmarshal as an audit.Report: %v", err)
	}
	if got.Summary.TotalFindings != want.Summary.TotalFindings || len(got.Findings) != len(want.Findings) {
		t.Fatalf("unexpected embedded report data: summary=%#v findings=%d", got.Summary, len(got.Findings))
	}
}

func TestWriteHTMLRendersAIControlCenterStaticActions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	want := audit.Report{
		Metadata: audit.Metadata{ToolName: "quietscope", Version: "test"},
		ManageableArtifacts: []audit.ManageableArtifact{{
			ID:       "agent-md",
			Path:     filepath.Join(dir, "AGENTS.md"),
			Tool:     "Codex",
			Kind:     "instruction",
			Scope:    "project",
			Risk:     "high",
			LiveOnly: true,
			SafeActions: []audit.ActionAvailability{{
				Action:          audit.ArtifactActionEdit,
				Available:       true,
				RequiresPreview: true,
				RequiresBackup:  true,
			}},
		}},
	}
	if err := WriteHTML(path, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, needle := range []string{
		"AI Control Center",
		"Disabled in static report",
		"/api/actions/preview",
		"Backup will be created",
		"control-skills-body",
	} {
		if !strings.Contains(html, needle) {
			t.Fatalf("expected HTML to contain %q", needle)
		}
	}
}

func extractAuditDataPayload(t *testing.T, html string) string {
	t.Helper()
	startToken := `<script type="application/json" id="audit-data">`
	start := strings.Index(html, startToken)
	if start < 0 {
		t.Fatal("audit-data script tag not found")
	}
	start += len(startToken)
	end := strings.Index(html[start:], "</script>")
	if end < 0 {
		t.Fatal("audit-data script closing tag not found")
	}
	return html[start : start+end]
}
