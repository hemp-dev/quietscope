package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func TestWriteJSONSerializesManageableArtifacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	want := audit.Report{
		Metadata: audit.Metadata{ToolName: "quietscope", Version: "test"},
		ManageableArtifacts: []audit.ManageableArtifact{{
			ID:       "artifact-1",
			Path:     "/tmp/project/AGENTS.md",
			Tool:     "Codex",
			Kind:     "instruction",
			Scope:    "project",
			Risk:     "high",
			LiveOnly: false,
			SafeActions: []audit.ActionAvailability{{
				Action:          audit.ArtifactActionEdit,
				Available:       true,
				RequiresPreview: true,
				RequiresBackup:  true,
			}, {
				Action:         audit.ArtifactActionDelete,
				Available:      false,
				DisabledReason: "manual review required",
			}},
		}},
	}

	if err := WriteJSON(path, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var got audit.Report
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("report should round-trip as audit.Report: %v", err)
	}
	if len(got.ManageableArtifacts) != 1 {
		t.Fatalf("expected one manageable artifact, got %d", len(got.ManageableArtifacts))
	}
	artifact := got.ManageableArtifacts[0]
	if artifact.ID != "artifact-1" || artifact.SafeActions[0].Action != audit.ArtifactActionEdit {
		t.Fatalf("unexpected manageable artifact payload: %#v", artifact)
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["manageable_artifacts"]; !ok {
		t.Fatalf("manageable_artifacts field missing from report JSON: %s", string(body))
	}
}
