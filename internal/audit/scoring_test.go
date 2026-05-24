package audit

import "testing"

func TestCalculateSummaryCapsScore(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Status: StatusFail},
		{Severity: SeverityCritical, Status: StatusFail},
		{Severity: SeverityCritical, Status: StatusFail},
		{Severity: SeverityCritical, Status: StatusFail},
		{Severity: SeverityCritical, Status: StatusFail},
	}
	summary := CalculateSummary(findings, nil)
	if summary.OverallRiskScore != 100 {
		t.Fatalf("expected capped score 100, got %d", summary.OverallRiskScore)
	}
	if summary.RiskLevel != "Critical" {
		t.Fatalf("expected Critical, got %s", summary.RiskLevel)
	}
}

func TestCalculateSummaryCountsRiskFlags(t *testing.T) {
	findings := []Finding{
		{Category: CategoryAISecurity, Severity: SeverityMedium, Status: StatusWarn},
		{Category: CategorySecrets, Severity: SeverityHigh, Status: StatusFail, DataExposureRisk: true},
		{Severity: SeverityLow, Status: StatusPass},
	}
	candidates := []CleanupCandidate{{SafeToAutoFix: true, EstimatedSizeBytes: 42}}
	summary := CalculateSummary(findings, candidates)
	if summary.AIRiskCount != 1 {
		t.Fatalf("expected 1 AI risk, got %d", summary.AIRiskCount)
	}
	if summary.SecretsExposureCount != 1 {
		t.Fatalf("expected 1 secrets exposure, got %d", summary.SecretsExposureCount)
	}
	if summary.CleanupReclaimableBytes != 42 {
		t.Fatalf("expected cleanup bytes 42, got %d", summary.CleanupReclaimableBytes)
	}
}
