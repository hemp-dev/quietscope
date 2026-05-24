package audit

type Summary struct {
	OverallRiskScore        int    `json:"overall_risk_score"`
	RiskLevel               string `json:"risk_level"`
	TotalFindings           int    `json:"total_findings"`
	PassCount               int    `json:"pass_count"`
	WarnCount               int    `json:"warn_count"`
	FailCount               int    `json:"fail_count"`
	InfoCount               int    `json:"info_count"`
	SkippedCount            int    `json:"skipped_count"`
	CriticalCount           int    `json:"critical_count"`
	HighCount               int    `json:"high_count"`
	MediumCount             int    `json:"medium_count"`
	LowCount                int    `json:"low_count"`
	CleanupReclaimableBytes int64  `json:"cleanup_reclaimable_bytes"`
	AIRiskCount             int    `json:"ai_risk_count"`
	SecretsExposureCount    int    `json:"secrets_exposure_count"`
}

func CalculateSummary(findings []Finding, cleanup []CleanupCandidate) Summary {
	var s Summary
	s.TotalFindings = len(findings)
	for _, f := range findings {
		switch f.Status {
		case StatusPass:
			s.PassCount++
		case StatusWarn:
			s.WarnCount++
		case StatusFail:
			s.FailCount++
		case StatusInfo:
			s.InfoCount++
		case StatusSkipped:
			s.SkippedCount++
		}

		switch f.Severity {
		case SeverityCritical:
			s.CriticalCount++
			s.OverallRiskScore += 25
		case SeverityHigh:
			s.HighCount++
			s.OverallRiskScore += 15
		case SeverityMedium:
			s.MediumCount++
			s.OverallRiskScore += 7
		case SeverityLow:
			s.LowCount++
			s.OverallRiskScore += 2
		}

		if f.Category == CategoryAISecurity || f.CommandExecutionRisk || f.NetworkExfiltrationRisk {
			s.AIRiskCount++
		}
		if f.Category == CategorySecrets || f.DataExposureRisk {
			s.SecretsExposureCount++
		}
	}

	for _, c := range cleanup {
		if c.SafeToAutoFix && c.EstimatedSizeBytes > 0 {
			s.CleanupReclaimableBytes += c.EstimatedSizeBytes
		}
	}

	if s.OverallRiskScore > 100 {
		s.OverallRiskScore = 100
	}
	s.RiskLevel = RiskLevel(s.OverallRiskScore)
	return s
}

func RiskLevel(score int) string {
	switch {
	case score <= 10:
		return "Low"
	case score <= 35:
		return "Moderate"
	case score <= 70:
		return "High"
	default:
		return "Critical"
	}
}
