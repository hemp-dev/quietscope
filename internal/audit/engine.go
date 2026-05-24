package audit

import (
	"context"
	"fmt"
	"time"
)

type NamedCheck struct {
	Name string
	Run  func(context.Context) (CheckResult, error)
}

type Engine struct {
	checks []NamedCheck
}

func NewEngine(checks ...NamedCheck) *Engine {
	return &Engine{checks: checks}
}

func (e *Engine) Run(ctx context.Context) CheckResult {
	return e.RunWithProgress(ctx, nil)
}

func (e *Engine) RunWithProgress(ctx context.Context, observe ProgressObserver) CheckResult {
	var combined CheckResult
	total := len(e.checks)
	startedAt := time.Now()
	emit(observe, ProgressEvent{
		Type:      ProgressStarted,
		Total:     total,
		Message:   fmt.Sprintf("Starting %d audit check(s).", total),
		StartedAt: startedAt,
	})
	completedChecks := 0
	canceled := false
	for i, check := range e.checks {
		if err := ctx.Err(); err != nil {
			canceled = true
			emit(observe, ProgressEvent{
				Type:      ProgressCanceled,
				Completed: completedChecks,
				Total:     total,
				Message:   "Audit canceled before the next check.",
				Error:     err.Error(),
			})
			break
		}
		checkStartedAt := time.Now()
		emit(observe, ProgressEvent{
			Type:       ProgressCheckStarted,
			CheckName:  check.Name,
			CheckIndex: i,
			Completed:  i,
			Total:      total,
			Message:    "Running " + check.Name + ".",
			StartedAt:  checkStartedAt,
		})
		result, err := check.Run(ctx)
		combined.Merge(result)
		if err != nil {
			combined.Findings = append(combined.Findings, Finding{
				ID:             "check-error-" + check.Name,
				Category:       CategoryReporting,
				Title:          "Audit check failed gracefully: " + check.Name,
				Status:         StatusInfo,
				Severity:       SeverityInfo,
				Evidence:       fmt.Sprintf("The check returned an error and the audit continued: %v", err),
				Recommendation: "Review the local environment and rerun the audit if this check is important.",
			})
		}
		completed := time.Now()
		event := ProgressEvent{
			Type:           ProgressCheckCompleted,
			CheckName:      check.Name,
			CheckIndex:     i,
			Completed:      i + 1,
			Total:          total,
			Message:        "Completed " + check.Name + ".",
			StartedAt:      checkStartedAt,
			FinishedAt:     completed,
			DurationMillis: completed.Sub(checkStartedAt).Milliseconds(),
		}
		if err != nil {
			event.Error = err.Error()
			event.Message = "Completed " + check.Name + " with a recoverable error."
		}
		completedChecks = i + 1
		emit(observe, event)
		if err := ctx.Err(); err != nil {
			canceled = true
			emit(observe, ProgressEvent{
				Type:      ProgressCanceled,
				Completed: completedChecks,
				Total:     total,
				Message:   "Audit canceled after the last completed check.",
				Error:     err.Error(),
			})
			break
		}
	}
	if canceled {
		return combined
	}
	finishedAt := time.Now()
	emit(observe, ProgressEvent{
		Type:           ProgressFinished,
		Completed:      completedChecks,
		Total:          total,
		Message:        "Audit checks finished.",
		StartedAt:      startedAt,
		FinishedAt:     finishedAt,
		DurationMillis: finishedAt.Sub(startedAt).Milliseconds(),
	})
	return combined
}

func emit(observe ProgressObserver, event ProgressEvent) {
	if observe != nil {
		observe(event)
	}
}
