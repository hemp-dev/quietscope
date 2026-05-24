package audit

import "time"

type ProgressEventType string

const (
	ProgressStarted        ProgressEventType = "started"
	ProgressCheckStarted   ProgressEventType = "check_started"
	ProgressCheckCompleted ProgressEventType = "check_completed"
	ProgressReportWriting  ProgressEventType = "report_writing"
	ProgressReportWritten  ProgressEventType = "report_written"
	ProgressCleanup        ProgressEventType = "cleanup"
	ProgressServer         ProgressEventType = "server"
	ProgressCanceled       ProgressEventType = "canceled"
	ProgressFinished       ProgressEventType = "finished"
)

type ProgressEvent struct {
	Type           ProgressEventType `json:"type"`
	CheckName      string            `json:"check_name,omitempty"`
	CheckIndex     int               `json:"check_index,omitempty"`
	Completed      int               `json:"completed"`
	Total          int               `json:"total"`
	Message        string            `json:"message"`
	Error          string            `json:"error,omitempty"`
	StartedAt      time.Time         `json:"started_at,omitempty"`
	FinishedAt     time.Time         `json:"finished_at,omitempty"`
	DurationMillis int64             `json:"duration_ms,omitempty"`
}

type ProgressObserver func(ProgressEvent)
