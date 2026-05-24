package app

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
)

type terminalProgressPrinter struct {
	w io.Writer
}

func combinedProgressObserver(w io.Writer, external audit.ProgressObserver, quiet bool) audit.ProgressObserver {
	printer := &terminalProgressPrinter{w: w}
	return func(event audit.ProgressEvent) {
		if external != nil {
			external(event)
		}
		if quiet || w == nil {
			return
		}
		printer.Print(event)
	}
}

func (p *terminalProgressPrinter) Print(event audit.ProgressEvent) {
	switch event.Type {
	case audit.ProgressStarted:
		fmt.Fprintf(p.w, "[audit] %s starting %d checks\n", progressBar(0, event.Total), event.Total)
	case audit.ProgressCheckStarted:
		fmt.Fprintf(p.w, "[audit] %s %02d/%02d %s ...\n", progressBar(event.Completed, event.Total), event.CheckIndex+1, event.Total, event.CheckName)
	case audit.ProgressCheckCompleted:
		status := "ok"
		if event.Error != "" {
			status = "warn"
		}
		fmt.Fprintf(p.w, "[audit] %s %02d/%02d %s %s (%s)\n", progressBar(event.Completed, event.Total), event.Completed, event.Total, event.CheckName, status, humanDuration(event.DurationMillis))
	case audit.ProgressReportWriting, audit.ProgressReportWritten, audit.ProgressCleanup, audit.ProgressServer:
		fmt.Fprintf(p.w, "[audit] %s\n", event.Message)
	case audit.ProgressCanceled:
		fmt.Fprintf(p.w, "[audit] %s canceled: %s\n", progressBar(event.Completed, event.Total), event.Message)
	case audit.ProgressFinished:
		fmt.Fprintf(p.w, "[audit] %s checks finished in %s\n", progressBar(event.Completed, event.Total), humanDuration(event.DurationMillis))
	}
}

func progressBar(completed, total int) string {
	const width = 18
	if total <= 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}
	if completed < 0 {
		completed = 0
	}
	if completed > total {
		completed = total
	}
	filled := completed * width / total
	return "[" + strings.Repeat("=", filled) + strings.Repeat("-", width-filled) + "]"
}

func humanDuration(ms int64) string {
	if ms <= 0 {
		return "<1ms"
	}
	d := time.Duration(ms) * time.Millisecond
	if d < time.Second {
		return d.String()
	}
	return d.Round(100 * time.Millisecond).String()
}
