package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxCommandOutputBytes = 256 * 1024

type CommandResult struct {
	Command   string
	Args      []string
	Output    string
	Error     string
	ExitCode  int
	Available bool
	TimedOut  bool
	Duration  time.Duration
}

type Runner struct {
	NoSudo  bool
	Timeout time.Duration
}

func NewRunner(noSudo bool) *Runner {
	return &Runner{NoSudo: noSudo, Timeout: 20 * time.Second}
}

func (r *Runner) Run(ctx context.Context, name string, args ...string) CommandResult {
	start := time.Now()
	result := CommandResult{
		Command:   name,
		Args:      append([]string(nil), args...),
		ExitCode:  -1,
		Available: true,
	}
	if name == "" {
		result.Available = false
		result.Error = "empty command"
		return result
	}
	if name == "sudo" && r.NoSudo {
		result.Available = false
		result.Error = "sudo disabled by --no-sudo"
		return result
	}
	if err := validateCommandName(name); err != nil {
		result.Available = false
		result.Error = err.Error()
		return result
	}
	if err := commandExists(name); err != nil {
		result.Available = false
		result.Error = err.Error()
		return result
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{Buffer: &stdout, Limit: maxCommandOutputBytes}
	cmd.Stderr = &limitedBuffer{Buffer: &stderr, Limit: maxCommandOutputBytes / 2}

	err := cmd.Run()
	result.Duration = time.Since(start)
	if commandCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.Error = "command timed out"
	}
	result.Output = strings.TrimSpace(stdout.String())
	if stderr.Len() > 0 {
		result.Error = strings.TrimSpace(stderr.String())
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			if result.Error == "" {
				result.Error = err.Error()
			}
		} else if result.Error == "" {
			result.Error = err.Error()
		}
	} else {
		result.ExitCode = 0
	}
	return result
}

func FormatCommand(name string, args ...string) string {
	parts := append([]string{name}, args...)
	for i, p := range parts {
		parts[i] = quoteArg(p)
	}
	return strings.Join(parts, " ")
}

func quoteArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.ContainsAny(arg, " \t\n\"'`$\\") {
		return "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
	}
	return arg
}

func validateCommandName(name string) error {
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid command name")
	}
	if strings.Contains(name, "\n") || strings.Contains(name, "\r") {
		return fmt.Errorf("invalid command name")
	}
	if strings.Contains(name, string(os.PathSeparator)) {
		clean := filepath.Clean(name)
		if clean != name {
			return fmt.Errorf("unclean command path")
		}
	}
	return nil
}

func commandExists(name string) error {
	if strings.Contains(name, string(os.PathSeparator)) {
		info, err := os.Stat(name)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("command path is a directory")
		}
		return nil
	}
	_, err := exec.LookPath(name)
	return err
}

type limitedBuffer struct {
	*bytes.Buffer
	Limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.Buffer.Len() >= b.Limit {
		return original, nil
	}
	remaining := b.Limit - b.Buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
	}
	_, err := b.Buffer.Write(p)
	return original, err
}
