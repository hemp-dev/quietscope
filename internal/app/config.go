package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
)

const ToolName = "quietscope"

type Config struct {
	Version       string
	WantJSON      bool
	WantHTML      bool
	WantText      bool
	Deep          bool
	AIAudit       bool
	CleanDryRun   bool
	CleanConfirm  bool
	NoSudo        bool
	OutputDir     string
	ProjectRoot   string
	MaxFileSizeMB int
	Serve         bool
	StartedAt     time.Time
}

func (c *Config) Normalize() error {
	if c.StartedAt.IsZero() {
		c.StartedAt = time.Now()
	}
	if c.MaxFileSizeMB <= 0 {
		c.MaxFileSizeMB = 5
	}
	home := platform.HomeDir()
	if c.OutputDir == "" {
		c.OutputDir = DefaultOutputDir(c.StartedAt, home)
	}
	c.OutputDir = platform.ExpandHome(c.OutputDir, home)
	absOutput, err := filepath.Abs(c.OutputDir)
	if err != nil {
		return err
	}
	c.OutputDir = absOutput
	if c.ProjectRoot != "" {
		c.ProjectRoot = platform.ExpandHome(c.ProjectRoot, home)
		absProject, err := filepath.Abs(c.ProjectRoot)
		if err != nil {
			return err
		}
		c.ProjectRoot = absProject
	}
	if !c.WantJSON && !c.WantHTML && !c.WantText {
		c.WantJSON = true
		c.WantText = true
	}
	return nil
}

func DefaultOutputDir(t time.Time, home string) string {
	if home == "" {
		home = "."
	}
	return filepath.Join(home, "Desktop", fmt.Sprintf("quietscope-audit-%s", t.Format("20060102-150405")))
}

func (c Config) RuntimeConfig() audit.RuntimeConfig {
	return audit.RuntimeConfig{
		Version:       c.Version,
		OutputDir:     c.OutputDir,
		ProjectRoot:   c.ProjectRoot,
		Deep:          c.Deep,
		AIAudit:       c.AIAudit,
		NoSudo:        c.NoSudo,
		CleanDryRun:   c.CleanDryRun,
		CleanConfirm:  c.CleanConfirm,
		MaxFileSizeMB: c.MaxFileSizeMB,
		HomeDir:       platform.HomeDir(),
		StartedAt:     c.StartedAt,
	}
}

func ensureOutputDir(path string) error {
	return os.MkdirAll(path, 0o755)
}
