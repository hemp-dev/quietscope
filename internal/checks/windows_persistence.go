package checks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectauthors/quietscope/internal/audit"
	"github.com/projectauthors/quietscope/internal/platform"
)

func windowsPersistenceFindings(cfg audit.RuntimeConfig) []audit.Finding {
	var findings []audit.Finding
	findings = append(findings, checkWindowsStartupFolders()...)
	findings = append(findings, checkWindowsRegistryRunKeys()...)
	findings = append(findings, checkWindowsPowerShellProfiles(cfg.HomeDir)...)
	return findings
}

func checkWindowsStartupFolders() []audit.Finding {
	var findings []audit.Finding

	// 1. User Startup folder
	userStartup := ""
	appData := os.Getenv("APPDATA")
	if appData != "" {
		userStartup = filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	}

	// 2. System/Common Startup folder
	commonStartup := ""
	programData := os.Getenv("ProgramData")
	if programData != "" {
		commonStartup = filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	} else {
		commonStartup = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
	}

	folders := []struct {
		id    string
		path  string
		title string
	}{
		{"windows-startup-user", userStartup, "User Startup folder folder"},
		{"windows-startup-common", commonStartup, "System common Startup folder folder"},
	}

	for _, folder := range folders {
		if folder.path == "" {
			continue
		}
		entries, err := os.ReadDir(folder.path)
		if err != nil {
			if os.IsNotExist(err) {
				findings = append(findings, newFinding(folder.id, audit.CategoryPersistence, folder.title, audit.StatusPass, audit.SeverityInfo, "Startup folder does not exist; no persistent files detected.", "No action needed.", ""))
				continue
			}
			findings = append(findings, newFinding(folder.id, audit.CategoryPersistence, folder.title, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Review folder contents manually.", ""))
			continue
		}

		if len(entries) == 0 {
			findings = append(findings, newFinding(folder.id, audit.CategoryPersistence, folder.title, audit.StatusPass, audit.SeverityInfo, "Startup folder is empty; no persistent items detected.", "No action needed.", ""))
			continue
		}

		var files []string
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			files = append(files, entry.Name())
		}

		if len(files) == 0 {
			findings = append(findings, newFinding(folder.id, audit.CategoryPersistence, folder.title, audit.StatusPass, audit.SeverityInfo, "Startup folder contains no executable/shortcut files.", "No action needed.", ""))
			continue
		}

		evidence := fmt.Sprintf("Found startup items: %s inside %s", strings.Join(files, ", "), folder.path)
		findings = append(findings, newFinding(folder.id, audit.CategoryPersistence, folder.title, audit.StatusWarn, audit.SeverityLow, evidence, "Review startup shortcuts and programs manually to ensure they are legitimate.", ""))
	}

	return findings
}

func checkWindowsRegistryRunKeys() []audit.Finding {
	var findings []audit.Finding

	keys := []struct {
		id   string
		path string
	}{
		{"windows-run-hkcu", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
		{"windows-run-hklm", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`},
	}

	runner := platform.NewRunner(true)
	ctx := context.Background()

	for _, key := range keys {
		result := runner.Run(ctx, "reg", "query", key.path)
		if !result.Available {
			findings = append(findings, newFinding(key.id, audit.CategoryPersistence, "Registry Run keys: "+key.path, audit.StatusInfo, audit.SeverityInfo, "reg command unavailable: "+result.Error, "Verify startup registry settings manually.", ""))
			continue
		}
		if result.ExitCode != 0 {
			// Sometime key might not exist which is fine
			findings = append(findings, newFinding(key.id, audit.CategoryPersistence, "Registry Run keys: "+key.path, audit.StatusPass, audit.SeverityInfo, "Registry run key does not exist or has no entries.", "No action needed.", "reg query "+key.path))
			continue
		}

		output := result.Output
		lines := strings.Split(output, "\n")
		var entries []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "HKEY_") {
				continue
			}
			// Parse key entries (format: ValueName REG_SZ ValueData)
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				entries = append(entries, parts[0])
			}
		}

		if len(entries) == 0 {
			findings = append(findings, newFinding(key.id, audit.CategoryPersistence, "Registry Run keys: "+key.path, audit.StatusPass, audit.SeverityInfo, "Registry key has no startup entries.", "No action needed.", "reg query "+key.path))
			continue
		}

		evidence := fmt.Sprintf("Found registry startup entries: %s under %s. Output: %s", strings.Join(entries, ", "), key.path, safetySnippet(output, 200))
		findings = append(findings, newFinding(key.id, audit.CategoryPersistence, "Registry Run keys: "+key.path, audit.StatusWarn, audit.SeverityLow, evidence, "Review registry auto-run paths manually to verify legitimacy.", "reg query "+key.path))
	}

	return findings
}

func checkWindowsPowerShellProfiles(home string) []audit.Finding {
	var findings []audit.Finding

	profiles := []struct {
		id   string
		path string
		name string
	}{
		{
			"windows-ps-profile-legacy",
			filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			"Legacy PowerShell profile",
		},
		{
			"windows-ps-profile-modern",
			filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			"Modern PowerShell profile",
		},
	}

	for _, profile := range profiles {
		meta, err := platform.StatMeta(profile.path)
		if err != nil {
			if os.IsNotExist(err) {
				findings = append(findings, newFinding(profile.id, audit.CategoryPersistence, profile.name, audit.StatusPass, audit.SeverityInfo, "PowerShell profile script does not exist.", "No action needed.", ""))
				continue
			}
			findings = append(findings, newFinding(profile.id, audit.CategoryPersistence, profile.name, audit.StatusInfo, audit.SeverityInfo, err.Error(), "Verify profile file existence manually.", ""))
			continue
		}

		evidence := fmt.Sprintf("Profile exists at: %s size=%d mtime=%s", profile.path, meta.Size, meta.ModTime.Format("2006-01-02"))
		findings = append(findings, newFinding(profile.id, audit.CategoryPersistence, profile.name, audit.StatusWarn, audit.SeverityLow, evidence, "Open the PowerShell profile script and review its contents for persistence or unauthorized startup actions.", ""))
	}

	return findings
}
