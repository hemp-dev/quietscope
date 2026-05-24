# Release Notes

## v0.5.1

UI layout polish and release asset cleanup for the desktop/report refresh.

### Fixed

- Standalone HTML reports no longer overflow horizontally at desktop widths when the sidebar is fixed.
- Findings tables now stay constrained to the report content area, with long content wrapping inside table cells.
- The report risk gauge initializes on first render instead of showing an empty placeholder state.
- The README logo asset is now a valid PNG file matching its `.png` extension.

### Changed

- Version bumped to `v0.5.1`.

## v0.5.0

Desktop UI & Report overhaul with full-screen Audit Findings Explorer.

### Added

- **Full-screen Audit Findings Explorer**: dual-pane interactive workstation with scrollable finding cards (left) and full remediation details panel (right) including evidence, detection commands, auto-fix status, reclaimable size, and copy-to-clipboard actions.
- **Horizontal Metrics Summary Bar**: compact inline bar displaying Risk Score, Findings count, AI Risks, Secrets exposure, Duration, and "Open In Browser" action — visible at a glance in the findings view.
- **Active Scan Pulse Loaders**: animated pulsing skeleton indicators for Findings, AI Risks, and Secrets metrics while audits are running or queued, preventing misleading zero values.
- **Analyzing Gauge State**: circular risk gauge enters a pulsing "Analyzing..." mode with a blue ring during active scans instead of prematurely showing "Secure" with score 0.
- **XSS Protection**: all finding data is escaped via `escapeHTML()` before rendering in innerHTML templates.
- **Standalone HTML Report redesign**: interactive glassmorphic safety dashboard with animated SVG risk gauge, privacy masking toggle, remediation simulator, coordinated multi-faceted filters, and print-optimized PDF export styling.

### Fixed

- **Duration calculation bug**: Go's zero-value timestamps (`0001-01-01T00:00:00Z`) no longer produce `-63915244578.8s` — safely detected and rendered as `"-"` for queued jobs or live count-up for running jobs.
- **Metrics display during active scans**: Findings, AI Risks, and Secrets no longer show misleading `0` while scan is in progress.

### Changed

- Version bumped to `v0.5.0`.
- Desktop UI upgraded from basic table-based findings viewer to professional dual-pane security analysis workstation.
- Wails desktop header badge updated to v0.5.0.
- SECURITY.md supported versions updated (v0.5.x active, v0.4.x maintenance).

### Known limitations

- Wails UI remains in developer preview and requires Wails CLI framework installation to compile.
- Cleanup operations remain CLI-only for safety.

## v0.4.0

Wails Desktop Preview and Basic Windows Audit release.

### Added

- Wails desktop frontend scaffolding under `desktop/` providing a native window wrapper around Quietscope audit engine.
- Real-time progress and logs streaming from Go core to Wails UI via Wails Events bus.
- Basic Windows audit module with persistence checks for User/System Startup folders, registry Run keys, and User PowerShell profiles.
- Basic Windows security checks including SSH file permissions, Windows Defender status, Firewall profiles status, and User Account Control (UAC) EnableLUA status.
- Integration tests and mock fixtures for Windows checks validation.

### Changed

- Version bumped to `v0.4.0`.
- README updated to reflect Wails developer preview availability and new basic Windows support levels.
- CLI main registry gates now load Windows audit modules on Windows hosts.

### Known limitations

- Wails UI is in active developer preview and requires Wails CLI framework installation to compile.
- UI does not support destructive cache cleanup operations (kept CLI-only for safety).
- Windows checks are read-only and metadata-first; they do not cover active malware removal or deep registry hardening.

## v0.3.0

Initial Linux audit module release.

### Added

- Linux check registry that enables `linux_persistence` and `linux_security` groups on Linux only.
- Linux persistence metadata checks for systemd system/user units, cron paths, desktop autostart entries, and Linux shell startup files.
- Safe sampled parsing of systemd, cron, and desktop autostart startup lines with redaction and command/network risk flags.
- Linux security basics for user/system SSH metadata, host key permissions, firewall status, update metadata timestamps, and sudoers metadata.
- Linux smoke test that builds the CLI and generates TXT/JSON/HTML reports on Ubuntu.
- Fixture-driven unit tests for Linux systemd/cron/autostart metadata, firewall parsing, unavailable firewall status, SSH/update/sudoers metadata, and path handling.

### Changed

- Version bumped to `v0.3.0`.
- README platform support now marks Linux as an initial audit platform instead of soft-supported only.
- CI now includes a Linux smoke job alongside macOS smoke and cross-compile validation.

### Known limitations

- Linux checks are conservative and metadata-first. They do not claim full distro hardening coverage.
- Firewall ruleset interpretation is best-effort and should be manually verified.
- Package update checks do not run network package-manager commands.
- Windows remains soft-supported with full Windows audit work planned later.

## v0.2.0

Soft cross-platform CLI release.

### Added

- Platform capability helpers for Darwin, Linux, Windows, macOS security settings, launchd persistence, Linux systemd, Windows registry, and common filesystem checks.
- `SKIPPED` finding status so unsupported OS-specific checks are visible without being treated as failures.
- Linux and Windows safe metadata roots for common AI/MCP config discovery.
- Platform-specific file ownership handling so Windows builds can represent unavailable UID/GID values as `0`.
- CI matrix for Ubuntu, macOS, and Windows, plus cross-compile validation for release targets.
- Tag-triggered release workflow that builds Darwin arm64/amd64, Linux amd64, Windows amd64, and `SHA256SUMS`.
- Platform support table and build examples for macOS, Linux, and Windows.

### Changed

- Version bumped to `v0.2.0`.
- macOS-only security, update, launchd persistence, launchd permission, Time Machine, and macOS system metadata checks are gated by platform support.
- Linux and Windows runs keep common checks and reports available while explaining unsupported macOS checks in plain language.
- Report summaries include a skipped count.

### Known limitations

- macOS remains the only fully supported audit platform in v0.2.
- Linux and Windows are soft-supported: common checks and report generation are best-effort, not full platform audits.
- Linux systemd/firewall/package-manager audit checks are planned for v0.3.
- Windows Defender/Firewall/startup/registry audit checks are planned after the Linux module work begins.
- Cross-compilation may require a Go toolchain installation that includes the target standard libraries.

## v0.1.1

Terminal observability and local UI control release.

### Added

- Short terminal process log with a compact progress bar for audit checks, report writing, cleanup dry-runs, and local server startup.
- `--ui` mode for a local 127.0.0.1 audit control UI.
- UI audit management: configure report outputs, deep checks, AI audit checks, no-sudo mode, cleanup dry-run, output directory, project root, and max scan size.
- UI run history with live progress events, summary metrics, cancel action, and generated report links.
- Same-origin UI token for local mutating API requests.
- README documentation for CLI, self-contained report UI, and audit control UI modes.

### Changed

- Version bumped to `v0.1.1`.
- The local UI notice now reflects that the controller can launch local audits but still never uploads report or file contents.

## v0.1.0

Initial open-source-ready release.

### Added

- Go-first single-binary CLI.
- Defensive local macOS audit checks for system info, security settings, persistence, permissions, storage, cleanup candidates, AI tooling, MCP configs, local LLM listeners, prompt-injection artifacts, and secret metadata.
- AI Skills & Context Inventory for Claude, Codex, Cursor, Copilot, VS Code, Continue, Cline, Roo, Windsurf, Aider, Open Interpreter, and generic AI-agent artifacts.
- AI-related directory disk usage inventory with context impact scoring and manual-review recommendations for model directories.
- Extended AI Tool Catalog covering AI IDEs, coding agents, CLI agents, MCP clients/servers, local LLM runtimes, desktop wrappers, AI security scanners, Hermes Agent, OpenCode/opencode, and hosted/cloud agent local artifacts.
- Chinese AI Models & Providers inventory for Qwen, DeepSeek, Kimi/Moonshot, GLM/Z.ai/Zhipu, MiniMax, Doubao/ByteDance, ERNIE/Baidu, Baichuan, Yi/01.AI, InternLM, Hunyuan/Tencent, StepFun, SenseNova, and related local caches/provider configs.
- TXT and JSON reports by default.
- Optional self-contained HTML UI with dashboard, filters, privacy mode, AI section, cleanup section, print, and copy-summary.
- Safe cleanup dry-run and exact confirmation phrase enforcement.
- No external dependencies, telemetry, analytics, auto-update, or remote report upload.
- GitHub Actions CI, smoke test, issue templates, PR template, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT, and MIT license.

### Known limitations

- TCC permissions are reported as manual review metadata in v0.1.0.
- Software update availability is not automatically queried to preserve local-only defaults.
- Binary plist parsing is best-effort without external dependencies.
- MCP schema coverage is best-effort and will expand over time.
