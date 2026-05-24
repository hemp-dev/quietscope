# Changelog 📖

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.1] - 2026-05-24

UI layout polish for the desktop/report refresh.

### Fixed
- Standalone HTML reports no longer overflow horizontally with the fixed sidebar layout.
- Findings tables now stay constrained to the report content area and wrap long content safely.
- The report risk gauge initializes on first render instead of showing a placeholder state.
- README logo asset now uses valid PNG encoding.

### Changed
- Version bumped to `v0.5.1`.

---

## [0.5.0] - 2026-05-24

Desktop UI & Report overhaul with full-screen Audit Findings Explorer, runtime metrics fix, and standalone HTML report redesign.

### Added
- **Full-screen Audit Findings Explorer**: dual-pane interactive workstation with filterable finding cards and detailed remediation panel.
- **Horizontal Metrics Summary Bar**: inline metrics strip with Risk Score, Findings, AI Risks, Secrets, Duration.
- **Active Scan Pulse Loaders**: animated loading indicators replacing misleading zero metrics during running scans.
- **Standalone HTML Report redesign**: interactive glassmorphic safety dashboard with SVG risk gauge, privacy masking, remediation simulator.
- **XSS Protection**: `escapeHTML()` helper for all dynamically rendered finding data.

### Fixed
- **Duration bug**: Go zero-value timestamps no longer produce massive negative elapsed times (`-63915244578.8s`).
- **Metrics bug**: Findings/AI Risks/Secrets no longer show `0` while audit is actively running.

### Changed
- Version bumped to `v0.5.0`.
- SECURITY.md updated: v0.5.x active, v0.4.x maintenance.

---

## [0.4.0] - 2026-05-24

This release introduces native Windows security checks, basic Linux persistence checks, and the developer preview of our Wails desktop application dashboard.

### Added
- **Wails Desktop Preview**: Introduces `desktop/` application utilizing a native Go/Webview wrapper for a clean audit management UI.
- **Windows Security Audit**: Adds Defender, UAC status, Firewall checks, registry startup keys, and Windows PowerShell profile persistence audits.
- **Linux Security Audit**: Adds modules for systemd service metadata, autostart configurations, cron permissions, and sudoers checks.
- **Deep Content Analysis**: Option to scan instruction files (`.cursorrules`, `CLAUDE.md`) for high-risk prompt-injection strings and file access requests.
- **CI/CD Pipeline**: Configured GitHub workflows for multi-platform build testing and automated binary releases.

### Changed
- **Masking Engine**: Upgraded sensitive environment variable masking to support localized provider names under **hemp-dev** specification.
- **Commands Engine**: Reinforced argument-level separation for command execution in `internal/platform/commands.go` to prevent raw system shell injection.
- **Project Structure**: Cleaned up open-source community files (README, LICENSE, SECURITY, CONTRIBUTING, CHANGELOG) in preparation for public release.
