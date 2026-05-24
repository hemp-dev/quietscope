# Changelog 📖

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
