# quietscope 🛡️

[![Go Report Card](https://goreportcard.com/badge/github.com/hemp-dev/quietscope)](https://goreportcard.com/report/github.com/hemp-dev/quietscope)
[![Build Status](https://github.com/hemp-dev/quietscope/workflows/CI/badge.svg)](https://github.com/hemp-dev/quietscope/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-v0.4.0-blue.svg)](./VERSION)

**quietscope** is a privacy-first, local-only defensive audit dashboard for system security settings, storage hygiene, and local AI-agent risk surface (macOS, Linux, and Windows).

In the era of AI coding assistants (like Cursor, Claude Code, Cline, and aider), your local filesystem is exposed to new risk vectors: malicious auto-loaded instructions (`.cursorrules`, `CLAUDE.md`), permissive MCP server configurations, and exposed API tokens. `quietscope` inventories these risks, checks standard OS security parameters, performs safe dry-run cleanups, and generates a self-contained interactive HTML dashboard—**100% locally with zero telemetry.**

---

## Key Features 🚀

- **AI & MCP Agent Security Audit**: Checks Claude Desktop/Code, Cline/Roo, Cursor, aider, LM Studio, and Ollama settings. Flags unsafe execution permissions, remote unpinned packages, and credentials exposed in agent rules.
- **AI Skills & Rules Inventory**: Scans `.cursorrules`, `.cursor/rules`, `CLAUDE.md`, `AGENTS.md` and manifests to estimate context impact and flag prompt-injection or suspicious patterns (e.g., attempts to read `~/.ssh` or ignore system instructions).
- **System Security Audit**: Checks SIP, Gatekeeper, FileVault, sharing services, SSH configurations, cron persistence, and OS auto-updates (fully optimized for macOS; initial modules for Linux systemd/sudoers and Windows Defender/UAC).
- **Storage Hygiene & Safe Cleanup**: Scans system logs, caches, Xcode DerivedData, simulator footprints, and package manager wastes. Provides a safe dry-run first and requires explicit verification to delete anything.
- **Local Web Controller & HTML UI**: Runs a local control server (`127.0.0.1` only) to configure, execute, and view beautifully structured interactive audits.
- **Wails Desktop Application**: Developer preview of a fully native cross-platform GUI wrapper.

---

## Quick Start ⏱️

### 1. Build from Source (Requires Go 1.22+)
```bash
# Clone the repository
git clone https://github.com/hemp-dev/quietscope.git
cd quietscope

# Build CLI core
go build -o quietscope ./cmd/quietscope
```

### 2. Run an Audit and Open the Interactive Report
```bash
# Run a safe, non-root system & AI audit generating all report formats
./quietscope --all-reports --no-sudo

# Open the self-contained local HTML report
open ~/Desktop/quietscope-audit-*/report.html
```

### 3. Launch the Audit Control UI in Browser
```bash
# Start the local controller on localhost:8080
./quietscope --ui
```

---

## CLI Reference ⌨️

```text
Usage of quietscope:
  --all-reports          Save TXT, JSON, and HTML reports (default)
  --ui                   Start local audit control UI on 127.0.0.1
  --deep                 Enable deeper security scan of file contents
  --no-sudo              Do not invoke or request sudo permissions
  --clean-dry-run        List cleanable system caches/logs without deleting
  --clean-confirm        Execute cleanup (requires interactive safety phrase)
  --output DIR           Custom output directory (default: ~/Desktop)
  --project-root DIR     Scan an additional local codebase for risky .cursorrules
  --max-file-size-mb N   Limit size of scanned text files in MB (default: 5)
  --version              Print quietscope version
```

---

## Security & Privacy by Design 🔒

`quietscope` is defensive-only, local-only, and safe-by-default:
- **No Telemetry**: No tracking, cookies, remote script loading, or third-party CDN assets.
- **Zero Credentials Exposure**: Environment variables with sensitive names (e.g., `ANTHROPIC_API_KEY`) are masked (`***MASKED***`). We **never** read your actual `.env` file contents, Keychains, or private keys.
- **Execution Safety**: All OS command invocations pass through a strict argument-array runner without launching shell wrappers like `sh -c`.
- **Cleanup Guarantee**: No destructive cleanup happens unless `--clean-confirm` is used and the user manually types `DELETE SAFE CACHE FILES`. Cleanup is strictly restricted to user caches, temporary paths, and trash.

---

## Platform Support 🖥️

| Operating System | Support Level | Core Scans Available |
| :--- | :--- | :--- |
| **macOS (Darwin)** | **Full (Primary)** | SIP, Gatekeeper, FileVault, launchd persistence, permissions, cache cleanup, AI/MCP audit, interactive HTML. |
| **Linux** | **Initial Support** | systemd units, cron paths, SSH/sudoers metadata, autostart entries, cache dry-run, AI/MCP audit. |
| **Windows** | **Basic Support** | Defender, Firewall, UAC status, startup folder registries, local model inventory, basic reports. |

---

## Desktop Application (Wails Developer Preview) 🎨

We are building a beautiful native desktop app using Wails. To test it:
1. Install Wails CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
2. Navigate to `desktop/` and run:
   ```bash
   cd desktop
   wails dev
   ```

---

## Contributing 🤝

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) to learn how to add new security checks, write cross-platform checks, or improve the Wails UI.

---

## License 📄

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
