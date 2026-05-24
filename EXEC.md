# Agent Execution Plan

This plan is written for parallel coding agents. Each task has a bounded scope,
file ownership, dependencies, validation commands, and a definition of done.

## Operating Rules

- Keep the project defensive-only, local-only, and safe-by-default.
- Do not add telemetry, remote report upload, auto-update, external UI assets, or CDN dependencies.
- Do not read Keychain, browser saved passwords, cookies, private key contents, `.env` contents, or cloud credential contents.
- Route all external command execution through `internal/platform/commands.go`.
- Use strict `os/exec` argument arrays. Do not add `sh -c`, `eval`, or execution of discovered commands.
- Preserve CLI behavior unless the task explicitly changes it.
- Do not revert unrelated user or agent changes.
- If two agents need the same file, the later agent must rebase mentally on the current file contents and make the smallest compatible change.

## Target Roadmap

- `v0.2.0`: Soft cross-platform CLI.
- `v0.3.0`: Linux audit module.
- `v0.4.0`: Wails desktop preview.
- Later: Windows Basic Audit.

## Platform Support Policy

- macOS: supported audit platform.
- Linux: soft-supported in `v0.2.0`, audit-supported starting `v0.3.0`.
- Windows: soft-supported in `v0.2.0`; basic audit later.

Soft-supported means the binary builds and runs, common checks work, reports are generated, and unsupported OS-specific checks are reported as skipped or unavailable rather than failed.

## Validation Commands

Use these commands as applicable:

```sh
go test ./...
GOCACHE=/private/tmp/macos-malware-gocache go test ./...
GOOS=linux GOARCH=amd64 go test -exec=true ./...
GOOS=windows GOARCH=amd64 go test -exec=true ./...
go build -o quietscope ./cmd/quietscope
sh tests/smoke_test.sh
```

Agents working on CI or release automation should also validate GitHub workflow syntax by inspection and, if available, with `gh workflow list` or `gh run list`.

## Wave 0: Coordination

### Agent R0: Establish Integration Branch

Owner: release captain.

Scope:
- Branch naming and integration order only.
- No code changes unless needed to resolve merge conflicts.

Tasks:
- Create or select an integration branch for `v0.2.0`.
- Merge completed agent branches in this order: A1, A2, A3, A4, A5, A6, A7.
- Run full validation after each merge that touches platform or check registration code.

Definition of done:
- Integration branch exists.
- Merge order is documented in the PR or coordination notes.
- No unrelated changes are introduced.

## Wave 1: v0.2.0 Soft Cross-Platform CLI

Wave 1 can run mostly in parallel. A3 depends conceptually on A2, but can start by identifying macOS-only check surfaces.

### Agent A1: Fix Windows Build

Owner: platform filesystem compatibility.

Primary files:
- `internal/platform/fs.go`
- Optional new files:
  - `internal/platform/stat_unix.go`
  - `internal/platform/stat_windows.go`

Tasks:
- Move `syscall.Stat_t` usage behind platform-specific build tags.
- Keep `FileMeta` fields stable.
- On Windows, populate UID/GID as zero or another clearly documented unavailable value.
- Avoid changing path exclusion behavior unless required for compilation.

Definition of done:
- `GOOS=windows GOARCH=amd64 go test -exec=true ./...` passes.
- `GOOS=linux GOARCH=amd64 go test -exec=true ./...` passes.
- Native `go test ./...` passes.

Risk notes:
- Keep `StatMeta` behavior identical on Darwin/Linux.
- Do not make callers depend on UID/GID being meaningful on Windows.

### Agent A2: Add Platform Capability Model

Owner: platform support semantics.

Primary files:
- `internal/platform/macos.go`
- `internal/platform`
- `internal/audit/finding.go`
- `internal/audit`

Tasks:
- Add helpers for current OS detection: Darwin, Linux, Windows.
- Add capability helpers for feature families such as macOS security settings, launchd persistence, Linux systemd, Windows registry, and common filesystem checks.
- Add or reuse finding statuses so unsupported/skipped checks are distinguishable from failures.
- Keep JSON/report compatibility as much as possible.

Definition of done:
- Platform helpers are unit-tested.
- Unsupported platform state is representable without using failure severity.
- Existing report rendering still works.

Risk notes:
- Avoid a broad enum migration if a small helper and clear `StatusInfo` finding is enough.
- Do not break existing JSON consumers without documenting it.

### Agent A3: Gate macOS-Specific Checks

Owner: check registration and macOS-only execution.

Primary files:
- `internal/app/app.go`
- `internal/checks/security.go`
- `internal/checks/persistence.go`
- `internal/checks/permissions.go`
- `internal/checks/storage.go`
- `internal/checks/system.go`

Tasks:
- Ensure macOS-only checks run only on Darwin.
- On Linux/Windows, emit clear informational findings for unsupported macOS check groups.
- Keep common checks registered on every platform.
- Preserve macOS behavior and report contents.

Definition of done:
- On Darwin, current checks still run.
- On Linux/Windows cross-test, unsupported macOS checks do not call macOS commands.
- Reports explain skipped checks in plain language.

Risk notes:
- Do not hide important common checks by gating too broadly.
- Keep skipped checks visible enough that users understand platform support.

### Agent A4: Preserve Common Cross-Platform Checks

Owner: AI/MCP/project-root/common report behavior.

Primary files:
- `internal/checks/ai_security.go`
- `internal/checks/ai_skills.go`
- `internal/checks/ai_tools_catalog.go`
- `internal/checks/privacy_secrets.go`
- `internal/report`
- `internal/safety`

Tasks:
- Audit common checks for hardcoded macOS paths and commands.
- Keep metadata-only behavior for AI/MCP/project-root scans on all platforms.
- Add platform-safe Windows and Linux user path roots where low-risk.
- Ensure missing platform-specific paths are ignored gracefully.

Definition of done:
- Common checks do not panic or fail on Linux/Windows.
- Tests cover at least one non-Darwin path scenario.
- `GOOS=linux` and `GOOS=windows` cross-tests pass after A1.

Risk notes:
- Do not expand scanning into sensitive content.
- Prefer metadata and filenames over file contents unless existing behavior already scans safe text artifacts.

### Agent A5: Add CI Matrix

Owner: GitHub Actions CI.

Primary files:
- `.github/workflows/ci.yml`
- `tests/smoke_test.sh`
- Optional new scripts under `tests/`

Tasks:
- Add CI jobs for Linux, macOS, and Windows.
- Keep macOS smoke test as the full behavior smoke.
- Add Linux and Windows build/test validation appropriate to current support level.
- Add cross-compile checks for release target triples.

Definition of done:
- CI validates Go tests on at least Ubuntu, macOS, and Windows.
- CI validates buildability for release assets.
- Workflow remains simple and dependency-light.

Risk notes:
- Do not require privileged system access in CI.
- Avoid flaky OS-specific commands in non-macOS jobs.

### Agent A6: Add Release Automation

Owner: release assets and checksums.

Primary files:
- New `.github/workflows/release.yml`
- `VERSION`
- Optional `scripts/` release helpers

Tasks:
- Add tag-triggered release workflow.
- Build assets:
  - `quietscope_darwin_arm64`
  - `quietscope_darwin_amd64`
  - `quietscope_linux_amd64`
  - `quietscope_windows_amd64.exe`
- Generate SHA256 checksums.
- Upload artifacts to GitHub Releases.

Definition of done:
- Release workflow is readable and minimal.
- Asset names match documentation.
- Checksums are generated consistently.

Risk notes:
- Do not add auto-update.
- Prefer plain GitHub Actions unless GoReleaser is explicitly chosen.

### Agent A7: Update v0.2 Documentation

Owner: user-facing docs.

Primary files:
- `README.md`
- `RELEASE_NOTES.md`
- `CONTRIBUTING.md`

Tasks:
- Document soft cross-platform behavior.
- Add platform support table.
- Add install/build examples for macOS, Linux, and Windows.
- Document unsupported/skipped checks.
- Add `v0.2.0` release notes draft.

Definition of done:
- Docs match implemented behavior.
- No unsupported Windows/Linux audit claims are made.
- Safety and privacy guarantees remain prominent.

Risk notes:
- Use conservative wording: "soft-supported", "best-effort", and "metadata-only" where accurate.

## Wave 2: v0.3.0 Linux Audit Module

Start Wave 2 after Wave 1 is merged and green. L1 should land first; L2, L3, and L4 can then proceed in parallel with coordination.

### Agent L1: Add Linux Check Registry

Owner: Linux audit architecture.

Primary files:
- `internal/app/app.go`
- New `internal/checks/linux.go`
- New Linux-specific test files

Tasks:
- Add Linux-specific check registration without changing macOS check behavior.
- Define Linux check group names and finding categories.
- Ensure Linux checks use existing runner and reporting patterns.

Definition of done:
- Linux check group exists and can be enabled by OS detection.
- Empty or minimal Linux check result renders cleanly.
- macOS output remains unchanged except for intentional platform support wording.

Risk notes:
- Do not mix Linux logic into macOS check files unless it is common helper code.

### Agent L2: Implement Linux Persistence Checks

Owner: Linux persistence metadata.

Primary files:
- `internal/checks/linux_persistence.go`
- Tests for Linux persistence helpers

Tasks:
- Inspect metadata for systemd service and timer directories.
- Inspect metadata for user systemd directories.
- Inspect cron paths such as `/etc/cron*`, user crontab metadata where safe, and periodic scripts where present.
- Inspect shell startup files by metadata and suspicious pattern snippets only if aligned with existing safe scanning behavior.

Definition of done:
- Linux persistence findings are useful but non-destructive.
- Tests use fake filesystem fixtures.
- No discovered scripts or service commands are executed.

Risk notes:
- Treat service contents as untrusted text.
- Keep findings review-oriented, not malware verdicts.

### Agent L3: Implement Linux Security Basics

Owner: Linux security settings metadata.

Primary files:
- `internal/checks/linux_security.go`
- Tests for Linux security helpers

Tasks:
- Check SSH directory and key permission metadata.
- Check firewall status best-effort through available commands such as `ufw`, `firewall-cmd`, `nft`, or `iptables`.
- Check update metadata best-effort without forcing package manager network calls.
- Check sudoers metadata without reading secret material.

Definition of done:
- Missing commands produce unavailable/info findings.
- No network package update operation is triggered.
- Tests cover missing command and sample output parsing.

Risk notes:
- Be careful with distro differences.
- Prefer command availability checks and graceful degradation.

### Agent L4: Add Linux Smoke Tests

Owner: Linux validation.

Primary files:
- `tests/`
- `.github/workflows/ci.yml`
- Linux-focused test fixtures if needed

Tasks:
- Add a Linux smoke test that builds the CLI and generates TXT/JSON/HTML reports.
- Ensure smoke test does not require root.
- Add fixture-driven unit tests for Linux check parsing.

Definition of done:
- Linux CI smoke passes on `ubuntu-latest`.
- Smoke validates report files exist and JSON starts with `{`.
- Tests are deterministic.

Risk notes:
- Do not assert host-specific firewall/update state in CI.

## Wave 3: v0.4.0 Wails Desktop Preview

Start Wave 3 after the CLI platform boundary is stable. W1 lands before W2.

### Agent W1: Wails Architecture Spike

Owner: desktop architecture proposal.

Primary files:
- New `desktop/README.md` or `docs/wails-preview.md`
- No production code required

Tasks:
- Define the Wails app structure.
- Define how the desktop layer calls `internal/app.Run`.
- Define progress streaming, cancellation, and report opening.
- Define packaging targets for macOS, Linux, and Windows preview.

Definition of done:
- Architecture doc is concrete enough for implementation.
- It preserves CLI as the primary stable interface.
- It forbids destructive cleanup confirmation in the UI for preview.

Risk notes:
- Do not introduce Wails dependencies in root build until implementation is approved.

### Agent W2: Implement Wails Preview

Owner: desktop preview implementation.

Depends on:
- W1

Primary files:
- New `desktop/`
- Minimal Wails config
- UI source under the desktop app only

Tasks:
- Create minimal Wails desktop app.
- Reuse existing Go audit core.
- Implement audit configuration, run, cancel, progress display, and open generated reports.
- Keep external assets local.

Definition of done:
- Desktop preview runs locally on the developer platform.
- CLI build and tests still pass without requiring desktop tooling.
- README documents preview status and build command.

Risk notes:
- Keep desktop dependencies isolated from the CLI path.
- Do not make Wails required for normal `go test ./...`.

## Later: Windows Basic Audit

Do not start until `v0.2.0` is stable and Linux work is underway or complete.

Candidate agents:
- Windows Defender and Firewall status.
- UAC and Windows Update best-effort metadata.
- Startup folders, Run/RunOnce registry keys, Services, Scheduled Tasks.
- PowerShell profile files and SSH permission metadata.
- Windows AI tool paths under `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%`, and `%ProgramFiles%`.

Rules:
- Use Windows APIs or safe command execution through the runner.
- Do not execute discovered commands.
- Do not claim full Windows security coverage in early releases.

## Final Integration Checklist

- `go test ./...` passes natively.
- `GOOS=linux GOARCH=amd64 go test -exec=true ./...` passes.
- `GOOS=windows GOARCH=amd64 go test -exec=true ./...` passes.
- `sh tests/smoke_test.sh` passes on macOS.
- CI matrix is green.
- Release assets build with expected names.
- SHA256 checksums are generated.
- README support table matches actual behavior.
- Release notes include known limitations.
- No telemetry, external report upload, auto-update, or external UI assets were added.
