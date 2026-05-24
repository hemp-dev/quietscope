# Contributing

Thanks for helping improve `quietscope`.

## Local development

```sh
go test ./...
go build -o quietscope ./cmd/quietscope
./quietscope --help
```

If your local sandbox cannot write to the default Go build cache, use a writable cache:

```sh
GOCACHE=/private/tmp/macos-malware-gocache go test ./...
```

### Git hooks & pre-commit validation

To ensure code style consistency, formatting compliance, and that all tests pass, the repository supports automated local validation hooks.

#### Option A: Native Git Hooks (Recommended, Zero Dependencies)
Run the setup script to configure local hook executions:

```sh
sh scripts/setup-git-hooks.sh
```

- **Pre-commit hook**: Automatically runs `gofmt` and `go vet`, and verifies compilation on staged `.go` files.
- **Pre-push hook**: Automatically runs the entire test suite (`go test ./...`) and platform smoke tests (`tests/smoke_test.sh`).

#### Option B: Pre-commit Framework
If you prefer using the `pre-commit` CLI tool, you can install the configuration via:

```sh
pre-commit install
```

---

Run smoke tests:

```sh
sh tests/smoke_test.sh
```

Cross-platform validation for platform-sensitive changes:

```sh
GOOS=linux GOARCH=amd64 go test -exec=true ./...
GOOS=windows GOARCH=amd64 go test -exec=true ./...
GOOS=darwin GOARCH=arm64 go build ./cmd/quietscope
```

## Code style

- Use Go 1.22+ and the standard library unless a dependency is clearly justified.
- Keep checks modular under `internal/checks`.
- Route all command execution through `internal/platform/commands.go`.
- Use strict argument arrays with `os/exec`; do not add `sh -c`.
- Keep report rendering behind escaping/redaction helpers.
- Handle missing commands and permission denials gracefully.
- Use `internal/platform` OS and capability helpers for platform-specific behavior.
- Represent unsupported platform checks with `SKIPPED`/info findings rather than warn/fail severities.

## Adding a new check

1. Add a focused function in the relevant `internal/checks` file.
2. Return `audit.Finding` values with clear evidence and recommendation.
3. Do not read secret contents.
4. Do not execute discovered commands.
5. Add tests for risky classification, redaction, allowlist, or scoring logic when applicable.
6. Gate OS-specific checks behind platform capability helpers.
7. Update README if the user-visible behavior changes.

## Pull request requirements

- Explain the security/privacy impact.
- Include tests or justify why a change is docs-only.
- Confirm `go test ./...` passes.
- Confirm Linux/Windows build or cross-test behavior when touching platform boundaries.
- Confirm no telemetry, external report upload, auto-update, or external UI assets were added.
- Confirm cleanup behavior remains allowlist-only and confirmation-gated.

## Privacy and safety guardrails

Do not add code that reads Keychain, browser saved passwords, cookies, private key contents, `.env` contents, or cloud credential contents. Metadata-only checks are acceptable when useful.
