# Contributing to quietscope 🤝

Thank you for your interest in improving `quietscope`! We want to make it easy to contribute new security checks, support more platforms, and optimize disk hygiene scanning.

## Our Philosophy 🧠
1. **Privacy Above All**: No checks must ever transmit data over the network or read private secret contents (API key values, passwords, private keys).
2. **Defensive Only**: `quietscope` is an auditing tool. It must never attempt to exploit vulnerabilities or silently modify system settings.
3. **Safety First**: Any feature that deletes files (cleanup) must be strictly opt-in, highly restrictive, and thoroughly validated.

---

## How to Add a New Security Check 🛠️

All quietscope audit checks are organized under `internal/checks/`. 

### Step 1: Identify the Check Group
Choose where your check belongs:
- `internal/checks/os_darwin.go` (macOS specific)
- `internal/checks/os_linux.go` (Linux specific)
- `internal/checks/os_windows.go` (Windows specific)
- `internal/checks/ai_security.go` (AI / MCP / local LLM checks)
- `internal/checks/storage.go` (Caches, logs, simulator cleanups)

### Step 2: Implement the Check Interface
Every check returns a structured `Finding`:

```go
type Finding struct {
	ID          string    `json:"id"`          // Unique identifier (e.g., "SEC-MAC-SIP-001")
	Title       string    `json:"title"`       // Short description
	Category    string    `json:"category"`    // "Security", "AI Agent Risk", "Storage", "Permissions"
	Severity    string    `json:"severity"`    // "CRITICAL", "HIGH", "WARNING", "INFO"
	Status      string    `json:"status"`      // "FAILED", "PASSED", "SKIPPED"
	Message     string    `json:"message"`     // Human-readable outcome summary
	Remediation string    `json:"remediation"` // How to fix the finding
}
```

Use `internal/platform/commands.go` to invoke system shell commands safely:
```go
// Correct: passing arguments as an array slice, preventing command injection
output, err := platform.RunCommand("csrutil", []string{"status"}, 5 * time.Second)
```

---

## Development Environment Setup 💻

### Prerequisites
- **Go 1.22+**
- **Wails CLI v2** (only if working on the desktop application)
- **Node.js & npm** (only for the Wails frontend)

### Running tests
```bash
# Run all Go unit tests
go test ./...
```

### Running Wails Desktop in Development Mode
```bash
cd desktop
wails dev
```

---

## Submitting a Pull Request 🚀

1. Fork the repository and create your branch from `main`.
2. Run `gofmt -s -w .` and `go vet ./...` to verify code format and basic correctness.
3. Commit your changes using descriptive commit messages (following [Conventional Commits](https://www.conventionalcommits.org/)):
   - `feat(checks): add systemd autostart check for linux`
   - `fix(safety): restrict cleanup boundaries for trash directory`
4. Push your branch and open a Pull Request. Fill in the Pull Request Template.
