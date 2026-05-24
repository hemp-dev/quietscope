# Quietscope Wails Desktop Preview

This directory contains the developer preview (`v0.5.0`) of the **Quietscope Desktop Application**, packaged using the [Wails framework](https://wails.io/).

It provides a premium, responsive, sandboxed native window UI that wraps around Quietscope's robust Go audit core (`internal/app`).

---

## 🏗️ Architecture

```
                                 [ Quietscope Desktop App ]
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
             [ Wails HTML/CSS/JS UI ]                       [ Go App Controller ]
             (desktop/frontend/index.html)                  (desktop/desktop_app.go)
                       │                                           │
                       │ ◄───────── [ progress events ] ───────────┤ (wails.EventsEmit)
                       │                                           │
                       └─────────── [ bound functions ] ──────────►│ (StartAudit, CancelAudit)
                                                                   │
                                                                   ▼
                                                          [ internal/app.Run ]
                                                          (Quietscope Audit Core)
```

### Key Design Decisions
1. **Isolated Build:** The desktop application exists entirely under the `/desktop` folder and does not inject desktop UI dependencies into the CLI.
2. **Real-time Event Streaming:** The bridge leverages Wails' high-performance event bus (`wails.EventsEmit`) to push log entries and progress indicators to the frontend in real time, bypassing HTTP overhead.
3. **Safety & Sandboxing:**
   - **Local Only:** No remote CDN, external stylesheets, analytics, telemetry, or auto-updating packages are included.
   - **No Sudo Escalation in UI:** Audits run within user-space context by default.
   - **CLI-only Cleanup:** Confirming cache cleanups (`--clean-confirm`) remains strictly CLI-only to prevent destructive operations via simple UI clicks.

---

## 🛠️ Getting Started

### Prerequisites

1. **Go:** Ensure Go 1.22+ is installed.
2. **Wails CLI:** Install the Wails generator and build system:
   ```bash
   go install github.com/wailsapp/wails/v2/cmd/wails@latest
   ```
3. **OS Requirements:**
   - **macOS:** Xcode Command Line Tools installed.
   - **Linux:** `libgtk-3-dev` and `webkit2gtk-4.0-dev` packages (e.g., `sudo apt install libgtk-3-dev webkit2gtk-4.0-dev`).
   - **Windows:** WebView2 runtime.

### 🏃 Running in Development Mode

You can run the application with live hot-reloading using the Wails dev environment:

```bash
cd desktop
wails dev
```

This compiles the Go backend, mounts the frontend, launches a native window, and watches for edits to both Go and HTML/CSS/JS source files.

### 📦 Building the Production Binary

To compile a highly optimized, single self-contained native binary:

```bash
cd desktop
wails build
```

The resulting executable will be generated in the `desktop/build/bin/` folder.

---

## 🧪 Verification & Local Compilation Spike

To verify that the code and dependencies are 100% syntactically correct, you can run a dry-compile validation spike:

```bash
# Verify standard unit tests still build and run:
go test ./...

# Verify that the desktop wrapper packages build:
go build -o /dev/null ./desktop/...
```
