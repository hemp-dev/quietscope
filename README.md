# quietscope

Version: `v0.3.0`

Privacy-first local audit dashboard for security, storage hygiene, and AI-agent risk surface. macOS is the primary supported audit platform; Linux has an initial audit module; Windows remains soft-supported for common checks and report generation.

This tool is for defensive local auditing only. It does not exploit vulnerabilities, exfiltrate data, or modify system settings. Review all findings before taking action.

## What this tool does

- Audits common macOS security settings best-effort: SIP, Gatekeeper, FileVault, Firewall, update preferences, XProtect/MRT package metadata, sharing services, and remote access.
- Runs common local checks on Linux and Windows where safe, while reporting unsupported platform check groups as `SKIPPED` instead of failed.
- Adds Linux-specific checks for systemd persistence, cron paths, desktop autostart entries, SSH metadata, firewall status, package update metadata, and sudoers metadata.
- Reviews persistence surfaces including LaunchAgents, LaunchDaemons, cron metadata, periodic scripts, and shell startup files.
- Checks dangerous permissions on `~/.ssh`, shell startup files, LaunchAgent/Daemon plists, home directory, and sampled config paths.
- Estimates storage used by caches, logs, Downloads, Xcode, simulator, Docker, package-manager, Gradle, Android, and Time Machine local snapshot metadata.
- Produces safe cleanup dry-runs and requires the exact phrase `DELETE SAFE CACHE FILES` before deleting only allowlisted user cache/log/trash/DerivedData paths.
- Audits local AI tools, MCP configs, local LLM/API listeners, prompt-injection artifacts, and AI workflow secret exposure risks.
- Inventories AI skills, rules, prompts, memories, instructions, manifests, and AI-related directories that may influence agent context.
- Writes TXT and JSON reports by default, with an optional self-contained local HTML report UI.
- Prints a short terminal progress log with a compact progress bar for audit checks and report writing.
- Provides a local audit control UI for configuring, launching, monitoring, canceling, and opening audit runs.

## What this tool does not do

- It is not an EDR, antivirus, malware remover, exploit tool, or destructive cleaner.
- It is not a replacement for CIS, mSCP, MDM, or enterprise compliance baselines.
- It does not read Keychain, browser saved passwords, cookies, private keys, `.env` contents, or secret values.
- It does not execute MCP commands, suspicious scripts, or project-local instructions.
- It does not upload reports, send telemetry, auto-update, or use external UI assets/CDNs.
- It does not change system settings without explicit future design and confirmation.

## Security model

The project is defensive-only, local-only, and safe-by-default. All external command execution goes through `internal/platform/commands.go` using strict argument arrays and timeouts. The code does not use `sh -c`, `eval`, curl-to-shell installation, telemetry, analytics, or remote report upload.

Filesystem scanning uses explicit exclusions for Keychains, browser profiles, Photos Library, Mail, iCloud Drive, and protected system paths. Cleanup uses a positive allowlist and revalidates each path immediately before deletion.

## Privacy guarantees

- Secret files are checked by metadata only: path, owner, permissions, size, and mtime.
- Environment variables with sensitive names are reported by name only with `***MASKED***`.
- HTML report rendering embeds escaped JSON and uses `textContent`, not unsafe HTML insertion.
- The optional UI server binds only to `127.0.0.1`.
- Audit reports remain local files under the selected output directory.

## Platform support

| Platform | Support level | Notes |
| --- | --- | --- |
| macOS | Supported audit platform | Full audit surface: system metadata, security settings, launchd persistence, permissions, storage, cleanup dry-run, AI/MCP inventory, and reports. |
| Linux | Initial audit platform | Builds and runs. Includes common filesystem, SSH, shell startup, secret metadata, project, AI/MCP, storage, cleanup dry-run, reports, plus initial Linux systemd/cron/autostart/firewall/update/sudoers metadata checks. macOS-only checks are reported as `SKIPPED`. |
| Windows | Soft-supported | Builds and runs. Common metadata and AI/MCP/report checks are best-effort. UID/GID ownership fields are unavailable and reported as `0`. macOS-only checks are reported as `SKIPPED`. Windows audit modules are planned later. |

Soft-supported means the binary should build and run, common checks should produce reports, and unsupported OS-specific checks should be visible as skipped or unavailable rather than treated as failures. The Linux audit module is still conservative and metadata-first; it does not claim full distribution-specific hardening coverage.

## Installation

Build from source with Go 1.22+:

```sh
go build -o quietscope ./cmd/quietscope
```

Build release-style assets:

```sh
GOOS=darwin GOARCH=arm64 go build -o quietscope_darwin_arm64 ./cmd/quietscope
GOOS=darwin GOARCH=amd64 go build -o quietscope_darwin_amd64 ./cmd/quietscope
GOOS=linux GOARCH=amd64 go build -o quietscope_linux_amd64 ./cmd/quietscope
GOOS=windows GOARCH=amd64 go build -o quietscope_windows_amd64.exe ./cmd/quietscope
```

No Homebrew, npm, Python, Node, or external Go dependencies are required.

## Quick start

```sh
./quietscope --all-reports --no-sudo
open ~/Desktop/quietscope-audit-*/report.html
```

For the local audit controller:

```sh
./quietscope --ui
```

## CLI usage

```sh
quietscope [flags]
```

Important flags:

- `--json`: save JSON report.
- `--html`: save self-contained HTML report.
- `--text`: save TXT report.
- `--all-reports`: save TXT, JSON, and HTML.
- `--deep`: enable deeper checks.
- `--ai-audit`: enable AI/MCP/local LLM checks. Enabled by default.
- `--no-ai-audit`: disable AI checks.
- `--clean-dry-run`: show cleanup candidates without deleting anything.
- `--clean-confirm`: delete only allowlisted safe cache files after exact interactive confirmation.
- `--no-sudo`: do not use sudo.
- `--output DIR`: report directory. Default is `~/Desktop/quietscope-audit-YYYYMMDD-HHMMSS`.
- `--project-root DIR`: additional project directory for deep AI/prompt-injection scan.
- `--max-file-size-mb N`: text scan limit. Default `5`.
- `--serve`: serve the generated report directory on `127.0.0.1`.
- `--ui`: start the local audit control UI on `127.0.0.1`.
- `--version`: print version.

The CLI version (`v0.3.0`) runs one audit from terminal flags, writes reports, and exits unless `--serve` is used. While it runs, stderr shows concise process lines such as check start/completion, a compact ASCII progress bar, report-writing steps, cleanup dry-run output, and local server startup.

## UI usage

There are two UI surfaces in `v0.3.0`.

### Report UI

Generate a self-contained HTML report:

```sh
./quietscope --html --no-sudo
open ~/Desktop/quietscope-audit-*/report.html
```

The HTML UI is self-contained with inline CSS and JavaScript. It has dashboard cards, filters, sortable findings, AI security sections, cleanup sections, privacy mode, print/save-as-PDF, and copy-summary controls. It does not load remote fonts, scripts, analytics, or CDN assets.

### Audit Control UI

Start the local controller:

```sh
./quietscope --ui
```

The control UI binds only to `127.0.0.1` and exposes a browser page for audit management. It can configure report outputs, toggle deep checks, enable/disable AI audit checks, run without sudo, set an output directory or project root, launch audits, monitor progress, cancel running audits, and open generated HTML reports. Cleanup deletion remains CLI-only; the UI supports cleanup dry-runs but never sends the destructive confirmation phrase.

## Reports

Default output is TXT and JSON. `--html` or `--all-reports` adds `report.html`.

Top-level JSON fields:

- `metadata`
- `system_info`
- `summary`
- `findings`
- `cleanup_candidates`
- `ai_security`
- `ai_context_inventory`
- `ai_related_directories`
- `ai_skills`
- `ai_context_summary`
- `ai_tool_catalog`
- `mcp_clients`
- `mcp_servers`
- `hermes_agent`
- `opencode`
- `chinese_ai_providers`
- `local_model_inventory`
- `ai_security_tools`
- `ai_provider_summary`
- `generated_at`

## AI local security audit

The AI audit detects common AI coding tools and local LLM tools including Cursor, VS Code, Claude Desktop, Claude Code, Codex CLI, Copilot CLI, Cline/Roo/Continue, aider, Open Interpreter, Ollama, LM Studio, AnythingLLM, GPT4All, Jan, LocalAI, and llama.cpp binaries best-effort.

MCP configs are parsed as JSON and reported as data. MCP commands are never executed. The audit flags shell execution, network-capable tools, unpinned remote package launchers, secret path references, risky permissions, project-local MCP files, and possible local LLM listeners.

## AI Skills & Context Inventory

AI tools increasingly load project and user instructions automatically. Files such as `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.cursorrules`, `.github/copilot-instructions.md`, `SYSTEM_PROMPT.md`, MCP configs, skills, prompts, memories, and agent manifests can affect how an AI agent behaves, what it reads, and which tools it may try to use.

This tool inventories those artifacts for Claude, Codex, Cursor, Copilot, VS Code, Continue, Cline, Roo, Windsurf, Aider, Open Interpreter, and generic AI-agent projects. It records metadata such as path, owner, permissions, size, file count for directories, scope, tool name, artifact type, auto-loaded likelihood, and context impact.

Context impact estimates how likely a file or directory is to influence AI-agent behavior or be included in an AI tool's working context. It is not a malware verdict. A project-local `AGENTS.md` or `CLAUDE.md` can be critical impact because it may be intentionally loaded by an agent, not because the file is necessarily malicious.

In `--deep` mode, instruction-like files are scanned for suspicious review patterns such as requests to ignore previous instructions, reveal system prompts, read `.env`, read `~/.ssh`, use Keychain commands, exfiltrate data, or run network/tool-execution commands. The report shows pattern name, line number, and a short redacted snippet only; it does not print full file contents.

Safe review approach:

- Review project-local AI instruction files before opening an unknown repository in agent mode.
- Treat `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.cursorrules`, `.github/copilot-instructions.md`, and MCP configs as part of the executable trust surface of an AI workflow.
- Disable auto-run and auto-approve for MCP servers and shell commands.
- Restrict write permissions on AI instruction files.
- Keep secrets out of AI prompts, memories, skills, rules, and project settings.

AI model directories such as `~/.ollama/models` or LM Studio model storage can be very large. Large model files are not automatically considered junk and are never auto-cleaned by this tool. Review model directories manually if disk usage is unexpected.

## AI Tool Catalog

The AI Tool Catalog detects a broad set of local AI IDEs, coding agents, CLI agents, MCP clients, MCP servers, local LLM runtimes, desktop LLM apps, browser wrappers, workflow agents, cloud-agent CLIs, AI extensions, skill hosts, and AI security scanners.

Detection is read-only and metadata-only. A detected tool is not automatically a risk. Risk depends on concrete facts such as permissions, project context inclusion, shell access, MCP tools, remote provider usage, API key exposure by environment variable name, logs/caches, and local servers exposed outside loopback.

The catalog covers tools such as Claude Code, Codex CLI, ChatGPT/Codex local artifacts, GitHub Copilot, Cursor, Windsurf, Google Antigravity, Cline, Roo Code, Continue, Aider, Open Interpreter, Goose, OpenClaw, OpenCode/opencode, Hermes Agent, Sourcegraph Cody, Tabnine, JetBrains AI, Zed AI, Amazon Q Developer, Gemini Code Assist, Qwen/Kimi/DeepSeek/GLM CLIs, Ollama, LM Studio, Jan, GPT4All, AnythingLLM, Open WebUI, Pinokio, Msty, BoltAI, MindMac, SillyTavern, PrivateGPT, llama.cpp, LocalAI, vLLM, text-generation-webui, koboldcpp, and desktop wrappers such as ChatGPT, Claude, Perplexity, Poe, Doubao, Kimi, Qwen/Tongyi, and Wenxin/ERNIE where local artifacts exist.

## Hermes Agent Audit

Hermes Agent can have persistent memory, skills, commands, remote integrations, provider configs, and MCP-style tool access. The audit checks Hermes paths, permissions, disk usage, skills/memory/commands metadata, env key names, context impact, and suspicious review patterns where deep scanning is enabled.

The audit never executes Hermes skills or commands and never prints token values. Env key names such as `HERMES_API_KEY`, `HERMES_TOKEN`, `TELEGRAM_BOT_TOKEN`, `DISCORD_TOKEN`, `SLACK_BOT_TOKEN`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_HOST`, and `VLLM_API_KEY` are reported by name only with masked values.

## OpenCode Audit

OpenCode/opencode may have agents, subagents, custom prompts, rules, skills, MCP configs, permissions, and provider settings. The audit checks user-level and project-local OpenCode artifacts, desktop/CLI presence, agent paths, prompt/rule/skill paths, cache/log size, env key names, context impact, and permission/tool risk.

The audit never executes OpenCode agent commands. Provider env key names such as `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `QWEN_API_KEY`, `DASHSCOPE_API_KEY`, `MOONSHOT_API_KEY`, `KIMI_API_KEY`, `ZAI_API_KEY`, and `GLM_API_KEY` are masked.

## Chinese AI Models & Providers

The catalog detects local and cloud-provider artifacts for China-origin model families and providers including Qwen/Tongyi/DashScope/ModelScope, DeepSeek, Kimi/Moonshot, GLM/Z.ai/Zhipu/CodeGeeX, MiniMax, Doubao/ByteDance/Volcano Engine, ERNIE/Wenxin/Baidu/Qianfan, Baichuan, Yi/01.AI, InternLM/OpenCompass, Hunyuan/Tencent, StepFun, SenseNova/SenseTime, and related model/cache hints.

Detection is neutral and factual. Provider origin is not a risk by itself. Risk is based on concrete configuration facts: remote API usage, broad context upload, API key env names present, unsafe agent permissions, MCP tools paired with broad filesystem/shell access, logs/caches containing session metadata, and local servers exposed on non-loopback interfaces.

API key values are never printed. Local model caches such as Qwen, DeepSeek, Kimi, GLM, ModelScope, Hugging Face, Ollama, or LM Studio storage can be large but are never auto-cleaned.

## Cleanup safety

Cleanup is off by default. `--clean-dry-run` only prints candidates. `--clean-confirm` still requires the exact phrase:

```text
DELETE SAFE CACHE FILES
```

Allowed cleanup is limited to children of:

- `~/Library/Caches`
- `~/Library/Logs`
- `~/.Trash`
- `~/Library/Developer/Xcode/DerivedData`
- user temporary cache directories

On Linux and Windows, treat cleanup as best-effort and prefer `--clean-dry-run` plus manual review. Early cross-platform support focuses on report generation and metadata review, not broad cleanup automation.

## Linux audit module

Linux checks are read-only and metadata-first. They inspect systemd service/timer/socket/path unit metadata and sampled startup lines, cron path metadata, desktop autostart entries, shell startup files, SSH permissions, firewall command output, package update metadata timestamps, and sudoers metadata. Commands are never discovered from config files and executed.

Firewall checks probe `ufw`, `firewall-cmd`, `nft`, and `iptables` through the safe command runner. Package update checks only inspect local metadata timestamps; they do not run package-manager network operations such as `apt update`, `dnf check-update`, or equivalent commands.

Forbidden cleanup includes `/System`, `/Library` as a tree, Keychains, browser profiles, Mail, Photos Library, iCloud Drive, `.ssh`, cloud credentials, `.env`, project source files, and Docker volumes.

## Comparison with similar tools

This project is not a replacement for macOS Security Compliance Project (mSCP), CIS compliance automation, Mergen, HardeningPuppy/macOS hardening scripts, SecuraMac guidance, drduh's macOS Security and Privacy Guide, Mole, OpenClaw/mac-security-audit, or enterprise MDM baselines.

It is also not a replacement for storage-only cleaners such as mac-cleaner-cli or Clean-Me, and it is not an EDR, antivirus, malware remover, or destructive cleaner.

AI-agent and MCP security references such as Snyk Agent Scan, Cisco MCP Scanner, MCP Security Scan GitHub Action, ai-agent-audit, OWASP AI Agent Security Cheat Sheet, and OWASP MCP Security Cheat Sheet inform the risk categories, but this project does not copy their code or attempt to be a cloud scanner.

Differentiators:

- local-only by design;
- no telemetry;
- no cloud upload;
- modular Go implementation;
- one self-contained binary;
- self-contained HTML UI;
- AI-agent and MCP security audit included;
- AI skills/rules/prompts/context inventory included;
- safe cleanup dry-run;
- secrets metadata checks without reading secret values;
- open-source-ready repository structure.

Product positioning: Privacy-first local audit dashboard for macOS security, storage hygiene, and AI-agent risk surface, with soft cross-platform CLI support.

## Contributing

See `CONTRIBUTING.md`. New checks must preserve local-only, defensive-only, no-secret-content, and safe-by-default guarantees.

## Responsible disclosure

See `SECURITY.md`. Please do not include secrets or private report contents in public issues.

## Roadmap

- v0.4 Wails desktop preview while preserving the CLI as the primary stable interface.
- Broader Linux audit coverage for distro-specific package-manager, service, and desktop security posture.
- Platform-specific security modules for Windows startup persistence, Defender/Firewall posture, scheduled tasks, services, package managers, and desktop/AI tooling.
- Optional high-assurance Rust helper components for parsing complex binary formats.
- Richer TCC analysis using explicit user consent and local-only parsing.
- More MCP schema variants and package pinning heuristics.
- Optional enterprise profile exports without cloud upload.
