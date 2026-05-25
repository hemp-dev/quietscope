# Quietscope GPT Image prompts

Use these prompts to generate consistent high-fidelity raster mockups of Quietscope screens with GPT Image. They are meant for product visuals, release assets, website previews, and documentation screenshots. For pixel-perfect UI screenshots, render the app itself instead.

## Global art direction

Apply this visual language to every prompt unless the prompt says otherwise:

- Product: Quietscope, a privacy-first local-only defensive security audit dashboard for macOS, Linux, Windows, and local AI-agent risk surfaces.
- Brand mark: neon emerald shield with a simple scope/crosshair symbol. Keep it clean and vector-like.
- Color system: near-black app background, deep blue-black panels, emerald green `#10b981`, cyan `#00f2fe`, warning amber, error rose, soft glass borders, subtle neon glow.
- Tone: premium native security tool, calm and trustworthy, not "hacker movie".
- UI density: professional dashboard, compact, scannable, realistic controls and data tables.
- Data: use safe synthetic values only, never real personal data. Prefer masked paths like `/Users/<user>/Projects/quietscope`.
- Typography: modern system UI, clean sans-serif for app/report surfaces, monospace only for log/data-heavy areas.
- Text rule: make the major labels readable and exact; smaller table rows can be plausible UI text blocks.
- Avoid: people, mascots, skulls, malware icons, exploit code, random terminal commands, stock-photo backgrounds, purple gradients, orange/brown palettes, huge marketing hero copy, illegible microtext, decorative floating objects.

Recommended output framing:

- Desktop and report screens: 16:10 or 4:3 product screenshot, centered macOS-style app window, crisp UI, no external browser address bar unless requested.
- Local web controller screens: 16:10 browser-like dashboard screenshot, restrained and functional.
- Marketing preview variants: show the full window with a subtle background glow, but keep the UI itself as the primary subject.

## Prompt 01 - Wails desktop, idle start screen

```text
Use case: ui-mockup
Asset type: high-fidelity product screenshot for documentation
Primary request: Generate a native macOS desktop app screenshot for Quietscope in its idle start state before any audit has run.
Scene/backdrop: A centered macOS-style native window on a dark blue-black desktop background with a very subtle emerald and cyan ambient glow. Include macOS traffic-light window controls.
Subject: Quietscope defensive security audit desktop app.
Layout: Header with shield logo and title "Quietscope" on the left, badge "Developer Preview v0.6.0" on the right. Left sidebar titled "Audit Configurations" with "Scan Scope" checkboxes: Deep Scan, AI Audit checked, No Sudo checked. Section "Report Formats" with HTML, JSON, Text checked. Inputs labeled Output Directory, Project Root (Deep Scan), Max File Size (MiB). Large emerald primary button "Start Defensive Audit". Main workspace has top panel "Active / Past Audits" with empty state "No audits initiated yet. Configure options and start an audit." Bottom detail area empty with message "Select or start an audit from the list."
Style: Premium glassmorphic dark UI, emerald/cyan accents, compact controls, rounded 8-12 px panels, soft borders, realistic native app polish.
Composition: Full window visible, balanced spacing, UI is the focus, no people, no code outside the app.
Quality constraints: Major text must be readable and spelled correctly. Do not add unrelated sections.
```

## Prompt 02 - Wails desktop, running audit console

```text
Use case: ui-mockup
Asset type: high-fidelity product screenshot for release notes
Primary request: Generate the Quietscope Wails desktop app while a defensive audit is running.
Scene/backdrop: Native macOS window, dark blue-black glass interface, subtle cyan scanning glow.
Subject: Quietscope active audit workflow.
Layout: Header "Quietscope" with shield logo and "Developer Preview v0.6.0". Left sidebar "Audit Configurations" with Deep Scan, AI Audit, No Sudo checked, report format checkboxes, output/project fields, disabled-looking "Start Defensive Audit" button. Top workspace "Active / Past Audits" shows a selected run with status pill "running", progress around 64%, and another completed historical run. Detail area left column titled "Audit Summary & Metrics" with a pulsing circular gauge showing "-" and label "Analyzing...", progress bar at 64%, metric cards Findings "-", Duration "12.4s", AI Risks "-", Secrets "-". Buttons: "Cancel Run" enabled and "Open Report" disabled. Right pane is a terminal-style panel titled "Terminal Logs", tab "Console Log" active, tabs "Audit Findings" and "AI Control Center" disabled. Include colored log lines such as "[scan] ai_security checking MCP configs", "[info] privacy checks running", "[warn] possible exposed local AI port".
Style: Premium dark glassmorphism, emerald progress bar, cyan active state, realistic terminal log coloring.
Composition: Full window visible, dense but clean, active scan pulse indicators.
Quality constraints: No scary malware visuals, no exploit code, no real secrets.
```

## Prompt 03 - Wails desktop, completed run summary

```text
Use case: ui-mockup
Asset type: high-fidelity product screenshot for app store or README preview
Primary request: Generate the Quietscope desktop app after an audit has completed, showing the console summary tab.
Scene/backdrop: Centered macOS-style Quietscope window on a subdued dark gradient background.
Subject: Completed local defensive audit.
Layout: Header with Quietscope shield logo, title "Quietscope", badge "Developer Preview v0.6.0". Left sidebar with audit configuration controls. Top "Active / Past Audits" timeline shows several runs with status pills: completed, failed, canceled, completed. Selected run is completed. Detail left column shows circular risk gauge "18 / 100" with label "Secure", progress 100%, metric cards Findings 18, Duration 34.8s, AI Risks 3, Secrets 0, output path `/Users/<user>/Desktop/quietscope-desktop-audit`. Buttons "Cancel Run" disabled and "Open Report" enabled. Right pane terminal tabs show "Console Log" active with final green lines: audit completed, report.html written, json report written.
Style: Dark premium native UI, emerald success glow, clean security dashboard aesthetic.
Composition: Window fills most of the image, all key text readable, no extra marketing copy.
Quality constraints: Use safe synthetic paths, no personal names, no real credentials.
```

## Prompt 04 - Wails desktop, Audit Findings Explorer

```text
Use case: ui-mockup
Asset type: high-fidelity UI screenshot for release notes
Primary request: Generate Quietscope desktop app in the completed audit "Audit Findings" tab, showing the full-screen dual-pane findings explorer.
Scene/backdrop: Native macOS app window, dark glass interface, subtle emerald/cyan glow.
Subject: Interactive security findings workstation.
Layout: Header and left configuration sidebar remain visible. The main detail panel uses one full-width content area. Top terminal header has tabs "Console Log", active "Audit Findings", and "AI Control Center". Under it, a horizontal summary bar with Overall Risk Score "18 / 100 (Secure)", Findings "18", AI Risks "3", Secrets "0", Duration "34.8s", and button "Open In Browser". Below, a dual-pane explorer: left column has search input "Search findings...", filters "All Severities" and "All Categories", then scrollable finding cards with badges high, medium, low, info and titles like "MCP config uses remote package", "AI permissions / TCC manual review", "Local AI/API listening port". Right column has selected finding detail: severity and status badges, title "MCP config uses remote package", category "ai_security", evidence box, remediation recommendation box, detection command box, cards "Auto-Fixable: No (Manual verification required)" and "Reclaimable Size: 0 B (Diagnostic only)", footer buttons "Delete File", "Disable Skill", "Copy Info".
Style: Professional defensive security console, compact scannable cards, emerald active border, amber/rose risk badges.
Composition: Make the right detail panel visually dominant but keep the left findings list readable.
Quality constraints: No exploit instructions, no real commands beyond abstract UI snippets.
```

## Prompt 05 - Wails desktop, AI Control Center tab

```text
Use case: ui-mockup
Asset type: high-fidelity UI screenshot
Primary request: Generate the Quietscope Wails desktop app with the "AI Control Center" tab active for a completed audit.
Scene/backdrop: macOS native dark window, glass panels, quiet emerald lighting.
Subject: Safe management table for local AI artifacts.
Layout: Header "Quietscope", left audit configuration sidebar, top "Active / Past Audits" run timeline. Main detail panel is full-width. Terminal-style header tabs show Console Log, Audit Findings, active AI Control Center. Content title "AI Control Center" with subtitle "Preview changes, create backups, and restore safely through the Wails bridge." A dense table fills the panel with columns Tool, Kind, Scope, Risk, Path, Actions. Rows include Cursor rules, Claude skill, MCP server, Ollama cache, Local model. Paths are masked like `/Users/<user>/.config/claude/skills/research.md`. Action buttons in each row: read, edit, disable, enable, fix, clean, delete, restore. Some buttons disabled with muted styling, destructive actions rose, primary actions emerald.
Style: Compact enterprise dashboard, dark glassmorphic, crisp table lines, restrained neon accents.
Composition: Full UI window visible, table readable, no modal.
Quality constraints: Do not imply silent deletion; include preview/backup wording.
```

## Prompt 06 - Wails desktop, action preview modal

```text
Use case: ui-mockup
Asset type: high-fidelity UI screenshot
Primary request: Generate Quietscope desktop app showing the AI Control Center action preview modal before applying a safe artifact change.
Scene/backdrop: Same dark macOS Quietscope desktop window as the AI Control Center, dimmed by a dark overlay.
Subject: Backup-first preview/diff modal.
Layout: Background shows the AI Control Center table blurred or dimmed. Foreground modal centered, width about 900 px, rounded 10 px, dark panel border. Modal title "Preview disable", close button "Close". Body contains a monospaced diff preview with red removed line and green added line, plus message "Backup will be created before execution." Footer has an emerald button "Execute with backup". Use a synthetic path `/Users/<user>/.cursor/rules/agent-rules.md`.
Style: Security-focused confirmation flow, serious but calm, emerald primary action, rose caution accents, no alarmist imagery.
Composition: Modal is the focal point, background table still recognizable.
Quality constraints: Major modal labels must be readable. No destructive confirmation without backup wording.
```

## Prompt 07 - Local web controller, idle dashboard

```text
Use case: ui-mockup
Asset type: browser UI screenshot for docs
Primary request: Generate the Quietscope local web controller at `127.0.0.1` before any audit has been started.
Scene/backdrop: Clean browser-like dashboard, no visible address bar unless subtle. Light/dark-aware restrained admin UI, prefer dark mode.
Subject: Local-only audit control UI.
Layout: Top header with title "macOS Security Audit", subtitle "The local UI binds to 127.0.0.1, launches local audits only, and never uploads reports or file contents.", badge "UI v0.6.0". Main grid with left panel "Audit Control" containing checkboxes Deep, AI audit checked, No sudo checked, Cleanup dry-run, report outputs TXT, JSON, HTML, input fields Output directory, Project root, Max file size MiB, buttons "Start Audit" and "Refresh", notice "Cleanup confirmation remains CLI-only." Right workspace top status cards: Total runs 0, Active 0, Failed/Canceled 0, Latest score "-". Below, Runs panel empty "No audits yet.", Run Detail panel empty "Select or start an audit.", and bottom "AI Control Center" table with filters and empty row "Run an AI audit to populate manageable artifacts."
Style: Functional local admin console, monospace typography, muted green/blue accents, no glossy marketing treatment.
Composition: Full dashboard visible with left rail and right workspace.
Quality constraints: Keep text compact but readable, no external cloud branding.
```

## Prompt 08 - Local web controller, running audit detail

```text
Use case: ui-mockup
Asset type: browser UI screenshot for release notes
Primary request: Generate the Quietscope local web controller while an audit is actively running.
Scene/backdrop: Restrained dark local web dashboard.
Subject: Live audit management from a loopback browser UI.
Layout: Header "macOS Security Audit" with local-only notice. Left "Audit Control" form remains visible. Status cards show Total runs 3, Active 1, Failed/Canceled 0, Latest score "-". Runs panel lists three jobs; selected job has status pill "running". Run Detail panel shows running job id, progress bar 58%, buttons "Cancel", disabled "Open Report", disabled "Delete"; metadata cards Started, Duration, Output, Risk "-", Findings "-", Error "-"; log box contains live progress lines for system security, AI audit, persistence, storage cleanup dry-run. Bottom "AI Control Center" table still partially empty or loading.
Style: Dense operational UI, dark mode, monospaced text, green/cyan progress, clear status pills.
Composition: Emphasize status cards and live log panel.
Quality constraints: No fake network upload indicators; keep local-only privacy tone.
```

## Prompt 09 - Local web controller, AI Control Center populated

```text
Use case: ui-mockup
Asset type: browser UI screenshot
Primary request: Generate the Quietscope local web controller after a completed AI audit, with the AI Control Center populated.
Scene/backdrop: Dark local web dashboard with compact admin panels.
Subject: Manageable local AI artifacts table.
Layout: Top status cards show Total runs 4, Active 0, Failed/Canceled 1, Latest score "18/100". Left panel "Audit Control". Runs and Run Detail panels are visible above. Bottom section "AI Control Center" has filter controls Search artifacts, All tools, All kinds, All scopes, All actions. Table columns Tool, Kind, Scope, Risk, Path, Actions. Rows include Claude, Cursor, MCP server, Ollama, OpenCode. Actions are small buttons read, edit, disable, enable, fix, clean, delete, restore; unavailable actions are disabled.
Style: Local admin utility, compact, readable, no glossy distractions.
Composition: Make the AI Control Center table occupy the lower half and be the visual focus.
Quality constraints: Use masked paths and synthetic names only.
```

## Prompt 10 - Local web controller, preview/edit modal

```text
Use case: ui-mockup
Asset type: browser UI screenshot
Primary request: Generate the Quietscope local web controller with an action preview modal open from the AI Control Center.
Scene/backdrop: Dark local web dashboard dimmed behind a modal.
Subject: Preview changes workflow for backup-first local artifact edits.
Layout: Background shows AI Control Center table. Center modal with title "Preview edit", close button "Close". Modal body has a large textarea with safe synthetic config content, a diff preview panel below, note "Backup will be created before execution.", and footer buttons "Preview changes" and "Apply with backup". Use labels exactly. The modal should feel like a careful local admin tool, not a destructive warning.
Style: Monospace utility UI, dark panel, emerald primary button, muted borders.
Composition: Modal centered and dominant, background table visible but subdued.
Quality constraints: No real token values, no private file content.
```

## Prompt 11 - HTML report, Dashboard Summary

```text
Use case: ui-mockup
Asset type: high-fidelity standalone HTML report screenshot
Primary request: Generate Quietscope's self-contained interactive audit report on the "Dashboard Summary" section.
Scene/backdrop: Centered browser/app window on a light neutral background, dark report UI inside the window.
Subject: Offline local audit report dashboard.
Layout: Fixed left sidebar with shield logo "Quietscope" and nav links: Dashboard Summary active, Security Findings, AI Security Hardening, AI Context Inventory, AI Tool Catalog, AI Control Center, Storage & Cleanup. Sidebar footer has "Privacy Masking" toggle and "Offline Local Audit". Main header: "Quietscope Audit Report", subtitle "Defensive user-space analysis. No external APIs, uploads, or trackers.", buttons "Copy Summary" and "Save to PDF". Main section title "Security Dashboard Summary". Large risk gauge card shows "18 / 100" and badge "SECURE / LOW RISK". Right stacked metric cards: Findings 18, AI Risks 3, Reclaimable Space 1.2 GiB. Below, stat cards for Risk Assessment Level, Total Audit Findings, High & Critical Issues, PASS / WARN / FAIL / INFO, Reclaimable Disk Caches, Exposed AI Secrets / Credentials, Audit Time Stamp, Host Target OS, Hostname Node. Include "Remediation Plan Simulator" with projected score bar and checklist rows.
Style: Dark premium report UI, emerald/cyan glow gauge, crisp sidebar, restrained borders.
Composition: Full report window visible, dashboard is the focal point.
Quality constraints: Major labels exact, no cloud/upload visual language.
```

## Prompt 12 - HTML report, Security Findings

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's report on the "Security Findings" section.
Scene/backdrop: Dark report interface inside a centered browser-like window.
Subject: Defensive audit findings table with filters.
Layout: Left sidebar with "Security Findings" active. Header "Quietscope Audit Report" with Copy Summary and Save to PDF buttons. Main section title "Defensive Audit Findings". Filter toolbar with Global Search, Severity, Category, Verdict Status, Quick Filters. Below, a wide responsive table with columns Severity, Status, Category, Title, Technical Details. Rows show readable badges for critical/high/medium/low/info and PASS/WARN/FAIL/INFO. One row expanded with "View Technical Trace & Guidance" showing a preformatted evidence box, mitigation remedy, command evaluated, supports auto-fix, cleanup candidate, reclaimable bytes, and risk profiling. If buttons are shown, include "Delete File", "Disable Skill", "Fix Patterns" only as local-server actions.
Style: Dark enterprise report, dense table, emerald active sidebar indicator, rose/amber/blue badges.
Composition: Table and expanded detail occupy most of the screen.
Quality constraints: Use synthetic evidence, no real exploit commands, no real secrets.
```

## Prompt 13 - HTML report, AI Security Hardening

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's "AI Local Security & Hardening" report section.
Scene/backdrop: Dark standalone report window with fixed sidebar.
Subject: Local AI and MCP security hardening overview.
Layout: Sidebar active item "AI Security Hardening". Main section title "AI Local Security & Hardening". Highlight box explains local LLM/agent checks. A grid of cards labeled Discovered AI Tools, MCP Server Configurations Checked, Exposed AI Host Ports & API Bindings, Local Workspace Prompts Evaluated, AI System Hardening Recommendations. Cards contain concise monospaced rows with safe synthetic examples: Cursor, Claude Desktop, Ollama, MCP config risk medium, local server bound to 127.0.0.1, prompt artifact warning.
Style: Premium dark dashboard with compact cards, subtle emerald/cyan accents, no sensational threat imagery.
Composition: Card grid fills the main area; sidebar remains visible.
Quality constraints: Keep all content defensive and metadata-focused.
```

## Prompt 14 - HTML report, AI Context Inventory

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's "AI Skills & Context Inventory" report section.
Scene/backdrop: Dark report UI in a browser-like window.
Subject: Inventory of AI-related directories, rules, skills, and prompt context artifacts.
Layout: Sidebar active item "AI Context Inventory". Main title "AI Skills & Context Inventory". Highlight box describing auto-loaded LLM/developer context boundaries. Summary stat cards: AI Cache Directories, AI Directories Disk Usage, Identified prompt context artifacts, Critical prompt context footprint, High prompt context footprint, Writable prompt instruction files, Suspicious Prompt Injection Files. Filter toolbar with AI Agent Tool, Directory Type, Artifact Class, Access Scope, Context Impact, Auto-loaded Likelihood, Cleanup Status, Suspicious Skill Files, Min Size (MiB). Two tables: "AI-Related Directories Scanned" and "AI Instruction & Skill Files" with columns Tool, Path, Category, Disk Size, Files, Modified, Context Impact, Score, Cleanup, Recommendation.
Style: Dense technical inventory, dark theme, crisp tables, muted text, emerald highlights.
Composition: Summary cards at top, filters and first table visible, second table starts below.
Quality constraints: Use masked paths only, no real usernames or file contents.
```

## Prompt 15 - HTML report, AI Tool Catalog and MCP Providers

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's "AI Tool Catalog & MCP Providers" report section.
Scene/backdrop: Dark report interface with fixed left navigation.
Subject: Catalog of local AI tools, providers, MCP servers, and model inventories.
Layout: Sidebar active item "AI Tool Catalog". Main title "AI Tool Catalog & MCP Providers". Highlight box says catalog entries represent discovery, not a threat vector. Summary cards: Detected Local AI Tools 7, Exposed MCP Client instances 2, Configured MCP Servers 5, Hermes Agent status Not Found, OpenCode Workspace status Configured, Additional AI SDK Libraries 1, Discovered Environment API keys 0, Local LLM model Cache size 7.8 GiB, Broad local host API servers 0. Filter toolbar for Tool Category, Vendor / Provider, Model Family, Provider Group, Exposes Env Key, Contains MCP Tools, Min Size (MiB). Main visible table "Detected Local AI Tools" with columns Tool Name, Vendor, Categories, Paths / Executables, Configurations, Caches / Logs, Disk Usage, Ports, Security Risks. Include lower section headings MCP Integration, Additional AI SDKs & Providers, Local LLM Model Inventories.
Style: Technical audit catalog, dark premium UI, small readable badges and tables.
Composition: Summary cards and top catalog table are focal point.
Quality constraints: Keep provider and path examples synthetic and metadata-only.
```

## Prompt 16 - HTML report, AI Control Center

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's "AI Control Center" report section.
Scene/backdrop: Dark self-contained report window.
Subject: Safe management view for skills, guides, rules, prompts, MCP servers, caches, and models.
Layout: Sidebar active item "AI Control Center". Main title "AI Control Center". Highlight box: "Manageable skills, guides, rules, prompts, MCP server entries, caches, and models are listed here. Static reports show the same actions disabled; local-server mode enables preview, diff, backup, and restore flows." Filter toolbar with Tool, Kind, Scope, Risk, Action Availability. Three subsections: "Skills, Guides, Rules & Prompts", "MCP Servers", "Caches & Models". Each subsection has a table. First table columns Tool, Kind, Scope, Risk, Path, Actions. Action buttons read, edit, disable, enable, fix, clean, delete, restore appear mostly disabled with small tooltip-like muted state "Disabled in static report"; local-server actions can be shown enabled in emerald/rose if the prompt should show local mode.
Style: Dense safety management dashboard, muted disabled actions, clear backup-first posture.
Composition: The first table should be most visible; lower section headings visible.
Quality constraints: Do not imply actions run in static offline mode unless clearly labeled local mode.
```

## Prompt 17 - HTML report, Control Center modal

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's AI Control Center with a local-server action modal open.
Scene/backdrop: Dark report UI dimmed by overlay, fixed left sidebar still visible in the background.
Subject: Preview/diff/backup workflow for a manageable artifact.
Layout: Background active section "AI Control Center" with artifact table. Center modal title "Preview clean" or "Edit artifact", close button "Close". Modal body contains a preformatted diff or textarea, a note "Backup will be created before execution.", and button "Execute with backup" or "Apply with backup". Use masked path `/Users/<user>/Library/Application Support/Code/User/globalStorage/cache`. Keep actions clearly local-server only.
Style: Careful security admin modal, dark panel, emerald confirm, rose destructive accent, muted text.
Composition: Modal centered and dominant; background table still recognizable.
Quality constraints: No real data, no token strings, no exploit text.
```

## Prompt 18 - HTML report, Storage and Cleanup

```text
Use case: ui-mockup
Asset type: standalone HTML report screenshot
Primary request: Generate Quietscope's "Storage & Reclaimable Caches" report section.
Scene/backdrop: Dark standalone report window with Quietscope sidebar.
Subject: Storage hygiene and safe cleanup candidates.
Layout: Sidebar active item "Storage & Cleanup". Main title "Storage & Reclaimable Caches". Highlight box explaining logs, temporary models, and redundant indexes safe for removal. A grid of cards for cleanup candidates with titles as masked paths, each showing Cache folder size, Evaluated cleanup risk, Auto-fixable, Clean trigger cause. Examples: Xcode DerivedData 2.4 GiB, Ollama old model cache 5.1 GiB manual-only, npm cache 720 MiB, local logs 180 MiB. In local-server mode, include small rose buttons "Delete Cache"; otherwise show manual-only/disabled state. Summary visual should imply safe dry-run first.
Style: Calm storage dashboard, not destructive, emerald safe labels, amber manual-review labels.
Composition: Cards fill main area, sidebar visible.
Quality constraints: Keep cleanup framed as safe dry-run and backup-aware.
```

## Prompt 19 - HTML report, Privacy Masking enabled

```text
Use case: ui-mockup
Asset type: share-safe documentation screenshot
Primary request: Generate Quietscope's report with Privacy Masking enabled for a shareable screenshot.
Scene/backdrop: Dark report UI inside a centered window.
Subject: Privacy-safe local audit report.
Layout: Sidebar footer has "Privacy Masking" toggle switched on and "Offline Local Audit". Main section can be Dashboard Summary or Security Findings. Any paths and hostnames are masked: `/Users/<user>/Projects/<project>`, hostname `<hidden>`, project root `<project>`. Header has "Quietscope Audit Report", Copy Summary, Save to PDF. Show risk gauge 18/100, Findings 18, AI Risks 3, Reclaimable Space 1.2 GiB. Include a small visible note or tooltip-like label "Paths masked for safe sharing" without making it a marketing banner.
Style: Same premium dark report, but with privacy state emphasized by emerald toggle and masked text.
Composition: Make the privacy toggle and masked paths easy to notice.
Quality constraints: No real names, hostnames, API keys, or unmasked filesystem paths.
```

## Prompt 20 - Product overview composite

```text
Use case: ui-mockup
Asset type: hero/product overview image for README or website
Primary request: Generate a tasteful composite showing Quietscope's three main surfaces together: Wails desktop app, local web controller, and standalone HTML report.
Scene/backdrop: Deep blue-black background with subtle emerald/cyan ambient glow, no abstract orbs. Three overlapping windows arranged in depth, all readable enough to recognize.
Subject: Quietscope privacy-first local security audit suite.
Layout: Front window: standalone HTML report Dashboard Summary with risk gauge 18/100 and sidebar. Left/back window: Wails desktop app running an audit with console logs and audit configuration sidebar. Right/back window: local web controller with status cards and AI Control Center table. Include shield logo and title Quietscope in each window where appropriate. Add one small caption inside the image: "Local-only defensive audit".
Style: Premium product mockup, clean UI, realistic macOS/browser windows, emerald and cyan accents.
Composition: UI windows are the main subject; background is minimal and unobtrusive.
Quality constraints: No people, no cloud icons, no scary hacker imagery, no unreadable walls of text.
```
