package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"

	"github.com/hemp-dev/quietscope/internal/audit"
)

func WriteHTML(path string, report audit.Report) error {
	data, err := safeJSONForScript(report)
	if err != nil {
		return err
	}
	tpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}
	var b bytes.Buffer
	view := struct {
		Title string
		JSON  template.JS
	}{
		Title: "Quietscope Audit Report",
		JSON:  data,
	}
	if err := tpl.Execute(&b, view); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func safeJSONForScript(report audit.Report) (template.JS, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return "", err
	}
	return template.JS(b.String()), nil
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #090d10;
  --panel: #111820;
  --panel-hover: #17202c;
  --border: #1e293b;
  --border-focus: #10b981;
  --fg: #f8fafc;
  --muted: #94a3b8;
  --accent: #10b981;
  --accent-glow: rgba(16, 185, 129, 0.15);
  --accent-2: #3b82f6;
  --accent-2-glow: rgba(59, 130, 246, 0.15);
  
  --bad: #f43f5e;
  --bad-glow: rgba(244, 63, 94, 0.15);
  --warn: #f59e0b;
  --warn-glow: rgba(245, 158, 11, 0.15);
  --ok: #10b981;
  --ok-glow: rgba(16, 185, 129, 0.15);
  --info: #64748b;
  --info-glow: rgba(100, 116, 139, 0.15);
  
  --sidebar-w: 260px;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #f8fafc;
    --panel: #ffffff;
    --panel-hover: #f1f5f9;
    --border: #e2e8f0;
    --border-focus: #059669;
    --fg: #0f172a;
    --muted: #475569;
    --accent: #059669;
    --accent-glow: rgba(5, 150, 105, 0.1);
    --accent-2: #2563eb;
    --accent-2-glow: rgba(37, 99, 235, 0.1);
    
    --bad: #e11d48;
    --bad-glow: rgba(225, 29, 72, 0.1);
    --warn: #d97706;
    --warn-glow: rgba(217, 119, 6, 0.1);
    --ok: #059669;
    --ok-glow: rgba(5, 150, 105, 0.1);
    --info: #475569;
    --info-glow: rgba(71, 85, 105, 0.1);
  }
}

* { box-sizing: border-box; scroll-behavior: smooth; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: var(--font);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

.app-container {
  display: flex;
  min-height: 100vh;
}

/* Sidebar navigation */
aside.sidebar {
  width: var(--sidebar-w);
  border-right: 1px solid var(--border);
  background: var(--panel);
  position: fixed;
  top: 0;
  bottom: 0;
  left: 0;
  display: flex;
  flex-direction: column;
  padding: 24px 16px;
  z-index: 100;
}

.logo-area {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 32px;
}

.logo-area svg {
  color: var(--accent);
}

.logo-area h2 {
  font-size: 18px;
  margin: 0;
  font-weight: 700;
  letter-spacing: -0.5px;
}

.nav-links {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 1;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  color: var(--muted);
  text-decoration: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  transition: all 0.2s ease;
}

.nav-link:hover {
  background: var(--panel-hover);
  color: var(--fg);
}

.nav-link.active {
  background: var(--accent-glow);
  color: var(--accent);
}

.sidebar-footer {
  border-top: 1px solid var(--border);
  padding-top: 16px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* Privacy Toggle Switch */
.privacy-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  padding: 8px;
  background: var(--panel-hover);
  border: 1px solid var(--border);
  border-radius: 8px;
  user-select: none;
}

.privacy-toggle input {
  display: none;
}

.privacy-toggle .slider {
  position: relative;
  width: 36px;
  height: 20px;
  background-color: var(--border);
  border-radius: 20px;
  transition: .3s;
}

.privacy-toggle .slider::before {
  position: absolute;
  content: "";
  height: 14px;
  width: 14px;
  left: 3px;
  bottom: 3px;
  background-color: var(--fg);
  border-radius: 50%;
  transition: .3s;
}

.privacy-toggle input:checked + .slider {
  background-color: var(--accent);
}

.privacy-toggle input:checked + .slider::before {
  transform: translateX(16px);
}

.privacy-toggle span.label {
  font-size: 12px;
  font-weight: 600;
  color: var(--fg);
}

.offline-notice {
  font-size: 11px;
  color: var(--muted);
  text-align: center;
  background: rgba(127,127,127,0.05);
  border-radius: 6px;
  padding: 4px;
}

/* Main Content Area */
main.main-content {
  margin-left: var(--sidebar-w);
  flex: 1;
  padding: 40px 48px;
  max-width: 1400px;
}

header.content-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  border-bottom: 1px solid var(--border);
  padding-bottom: 24px;
  margin-bottom: 32px;
}

.header-titles h1 {
  margin: 0 0 6px 0;
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -0.75px;
}

.header-titles p.sub {
  margin: 0;
  color: var(--muted);
  font-size: 14px;
}

.header-actions {
  display: flex;
  gap: 12px;
}

button.btn {
  font-family: inherit;
  font-size: 13px;
  font-weight: 600;
  padding: 10px 16px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s ease;
  border: 1px solid var(--border);
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

button.btn.primary {
  background: var(--accent);
  color: var(--bg);
  border-color: var(--accent);
}

button.btn.primary:hover {
  filter: brightness(1.1);
  box-shadow: 0 0 10px var(--accent-glow);
}

button.btn.secondary {
  background: var(--panel);
  color: var(--fg);
}

button.btn.secondary:hover {
  background: var(--panel-hover);
}

/* Dashboard summary and layout */
section {
  margin-bottom: 48px;
  scroll-margin-top: 40px;
}

h2.section-title {
  font-size: 20px;
  font-weight: 700;
  margin: 0 0 20px 0;
  letter-spacing: -0.5px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 24px;
  margin-bottom: 32px;
}

.gauge-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
}

.gauge-card-title {
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--muted);
  font-weight: 700;
}

.gauge-holder {
  position: relative;
  width: 140px;
  height: 140px;
}

.gauge-holder svg {
  transform: rotate(-90deg);
}

.gauge-holder .bg-ring {
  fill: none;
  stroke: var(--border);
  stroke-width: 8px;
}

.gauge-holder .fill-ring {
  fill: none;
  stroke: var(--accent);
  stroke-width: 8px;
  stroke-linecap: round;
  stroke-dasharray: 376.99;
  stroke-dashoffset: 376.99;
  transition: stroke-dashoffset 1s ease-out, stroke 0.3s;
}

.gauge-val-area {
  position: absolute;
  top: 0; left: 0; width: 100%; height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.gauge-val-num {
  font-size: 28px;
  font-weight: 800;
}

.gauge-val-lbl {
  font-size: 10px;
  color: var(--muted);
  text-transform: uppercase;
  font-weight: 700;
}

.gauge-card-footer {
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid currentColor;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.stat-card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 20px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  transition: all 0.2s ease;
}

.stat-card:hover {
  border-color: var(--muted);
  transform: translateY(-2px);
}

.stat-card span.label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.stat-card b.val {
  font-size: 22px;
  font-weight: 700;
  margin-top: 8px;
  display: block;
}

/* Simulator and Checklist styling */
.simulator-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 40px;
}

.simulator-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.simulator-info h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 700;
}

.simulator-info p {
  margin: 0;
  color: var(--muted);
  font-size: 13px;
}

.sim-progress-box {
  background: rgba(127,127,127,0.03);
  border: 1px solid var(--border);
  padding: 16px;
  border-radius: 12px;
}

.sim-score-bar-lbl {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
  font-weight: 700;
  margin-bottom: 8px;
}

.sim-bar-outer {
  height: 10px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 99px;
  overflow: hidden;
}

.sim-bar-inner {
  height: 100%;
  width: 0%;
  background: linear-gradient(90deg, var(--accent), var(--accent-2));
  transition: width 0.4s ease;
}

.checklist-scroll {
  max-height: 280px;
  overflow-y: auto;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--bg);
}

.checklist-row {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.2s;
}

.checklist-row:hover {
  background: rgba(255,255,255,0.02);
}

.checklist-row:last-child {
  border-bottom: none;
}

.checklist-row input[type="checkbox"] {
  margin-top: 4px;
  accent-color: var(--accent);
  cursor: pointer;
}

.checklist-text {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.checklist-title {
  font-size: 13px;
  font-weight: 700;
}

.checklist-rec {
  font-size: 11px;
  color: var(--muted);
}

/* Control Toolbar styles */
.filter-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 24px;
  align-items: flex-end;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 1;
  min-width: 140px;
}

.filter-group label {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  color: var(--muted);
}

.filter-group input,
.filter-group select {
  min-height: 38px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--fg);
  padding: 8px 12px;
  font-family: inherit;
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}

.filter-group input:focus,
.filter-group select:focus {
  border-color: var(--border-focus);
}

.filter-checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  user-select: none;
  min-height: 38px;
  padding-bottom: 2px;
}

.filter-checkbox-label input {
  accent-color: var(--accent);
}

/* Tables and Data panels */
.table-container {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 24px;
}

.responsive-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}

.responsive-table th,
.responsive-table td {
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}

.responsive-table th {
  font-size: 11px;
  text-transform: uppercase;
  font-weight: 700;
  color: var(--muted);
  background: rgba(127,127,127,0.02);
  cursor: pointer;
  user-select: none;
}

.responsive-table tr:last-child td {
  border-bottom: none;
}

/* Details and Accordions */
details.evidence-box {
  margin-top: 6px;
}

details.evidence-box summary {
  font-size: 12px;
  font-weight: 700;
  color: var(--accent-2);
  cursor: pointer;
  outline: none;
  user-select: none;
}

details.evidence-box pre {
  margin-top: 8px;
  margin-bottom: 0;
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 12px;
  border-radius: 8px;
  font-family: monospace;
  font-size: 12px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--fg);
}

/* Custom visual badges */
.badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  padding: 3px 10px;
  border-radius: 99px;
  border: 1px solid currentColor;
}

.badge.critical, .badge.high, .badge.FAIL {
  color: var(--bad);
  background: var(--bad-glow);
}

.badge.medium, .badge.warn, .badge.WARN {
  color: var(--warn);
  background: var(--warn-glow);
}

.badge.low, .badge.info, .badge.INFO {
  color: var(--accent-2);
  background: var(--accent-2-glow);
}

.badge.pass, .badge.PASS {
  color: var(--ok);
  background: var(--ok-glow);
}

.badge.skipped {
  color: var(--info);
  background: var(--info-glow);
}

/* General Layout helpers */
.section-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
}

.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
}

.card h3 {
  margin: 0 0 12px 0;
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.25px;
}

.card pre {
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 12px;
  border-radius: 8px;
  font-family: monospace;
  font-size: 11px;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-x: auto;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: var(--muted);
  font-size: 13px;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
}

.highlight-box {
  border-left: 4px solid var(--accent);
  background: var(--panel);
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  border-right: 1px solid var(--border);
  padding: 14px 18px;
  border-radius: 0 8px 8px 0;
  font-size: 13px;
  margin-bottom: 24px;
}

.noscript-box {
  background: var(--bad-glow);
  color: var(--bad);
  border: 1px solid var(--bad);
  padding: 14px;
  border-radius: 8px;
  font-weight: 700;
  margin-bottom: 24px;
  text-align: center;
}

/* PDF/Print optimizations */
@media print {
  aside.sidebar,
  .filter-toolbar,
  .simulator-section,
  .header-actions,
  details.evidence-box summary {
    display: none !important;
  }
  
  body {
    background: #ffffff !important;
    color: #000000 !important;
  }
  
  main.main-content {
    margin-left: 0 !important;
    padding: 0 !important;
  }
  
  .table-container,
  .card {
    border-color: #000000 !important;
    page-break-inside: avoid;
  }
  
  details.evidence-box pre {
    display: block !important;
    border-color: #000000 !important;
    color: #000000 !important;
  }
}

/* Tablet & Mobile responsive layout */
@media (max-width: 960px) {
  aside.sidebar {
    width: 100%;
    position: relative;
    border-right: none;
    border-bottom: 1px solid var(--border);
    bottom: auto;
    padding: 16px;
  }
  
  .app-container {
    flex-direction: column;
  }
  
  main.main-content {
    margin-left: 0;
    padding: 24px;
  }
  
  .dashboard-grid,
  .simulator-section {
    grid-template-columns: 1fr;
  }
}
</style>
</head>
<body>

<noscript>
  <div class="noscript-box">
    JavaScript is disabled. The JSON data remains fully embedded in this document. Enable JavaScript for full dashboard rendering, dynamic filters, and Privacy Mode.
  </div>
</noscript>

<div class="app-container">
  <!-- Sidebar Navigation -->
  <aside class="sidebar">
    <div class="logo-area">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <h2>Quietscope</h2>
    </div>
    
    <nav class="nav-links">
      <a href="#dashboard" class="nav-link active" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        Dashboard Swell
      </a>
      <a href="#findings" class="nav-link" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Security Findings
      </a>
      <a href="#ai-security" class="nav-link" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
        AI Security Hardening
      </a>
      <a href="#ai-context" class="nav-link" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
        AI Context Inventory
      </a>
      <a href="#ai-catalog" class="nav-link" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        AI Tool Catalog
      </a>
      <a href="#cleanup" class="nav-link" onclick="activateLink(this)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
        Storage & Cleanup
      </a>
    </nav>
    
    <div class="sidebar-footer">
      <label class="privacy-toggle" title="Dynamically mask all user paths, project roots, and system hostnames for safe sharing">
        <span class="label">Privacy Masking</span>
        <input id="privacy" type="checkbox">
        <span class="slider"></span>
      </label>
      <div class="offline-notice">Local Offline Audit Only</div>
    </div>
  </aside>

  <!-- Main Content View -->
  <main class="main-content">
    <header class="content-header">
      <div class="header-titles">
        <h1 id="main-title">Quietscope Audit Report</h1>
        <p class="sub">Defensive user-space analysis. No external APIs, uploads, or trackers.</p>
      </div>
      <div class="header-actions">
        <button id="copy" type="button" class="btn secondary" title="Copy clean summary block to clipboard">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          Copy Summary
        </button>
        <button id="print" type="button" class="btn primary" title="Print document or compile to standalone offline PDF">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/></svg>
          Save to PDF
        </button>
      </div>
    </header>

    <!-- Dashboard Panel -->
    <section id="dashboard">
      <h2 class="section-title">Security Dashboard Summary</h2>
      
      <div class="dashboard-grid">
        <!-- SVG Gauge Card -->
        <div class="gauge-card">
          <span class="gauge-card-title">Risk Exposure</span>
          <div class="gauge-holder">
            <svg width="140" height="140">
              <circle cx="70" cy="70" r="60" class="bg-ring"></circle>
              <circle cx="70" cy="70" r="60" class="fill-ring" id="risk-gauge-fill"></circle>
            </svg>
            <div class="gauge-val-area">
              <span class="gauge-val-num" id="gauge-val-num">0</span>
              <span class="gauge-val-lbl">/ 100</span>
            </div>
          </div>
          <span class="gauge-card-footer" id="gauge-card-footer">-</span>
        </div>
        
        <!-- Statistics panel cards -->
        <div class="stats-grid" id="summary-stats-box">
          <!-- Dynamic contents will be inserted here -->
        </div>
      </div>

      <!-- Remediation Simulator (Checklist) -->
      <div class="simulator-section">
        <div class="simulator-info">
          <h3>Remediation Plan Simulator</h3>
          <p>Quietscope automatically converts security recommendations into an interactive checklist. Check off resolved recommendations to simulate your risk reduction in real time.</p>
          
          <div class="sim-progress-box">
            <div class="sim-score-bar-lbl">
              <span>Projected Score: <span id="projected-score-text">-</span></span>
              <span id="reduction-pct-text">0% Improved</span>
            </div>
            <div class="sim-bar-outer">
              <div class="sim-bar-inner" id="sim-progress-bar"></div>
            </div>
          </div>
        </div>
        <div class="checklist-scroll" id="remediation-checklist-box">
          <!-- Populated dynamically -->
        </div>
      </div>
    </section>

    <!-- Security Findings Table Panel -->
    <section id="findings">
      <h2 class="section-title">Defensive Audit Findings</h2>
      
      <div class="filter-toolbar">
        <div class="filter-group">
          <label for="search">Global Search</label>
          <input id="search" type="search" placeholder="Type key phrases...">
        </div>
        <div class="filter-group">
          <label for="severity">Severity</label>
          <select id="severity"><option value="">All Severities</option></select>
        </div>
        <div class="filter-group">
          <label for="category">Category</label>
          <select id="category"><option value="">All Categories</option></select>
        </div>
        <div class="filter-group">
          <label for="status">Verdict Status</label>
          <select id="status"><option value="">All Statuses</option></select>
        </div>
        <div class="filter-group">
          <label for="special">Quick Filters</label>
          <select id="special">
            <option value="">No Filter</option>
            <option value="cleanup">Cleanup Candidates</option>
            <option value="ai">AI / Agent Risks</option>
            <option value="secrets">Secrets Exposure</option>
          </select>
        </div>
      </div>

      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th data-sort="severity" style="width: 130px;">Severity</th>
              <th data-sort="status" style="width: 120px;">Status</th>
              <th data-sort="category" style="width: 140px;">Category</th>
              <th data-sort="title">Title</th>
              <th>Technical Details</th>
            </tr>
          </thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>
    </section>

    <!-- AI Security Hardening Recommendations -->
    <section id="ai-security">
      <h2 class="section-title">AI Local Security & Hardening</h2>
      <div class="highlight-box">
        AI security checks audit the security stance of locally installed LLM/agent tools (e.g. Cursor, Ollama, Wails, local shell integrations, MCP clients) and highlight hardening opportunities.
      </div>
      <div id="ai-security-grid" class="section-cards"></div>
    </section>

    <!-- AI Context Inventory Section -->
    <section id="ai-context">
      <h2 class="section-title">AI Skills & Context Inventory</h2>
      <div class="highlight-box">
        Estimates the likelihood of local directories or files being auto-loaded by LLMs or developers into agent prompts. It highlights data boundaries rather than proving malice.
      </div>
      <div class="stats-grid" id="ai-context-summary-box" style="margin-bottom: 24px;"></div>
      
      <div class="filter-toolbar">
        <div class="filter-group">
          <label for="ai-tool">AI Agent Tool</label>
          <select id="ai-tool"><option value="">All Tools</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-dir-category">Directory Type</label>
          <select id="ai-dir-category"><option value="">All Categories</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-artifact-type">Artifact Class</label>
          <select id="ai-artifact-type"><option value="">All Classes</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-scope">Access Scope</label>
          <select id="ai-scope"><option value="">All Scopes</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-impact">Context Impact</label>
          <select id="ai-impact"><option value="">All Impacts</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-auto">Auto-loaded Likelihood</label>
          <select id="ai-auto"><option value="">All Likelihoods</option></select>
        </div>
        <div class="filter-group">
          <label for="ai-cleanup">Cleanup Status</label>
          <select id="ai-cleanup">
            <option value="">All</option>
            <option value="true">Cleanup Candidates</option>
            <option value="false">Not Candidates</option>
          </select>
        </div>
        <div class="filter-group">
          <label for="ai-suspicious">Suspicious Skill Files</label>
          <select id="ai-suspicious">
            <option value="">All</option>
            <option value="true">Contains Patterns</option>
            <option value="false">No Patterns</option>
          </select>
        </div>
        <div class="filter-group" style="flex: 2; min-width: 140px;">
          <label for="ai-size-min">Min Size (MiB)</label>
          <input id="ai-size-min" type="number" min="0" step="1">
        </div>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px;">AI-Related Directories Scanned</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th data-ai-dir-sort="tool">Tool</th>
              <th>Path</th>
              <th data-ai-dir-sort="category">Category</th>
              <th data-ai-dir-sort="size">Disk Size</th>
              <th>Files</th>
              <th data-ai-dir-sort="modified">Modified</th>
              <th data-ai-dir-sort="impact">Context Impact</th>
              <th>Score</th>
              <th>Cleanup</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody id="ai-dir-body"></tbody>
        </table>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-top: 32px; margin-bottom: 12px;">AI Instruction & Skill Files</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th data-ai-artifact-sort="tool">Tool</th>
              <th data-ai-artifact-sort="type">Type</th>
              <th>File Path</th>
              <th data-ai-artifact-sort="scope">Scope</th>
              <th>Size</th>
              <th>Permissions</th>
              <th data-ai-artifact-sort="auto">Auto-load</th>
              <th data-ai-artifact-sort="impact">Impact</th>
              <th>Suspicious Patterns</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody id="ai-artifact-body"></tbody>
        </table>
      </div>
    </section>

    <!-- AI Tools Catalog Panel -->
    <section id="ai-catalog">
      <h2 class="section-title">AI Tool Catalog & MCP Providers</h2>
      <div class="highlight-box">
        Identifies active, offline, and remote configurations, exposed local ports, environment variables, and MCP configurations. A catalog entry represents a discovery, not a threat vector.
      </div>
      
      <div class="stats-grid" id="ai-provider-summary-box" style="margin-bottom: 24px;"></div>

      <div class="filter-toolbar">
        <div class="filter-group">
          <label for="catalog-category">Tool Category</label>
          <select id="catalog-category"><option value="">All Categories</option></select>
        </div>
        <div class="filter-group">
          <label for="catalog-vendor">Vendor / Provider</label>
          <select id="catalog-vendor"><option value="">All Vendors</option></select>
        </div>
        <div class="filter-group">
          <label for="provider-family">Model Family</label>
          <select id="provider-family"><option value="">All Families</option></select>
        </div>
        <div class="filter-group">
          <label for="china-origin">China-origin Vendor</label>
          <select id="china-origin">
            <option value="">All</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </div>
        <div class="filter-group">
          <label for="provider-env">Exposes Env Key</label>
          <select id="provider-env">
            <option value="">All</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </div>
        <div class="filter-group">
          <label for="catalog-mcp">Contains MCP Tools</label>
          <select id="catalog-mcp">
            <option value="">All</option>
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </div>
        <div class="filter-group" style="flex: 2; min-width: 140px;">
          <label for="catalog-size-min">Min Size (MiB)</label>
          <input id="catalog-size-min" type="number" min="0" step="1">
        </div>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px;">Detected Local AI Tools</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th>Tool Name</th>
              <th>Vendor</th>
              <th>Categories</th>
              <th>Paths / Executables</th>
              <th>Configurations</th>
              <th>Caches / Logs</th>
              <th>Disk Usage</th>
              <th>Ports</th>
              <th>Security Risks</th>
            </tr>
          </thead>
          <tbody id="ai-tool-catalog-body"></tbody>
        </table>
      </div>

      <!-- Specialized Local Agents details -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 32px; margin-bottom: 32px;">
        <div class="card" id="hermes-card">
          <h3>Hermes Deep-Agent Status</h3>
          <div id="hermes-section"></div>
        </div>
        <div class="card" id="opencode-card">
          <h3>OpenCode Workspace Status</h3>
          <div id="opencode-section"></div>
        </div>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-bottom: 12px;">MCP (Model Context Protocol) Integration</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th>Server</th>
              <th>Risk Category</th>
              <th>Scope</th>
              <th>Config Path</th>
              <th>Command Executed</th>
              <th>Loaded Env Keys</th>
              <th>Capabilities Checked</th>
              <th>Remediation Recommendation</th>
            </tr>
          </thead>
          <tbody id="mcp-server-body"></tbody>
        </table>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-top: 32px; margin-bottom: 12px;">Chinese AI SDKs & Providers</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th>Provider</th>
              <th>Vendor</th>
              <th>Families</th>
              <th>Keys Detected</th>
              <th>SDK Configs</th>
              <th>Local Caches</th>
              <th>Cache Size</th>
              <th>Security Level</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody id="chinese-provider-body"></tbody>
        </table>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-top: 32px; margin-bottom: 12px;">Local LLM Model Inventories</h3>
      <div class="table-container">
        <table class="responsive-table">
          <thead>
            <tr>
              <th>Model Hub</th>
              <th>Provider Hint</th>
              <th>Storage Directory</th>
              <th>Size</th>
              <th>Files</th>
              <th>Modified</th>
              <th>Safe to Clean</th>
              <th>Storage Actions</th>
            </tr>
          </thead>
          <tbody id="local-model-body"></tbody>
        </table>
      </div>

      <h3 style="font-size: 15px; font-weight: 700; margin-top: 32px; margin-bottom: 12px;">Local AI Defensive Scanning Tools</h3>
      <div id="ai-security-tools-section" class="section-cards"></div>
    </section>

    <!-- Storage and Cleanup Candidates -->
    <section id="cleanup">
      <h2 class="section-title">Storage & Reclaimable Caches</h2>
      <div class="highlight-box">
        Identifies logs, temporary models, and redundant indexes safe for removal. Removing these directories will not impact system stability.
      </div>
      <div id="cleanup-section" class="section-cards"></div>
    </section>
  </main>
</div>

<!-- Embedded JSON Payload -->
<script type="application/json" id="audit-data">{{.JSON}}</script>

<script>
(function() {
  "use strict";

  const raw = document.getElementById("audit-data").textContent;
  const data = JSON.parse(raw);

  // App Client State
  const state = {
    sort: "severity",
    dir: 1,
    aiDirSort: "size",
    aiDirDir: -1,
    aiArtifactSort: "impact",
    aiArtifactDir: -1,
    resolvedFindings: new Set()
  };

  const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const impactOrder = { critical: 5, high: 4, medium: 3, low: 2, none: 1 };

  const $ = (id) => document.getElementById(id);

  function text(value) { 
    return value === null || value === undefined ? "" : String(value); 
  }

  function bytes(n) { 
    if(!n) return "0 B"; 
    const u = ["B", "KiB", "MiB", "GiB", "TiB"]; 
    let i = 0, v = Number(n); 
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; } 
    return (i ? v.toFixed(1) : v.toFixed(0)) + " " + u[i]; 
  }

  // Dynamic Path & Data Masking
  function masked(s) { 
    s = text(s); 
    if (!$("privacy").checked) return s; 
    const root = text((data.metadata || {}).project_root); 
    if (root) { 
      s = s.split(root).join("<project>"); 
    } 
    return s.replace(/\/Users\/([^\/\s]+)/g, "/Users/<user>")
            .replace(/hostname: [^;\n]+/ig, "hostname: <hidden>")
            .replace(/"hostname"\s*:\s*"[^"]+"/ig, '"hostname":"<hidden>"'); 
  }

  // Radial Gauge Score Render
  function renderGaugeCircle(score) {
    const ring = $("risk-gauge-fill");
    const num = $("gauge-val-num");
    const label = $("gauge-card-footer");
    if (!ring || !num || !label) return;

    // Circumference for r=60 is 2 * PI * 60 = 376.99
    const circumference = 376.99;
    const offset = circumference - (circumference * score) / 100;
    ring.style.strokeDashoffset = offset;
    num.textContent = Math.round(score);

    // Apply color gradient classes
    if (score > 70) {
      ring.style.stroke = "var(--bad)";
      label.textContent = "CRITICAL / HIGH RISK";
      label.style.color = "var(--bad)";
      label.style.borderColor = "var(--bad)";
    } else if (score > 35) {
      ring.style.stroke = "var(--warn)";
      label.textContent = "MEDIUM WARNING";
      label.style.color = "var(--warn)";
      label.style.borderColor = "var(--warn)";
    } else {
      ring.style.stroke = "var(--ok)";
      label.textContent = "SECURE / LOW RISK";
      label.style.color = "var(--ok)";
      label.style.borderColor = "var(--ok)";
    }
  }

  // Populate dynamic summary cards
  function renderSummary() {
    const s = data.summary || {}, m = data.metadata || {}, sys = data.system_info || {};
    const box = $("summary-stats-box");
    if (!box) return;
    box.innerHTML = "";

    const addStatCard = (label, val, styleClass) => {
      const d = document.createElement("div");
      d.className = "stat-card";
      d.innerHTML = '\n        <span class="label">' + label + '</span>\n        <b class="val ' + (styleClass || '') + '">' + val + '</b>\n      ';
      box.appendChild(d);
    };

    addStatCard("Risk Assessment Level", text(s.risk_level), text(s.risk_level).toLowerCase());
    addStatCard("Total Audit Findings", text(s.total_findings));
    addStatCard("High & Critical Issues", text((s.high_count || 0) + (s.critical_count || 0)), "bad");
    addStatCard("PASS / WARN / FAIL / INFO", [s.pass_count, s.warn_count, s.fail_count, s.info_count].join(" / "));
    addStatCard("Reclaimable Disk Caches", bytes(s.cleanup_reclaimable_bytes));
    addStatCard("Exposed AI Secrets / Credentials", text(s.secrets_exposure_count), s.secrets_exposure_count ? "warn" : "low");
    addStatCard("Audit Time Stamp", text(m.generated_at));
    addStatCard("Host Target OS", masked(sys.macos_version || sys.go_runtime_os || "unknown"));
    addStatCard("Hostname Node", $("privacy").checked ? "<hidden>" : text(sys.hostname || "unknown"));
  }

  // Remediation Plan checklist simulation
  window.toggleResolveFinding = function(id) {
    if (state.resolvedFindings.has(id)) {
      state.resolvedFindings.delete(id);
    } else {
      state.resolvedFindings.add(id);
    }
    updateProjectedScore();
  };

  function updateProjectedScore() {
    const originalScore = Number((data.summary || {}).overall_risk_score || 0);
    let scoreReduction = 0;
    
    (data.findings || []).forEach(f => {
      if (state.resolvedFindings.has(f.id)) {
        if (f.severity === "critical") scoreReduction += 25;
        else if (f.severity === "high") scoreReduction += 15;
        else if (f.severity === "medium") scoreReduction += 8;
        else scoreReduction += 3;
      }
    });

    const projectedScore = Math.max(0, originalScore - scoreReduction);
    const reductionPercent = originalScore > 0 ? Math.round((scoreReduction / originalScore) * 100) : 100;

    renderGaugeCircle(projectedScore);

    const projectedText = $("projected-score-text");
    const reductionText = $("reduction-pct-text");
    const bar = $("sim-progress-bar");

    if (projectedText) projectedText.textContent = projectedScore + " / 100";
    if (reductionText) reductionText.textContent = Math.min(100, reductionPercent) + "% Resolved";
    if (bar) bar.style.width = Math.min(100, reductionPercent) + "%";
  }

  function renderChecklist() {
    const box = $("remediation-checklist-box");
    if (!box) return;
    box.innerHTML = "";

    const list = (data.findings || []).filter(f => f.status === "FAIL" || f.status === "WARN" || f.severity === "critical" || f.severity === "high" || f.severity === "medium");

    if (!list.length) {
      box.innerHTML = "<div class='empty-state'>All metrics are clean. No simulated fixes required!</div>";
      return;
    }

    list.forEach(f => {
      const isChecked = state.resolvedFindings.has(f.id);
      const row = document.createElement("div");
      row.className = "checklist-row";
      row.innerHTML = '\n        <input type="checkbox" ' + (isChecked ? "checked" : "") + ' onclick="event.stopPropagation(); toggleResolveFinding(\'' + f.id + '\')">\n        <div class="checklist-text" onclick="toggleResolveFinding(\'' + f.id + '\')">\n          <span class="checklist-title">' + masked(f.title) + '</span>\n          <span class="checklist-rec">Recommendation: ' + masked(f.recommendation || 'Verify manual remediation.') + '</span>\n        </div>\n        <span class="badge ' + f.severity + '">' + f.severity + '</span>\n      ';
      box.appendChild(row);
    });
  }

  // Populate Dropdown Selection Menus
  function fillSelect(id, values) { 
    const el = $(id); 
    if(!el) return;
    // Clear dynamic options while preserving "All"
    while (el.options.length > 1) { el.remove(1); }
    
    Array.from(new Set(values.filter(Boolean))).sort().forEach(v => {
      const o = document.createElement("option"); 
      o.value = v; 
      o.textContent = v; 
      el.appendChild(o);
    }); 
  }

  fillSelect("severity", (data.findings || []).map(f => f.severity));
  fillSelect("category", (data.findings || []).map(f => f.category));
  fillSelect("status", (data.findings || []).map(f => f.status));
  fillSelect("ai-tool", (data.ai_context_inventory || []).map(a => a.tool_name).concat((data.ai_related_directories || []).map(d => d.tool_name)));
  fillSelect("ai-dir-category", (data.ai_related_directories || []).map(d => d.category));
  fillSelect("ai-artifact-type", (data.ai_context_inventory || []).map(a => a.artifact_type));
  fillSelect("ai-scope", (data.ai_context_inventory || []).map(a => a.scope));
  fillSelect("ai-impact", (data.ai_context_inventory || []).map(a => a.context_impact).concat((data.ai_related_directories || []).map(d => d.context_impact)));
  fillSelect("ai-auto", (data.ai_context_inventory || []).map(a => a.auto_loaded_likelihood));
  fillSelect("catalog-category", (data.ai_tool_catalog || []).flatMap(t => t.categories || []));
  fillSelect("catalog-vendor", (data.ai_tool_catalog || []).map(t => t.vendor).concat((data.chinese_ai_providers || []).map(p => p.vendor)));
  fillSelect("provider-family", (data.chinese_ai_providers || []).flatMap(p => p.families || []));

  // Multi-faceted search and dynamic filtering execution
  function getFilteredFindings() {
    const q = $("search").value.toLowerCase();
    const sev = $("severity").value;
    const cat = $("category").value;
    const st = $("status").value;
    const special = $("special").value;

    return (data.findings || []).filter(f => {
      const blob = JSON.stringify(f).toLowerCase();
      if (q && !blob.includes(q)) return false;
      if (sev && f.severity !== sev) return false;
      if (cat && f.category !== cat) return false;
      if (st && f.status !== st) return false;
      
      if (special === "cleanup" && !f.cleanup_candidate) return false;
      if (special === "ai" && !(f.category === "ai_security" || f.command_execution_risk || f.network_exfiltration_risk)) return false;
      if (special === "secrets" && !(f.category === "secrets" || f.data_exposure_risk)) return false;
      
      return true;
    }).sort((a, b) => {
      let av = a[state.sort], bv = b[state.sort];
      if (state.sort === "severity") { 
        av = severityOrder[av] || 0; 
        bv = severityOrder[bv] || 0; 
        return (bv - av) * state.dir; 
      }
      return text(av).localeCompare(text(bv)) * state.dir;
    });
  }

  function renderFindings() {
    const body = $("findings-body"); 
    if(!body) return;
    body.textContent = "";
    
    getFilteredFindings().forEach(f => {
      const tr = document.createElement("tr");
      
      // Severity column
      let td = document.createElement("td");
      td.innerHTML = '<span class="badge ' + f.severity + '">' + masked(f.severity) + '</span>';
      tr.appendChild(td);

      // Status column
      td = document.createElement("td");
      td.innerHTML = '<span class="badge ' + f.status + '">' + masked(f.status) + '</span>';
      tr.appendChild(td);

      // Category column
      td = document.createElement("td");
      td.innerHTML = '<span class="badge info">' + masked(f.category) + '</span>';
      tr.appendChild(td);

      // Title column
      td = document.createElement("td");
      td.style.fontWeight = "700";
      td.textContent = masked(f.title);
      tr.appendChild(td);

      // Accordion detail column
      td = document.createElement("td");
      const det = document.createElement("details");
      det.className = "evidence-box";
      const sum = document.createElement("summary");
      sum.textContent = "View Technical Trace & Guidance";
      const pre = document.createElement("pre");
      
      pre.textContent = [
        "Rule Signature ID: " + text(f.id),
        "Identified Evidence: " + masked(f.evidence),
        "Mitigation Remedy: " + masked(f.recommendation),
        "Command Evaluated: " + masked(f.command_checked),
        "Supports Auto-Fix: " + text(f.safe_to_auto_fix),
        "Removable Storage Trash: " + text(f.cleanup_candidate),
        "Reclaimable Bytes: " + bytes(f.estimated_size_bytes),
        "Risk Profiling: [Exfiltration: " + text(f.network_exfiltration_risk) + " | Secrets: " + text(f.data_exposure_risk) + " | Execution: " + text(f.command_execution_risk) + "]"
      ].join("\n");
      
      det.append(sum, pre); 
      td.appendChild(det); 
      tr.appendChild(td); 
      
      body.appendChild(tr);
    });
  }

  // Populate helper functions for generic JSON list displays
  function addGridCard(parent, title, lines) { 
    const d = document.createElement("div"); 
    d.className = "card"; 
    const h = document.createElement("h3"); 
    h.textContent = title; 
    const pre = document.createElement("pre"); 
    pre.textContent = masked(lines.join("\n")); 
    d.append(h, pre); 
    parent.appendChild(d); 
  }

  function renderAI() {
    const box = $("ai-security-grid"); 
    if(!box) return;
    box.textContent = ""; 
    const ai = data.ai_security || {};
    
    addGridCard(box, "Discovered AI Tools", (ai.installed_tools || []).map(t => text(t.name) + " | " + text(t.kind) + " | " + text(t.path)));
    addGridCard(box, "MCP Server Configurations Checked", (ai.mcp_configs || []).map(c => text(c.risk) + " | " + text(c.path) + " | " + text(c.server_name || "") + " | " + text(c.command || "") + " | " + text(c.description || "")));
    addGridCard(box, "Exposed AI Host Ports & API Bindings", (ai.local_servers || []).map(s => text(s.risk) + " | " + text(s.name) + " pid=" + text(s.pid) + " " + text(s.address) + ":" + text(s.port)));
    addGridCard(box, "Local Workspace Prompts Evaluated", (ai.prompt_artifacts || []).map(a => text(a.severity) + " | " + text(a.path) + ":" + text(a.line) + " | " + text(a.phrase)));
    addGridCard(box, "AI System Hardening Recommendations", ai.recommendations || []);
  }

  // AI Context directory filter checks
  function getFilteredContextDirs() {
    const tool = $("ai-tool").value;
    const cat = $("ai-dir-category").value;
    const impact = $("ai-impact").value;
    const cleanup = $("ai-cleanup").value;
    const min = Number($("ai-size-min").value || 0) * 1024 * 1024;

    return (data.ai_related_directories || []).filter(d => {
      if (tool && d.tool_name !== tool) return false;
      if (cat && d.category !== cat) return false;
      if (impact && d.context_impact !== impact) return false;
      if (cleanup && String(d.cleanup_candidate) !== cleanup) return false;
      if (min && Number(d.size_bytes || 0) < min) return false;
      return true;
    }).sort((a, b) => {
      let av, bv, key = state.aiDirSort;
      if (key === "size") { 
        av = Number(a.size_bytes || 0); 
        bv = Number(b.size_bytes || 0); 
        return (av - bv) * state.aiDirDir; 
      }
      if (key === "impact") { 
        av = impactOrder[a.context_impact] || 0; 
        bv = impactOrder[b.context_impact] || 0; 
        return (av - bv) * state.aiDirDir; 
      }
      if (key === "modified") { 
        av = Date.parse(a.last_modified || "") || 0; 
        bv = Date.parse(b.last_modified || "") || 0; 
        return (av - bv) * state.aiDirDir; 
      }
      av = key === "tool" ? a.tool_name : a.category; 
      bv = key === "tool" ? b.tool_name : b.category; 
      return text(av).localeCompare(text(bv)) * state.aiDirDir;
    });
  }

  // AI Context Artifacts filter checks
  function getFilteredContextArtifacts() {
    const tool = $("ai-tool").value;
    const type = $("ai-artifact-type").value;
    const scope = $("ai-scope").value;
    const impact = $("ai-impact").value;
    const auto = $("ai-auto").value;
    const suspicious = $("ai-suspicious").value;

    return (data.ai_context_inventory || []).filter(a => {
      if (tool && a.tool_name !== tool) return false;
      if (type && a.artifact_type !== type) return false;
      if (scope && a.scope !== scope) return false;
      if (impact && a.context_impact !== impact) return false;
      if (auto && a.auto_loaded_likelihood !== auto) return false;
      if (suspicious && String(Boolean((a.suspicious_patterns || []).length)) !== suspicious) return false;
      return true;
    }).sort((a, b) => {
      let av, bv, key = state.aiArtifactSort;
      if (key === "impact") { 
        av = impactOrder[a.context_impact] || 0; 
        bv = impactOrder[b.context_impact] || 0; 
        return (av - bv) * state.aiArtifactDir; 
      }
      av = key === "tool" ? a.tool_name : key === "type" ? a.artifact_type : key === "scope" ? a.scope : a.auto_loaded_likelihood;
      bv = key === "tool" ? b.tool_name : key === "type" ? b.artifact_type : key === "scope" ? b.scope : b.auto_loaded_likelihood;
      return text(av).localeCompare(text(bv)) * state.aiArtifactDir;
    });
  }

  function renderAIContext() {
    const sum = $("ai-context-summary-box"); 
    if(!sum) return;
    sum.textContent = ""; 
    const s = data.ai_context_summary || {};
    
    const addCtxCard = (label, val, cls) => {
      const d = document.createElement("div");
      d.className = "stat-card";
      d.innerHTML = '<span class="label">' + label + '</span><b class="val ' + (cls || '') + '">' + val + '</b>';
      sum.appendChild(d);
    };

    addCtxCard("AI Cache Directories", text(s.total_ai_directories));
    addCtxCard("AI Directories Disk Usage", bytes(s.total_ai_directory_size_bytes));
    addCtxCard("Identified prompt context artifacts", text(s.total_ai_context_artifacts));
    addCtxCard("Critical prompt context footprint", text(s.critical_context_impact_count), "bad");
    addCtxCard("High prompt context footprint", text(s.high_context_impact_count), "warn");
    addCtxCard("Writable prompt instruction files", text(s.world_writable_ai_artifacts_count), s.world_writable_ai_artifacts_count ? "bad" : "low");
    addCtxCard("Suspicious Prompt Injection Files", text(s.suspicious_ai_prompt_patterns_count), s.suspicious_ai_prompt_patterns_count ? "warn" : "low");

    const dirBody = $("ai-dir-body"); 
    if(dirBody) {
      dirBody.textContent = "";
      getFilteredContextDirs().forEach(d => {
        const tr = document.createElement("tr");
        [
          d.tool_name, 
          masked(d.path), 
          d.category, 
          bytes(d.size_bytes), 
          d.file_count, 
          d.last_modified, 
          d.context_impact, 
          d.context_impact_score, 
          d.cleanup_candidate, 
          masked(d.recommendation)
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        dirBody.appendChild(tr);
      });
    }

    const artifactBody = $("ai-artifact-body"); 
    if(artifactBody) {
      artifactBody.textContent = "";
      getFilteredContextArtifacts().forEach(a => {
        const tr = document.createElement("tr");
        const patternText = (a.suspicious_patterns || []).map(p => text(p.line) + ": " + text(p.pattern) + " | " + masked(p.snippet)).join("\n");
        [
          a.tool_name, 
          a.artifact_type, 
          masked(a.path), 
          a.scope, 
          bytes(a.size_bytes), 
          a.permissions, 
          a.auto_loaded_likelihood, 
          a.context_impact, 
          patternText || "none", 
          masked(a.recommendation)
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        artifactBody.appendChild(tr);
      });
    }
  }

  function renderAIToolCatalog() {
    const summaryBox = $("ai-provider-summary-box"); 
    if(!summaryBox) return;
    summaryBox.textContent = ""; 
    const s = data.ai_provider_summary || {};
    
    const addCatalogCard = (lbl, val, cls) => {
      const d = document.createElement("div");
      d.className = "stat-card";
      d.innerHTML = '<span class="label">' + lbl + '</span><b class="val ' + (cls || '') + '">' + val + '</b>';
      summaryBox.appendChild(d);
    };

    addCatalogCard("Detected Local AI Tools", text(s.total_ai_tools_detected));
    addCatalogCard("Exposed MCP Client instances", text(s.total_mcp_clients_detected));
    addCatalogCard("Configured MCP Servers", text(s.total_mcp_servers_detected));
    addCatalogCard("Hermes Agent status", s.hermes_detected ? "Configured" : "Not Found", s.hermes_detected ? "warn" : "low");
    addCatalogCard("OpenCode Workspace status", s.opencode_detected ? "Configured" : "Not Found", s.opencode_detected ? "warn" : "low");
    addCatalogCard("China-origin AI SDK Libraries", text(s.chinese_providers_detected), s.chinese_providers_detected ? "warn" : "low");
    addCatalogCard("Discovered Environment API keys", text(s.remote_provider_env_keys_detected), s.remote_provider_env_keys_detected ? "warn" : "low");
    addCatalogCard("Local LLM model Cache size", bytes(s.local_model_cache_size_bytes));
    addCatalogCard("Broad local host API servers", text(s.non_loopback_ai_servers), s.non_loopback_ai_servers ? "bad" : "low");

    const category = $("catalog-category").value; 
    const vendor = $("catalog-vendor").value; 
    const mcp = $("catalog-mcp").value; 
    const min = Number($("catalog-size-min").value || 0) * 1024 * 1024;
    
    const toolBody = $("ai-tool-catalog-body"); 
    if(toolBody) {
      toolBody.textContent = "";
      (data.ai_tool_catalog || []).filter(t => {
        if (category && !(t.categories || []).includes(category)) return false;
        if (vendor && t.vendor !== vendor) return false;
        if (mcp && String((t.categories || []).includes("mcp_client") || (t.categories || []).includes("mcp_server")) !== mcp) return false;
        if (min && Number(t.disk_usage_bytes || 0) < min) return false;
        return true;
      }).forEach(t => {
        const tr = document.createElement("tr");
        [
          t.display_name, 
          t.vendor, 
          (t.categories || []).join(", "), 
          masked([...(t.app_paths || []), ...(t.binary_paths || [])].join("\n")), 
          masked((t.config_paths || []).join("\n")), 
          masked([...(t.cache_paths || []), ...(t.log_paths || [])].join("\n")), 
          bytes(t.disk_usage_bytes), 
          (t.ports || []).join(", "), 
          (t.risk_notes || []).join("\n")
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        toolBody.appendChild(tr);
      });
    }

    const hermes = data.hermes_agent || {}; 
    const hermesBox = $("hermes-section"); 
    if(hermesBox) {
      hermesBox.textContent = "";
      if (hermes.detected) {
        addItem(hermesBox, "Configured Attributes", [
          "Auto-detected: True", 
          "Disk weight: " + bytes(hermes.size_bytes), 
          "Estimated Context Impact: " + text(hermes.context_impact || "none"), 
          "Loaded API keys: " + (hermes.env_keys_detected || []).join(", ")
        ]);
        addItem(hermesBox, "Identified File Paths", [...(hermes.config_paths || []), ...(hermes.skill_paths || []), ...(hermes.memory_paths || []), ...(hermes.command_paths || []), ...(hermes.cache_log_paths || [])]);
        addItem(hermesBox, "Hardening advice", hermes.recommendations || []);
      } else {
        hermesBox.innerHTML = "<div class='offline-notice'>No Hermes Agent workspace detected.</div>";
      }
    }

    const oc = data.opencode || {}; 
    const ocBox = $("opencode-section"); 
    if(ocBox) {
      ocBox.textContent = "";
      if (oc.detected) {
        addItem(ocBox, "Configured Attributes", [
          "Auto-detected: True", 
          "Disk weight: " + bytes(oc.size_bytes), 
          "Estimated Context Impact: " + text(oc.context_impact || "none"), 
          "Loaded API keys: " + (oc.env_keys_detected || []).join(", ")
        ]);
        addItem(ocBox, "Identified File Paths", [...(oc.app_paths || []), ...(oc.binary_paths || []), ...(oc.config_paths || []), ...(oc.agent_paths || []), ...(oc.prompt_rule_paths || []), ...(oc.cache_log_paths || [])]);
        addItem(ocBox, "Hardening advice", oc.recommendations || []);
      } else {
        ocBox.innerHTML = "<div class='offline-notice'>No OpenCode workspace artifacts found.</div>";
      }
    }

    const mcpBody = $("mcp-server-body"); 
    if(mcpBody) {
      mcpBody.textContent = "";
      (data.mcp_servers || []).filter(sv => !mcp || "true" === mcp).forEach(sv => {
        const risks = "Exec: " + text(sv.command_execution_risk) + " | Write: " + text(sv.filesystem_access_risk) + " | Net: " + text(sv.network_exfiltration_risk) + " | Key: " + text(sv.credential_access_risk) + " | Cloud: " + text(sv.cloud_access_risk) + " | Automation: " + text(sv.browser_automation_risk);
        const tr = document.createElement("tr");
        [
          sv.server_name, 
          sv.risk_category, 
          sv.scope, 
          masked(sv.config_path), 
          masked(sv.command), 
          (sv.env_keys_only || []).join(", "), 
          risks, 
          sv.recommendation
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        mcpBody.appendChild(tr);
      });
    }

    const family = $("provider-family").value; 
    const china = $("china-origin").value; 
    const hasEnv = $("provider-env").value;
    
    const providerBody = $("chinese-provider-body"); 
    if(providerBody) {
      providerBody.textContent = "";
      (data.chinese_ai_providers || []).filter(p => {
        if (vendor && p.vendor !== vendor) return false;
        if (family && !(p.families || []).includes(family)) return false;
        if (china && String(p.country_or_region === "China") !== china) return false;
        if (hasEnv && String(Boolean((p.env_keys_detected || []).length)) !== hasEnv) return false;
        return true;
      }).forEach(p => {
        const tr = document.createElement("tr");
        [
          p.display_name, 
          p.vendor, 
          (p.families || []).join(", "), 
          (p.env_keys_detected || []).join(", "), 
          masked((p.config_paths || []).join("\n")), 
          masked((p.cache_paths || []).join("\n")), 
          bytes(p.local_cache_size_bytes), 
          p.risk_level, 
          masked(p.recommendation)
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        providerBody.appendChild(tr);
      });
    }

    const modelBody = $("local-model-body"); 
    if(modelBody) {
      modelBody.textContent = "";
      (data.local_model_inventory || []).filter(m => !min || Number(m.size_bytes || 0) >= min).forEach(m => {
        const tr = document.createElement("tr");
        [
          m.tool_name, 
          m.provider_hint, 
          masked(m.path), 
          bytes(m.size_bytes), 
          m.file_count, 
          m.last_modified, 
          m.safe_to_auto_clean, 
          masked(m.recommendation)
        ].forEach(v => {
          const td = document.createElement("td"); 
          td.textContent = text(v); 
          tr.appendChild(td);
        });
        modelBody.appendChild(tr);
      });
    }

    const securityBox = $("ai-security-tools-section"); 
    if(securityBox) {
      securityBox.textContent = "";
      (data.ai_security_tools || []).forEach(t => addItem(securityBox, t.name, ["Positive Scanner Signal: " + text(t.positive_security_signal), ...(t.paths || []), ...(t.risk_notes || [])]));
      if (!(data.ai_security_tools || []).length) {
        addItem(securityBox, "AI Security Systems Evaluated", ["No local AI compliance policies configured."]);
      }
    }
  }

  function renderCleanup() {
    const box = $("cleanup-section"); 
    if(!box) return;
    box.textContent = "";
    (data.cleanup_candidates || []).forEach(c => addItem(box, c.path, ["Cache folder size: " + bytes(c.estimated_size_bytes), "Evaluated cleanup risk: " + text(c.risk), "Auto-fixable: " + text(c.safe_to_auto_fix), "Clean trigger cause: " + text(c.reason)]));
    if (!(data.cleanup_candidates || []).length) {
      addItem(box, "Local reclaimable caches", ["Zero unnecessary diagnostic caches identified."]);
    }
  }

  function addItem(parent, title, lines) { 
    const d = document.createElement("div"); 
    d.className = "card"; 
    const h = document.createElement("h3"); 
    h.textContent = title; 
    const pre = document.createElement("pre"); 
    pre.textContent = masked(lines.join("\n")); 
    d.append(h, pre); 
    parent.appendChild(d); 
  }

  function renderAll() { 
    renderSummary(); 
    renderFindings(); 
    renderAI(); 
    renderAIContext(); 
    renderAIToolCatalog(); 
    renderCleanup(); 
    renderChecklist();
  }

  // Event bindings
  const inputIds = [
    "search", "severity", "category", "status", "special", "privacy", 
    "ai-tool", "ai-dir-category", "ai-artifact-type", "ai-scope", 
    "ai-impact", "ai-auto", "ai-cleanup", "ai-suspicious", "ai-size-min", 
    "catalog-category", "catalog-vendor", "provider-family", "china-origin", 
    "provider-env", "catalog-mcp", "catalog-size-min"
  ];
  
  inputIds.forEach(id => {
    const el = $(id);
    if(el) el.addEventListener("input", renderAll);
  });

  // Table Sorting logic
  document.querySelectorAll("th[data-sort]").forEach(th => th.addEventListener("click", () => { 
    const key = th.getAttribute("data-sort"); 
    state.dir = state.sort === key ? -state.dir : 1; 
    state.sort = key; 
    renderFindings(); 
  }));
  
  document.querySelectorAll("th[data-ai-dir-sort]").forEach(th => th.addEventListener("click", () => { 
    const key = th.getAttribute("data-ai-dir-sort"); 
    state.aiDirDir = state.aiDirSort === key ? -state.aiDirDir : -1; 
    state.aiDirSort = key; 
    renderAIContext(); 
  }));
  
  document.querySelectorAll("th[data-ai-artifact-sort]").forEach(th => th.addEventListener("click", () => { 
    const key = th.getAttribute("data-ai-artifact-sort"); 
    state.aiArtifactDir = state.aiArtifactSort === key ? -state.aiArtifactDir : -1; 
    state.aiArtifactSort = key; 
    renderAIContext(); 
  }));

  $("print").addEventListener("click", () => window.print());
  
  $("copy").addEventListener("click", () => { 
    const s = data.summary || {}; 
    const summary = "quietscope " + text((data.metadata || {}).version) + 
                    ": risk " + text(s.overall_risk_score) + "/100 (" + text(s.risk_level) + 
                    "), findings " + text(s.total_findings) + ", cleanup " + bytes(s.cleanup_reclaimable_bytes); 
    if (navigator.clipboard) { 
      navigator.clipboard.writeText(summary).catch(() => window.prompt("Copy clean audit summary block:", summary)); 
    } else { 
      window.prompt("Copy clean audit summary block:", summary); 
    } 
  });

  // Keep sidebar links highlighted based on scrolling target
  window.activateLink = function(target) {
    document.querySelectorAll(".nav-link").forEach(a => a.classList.remove("active"));
    target.classList.add("active");
  };

  // Initial trigger
  renderAll();
})();
</script>
</body>
</html>`
