package ui

const LocalOnlyNotice = "The local UI binds to 127.0.0.1, launches local audits only, and never uploads reports or file contents."

const ControlDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:dark;--bg:#061018;--bg-2:#091723;--fg:#ecf6f1;--muted:#91a5ad;--muted-2:#647984;--panel:#0b1722;--panel-2:#101f2d;--panel-3:#142737;--line:#223747;--line-strong:#2f6177;--accent:#2ee98f;--accent-2:#35c7f4;--bad:#ff625d;--warn:#f5c15d;--ok:#35e28b;--shadow:0 22px 70px rgba(0,0,0,.34);--glow:0 0 0 1px rgba(46,233,143,.22),0 0 34px rgba(46,233,143,.1)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(circle at 18% -8%,rgba(46,233,143,.16),transparent 32rem),radial-gradient(circle at 88% 6%,rgba(53,199,244,.14),transparent 34rem),linear-gradient(180deg,#061018 0%,#07121b 48%,#050b12 100%);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;line-height:1.42}
button,input,select{font:inherit}
header{border-bottom:1px solid var(--line);background:rgba(7,18,27,.86);backdrop-filter:blur(16px);padding:18px 22px;position:sticky;top:0;z-index:10}
.top{display:grid;grid-template-columns:max-content minmax(0,1fr) max-content;align-items:center;gap:22px;max-width:1540px;margin:0 auto}
.brand{display:flex;align-items:center;gap:12px;padding-right:20px;border-right:1px solid var(--line)}
.brand-mark{inline-size:42px;block-size:42px;border:1px solid rgba(46,233,143,.7);border-radius:12px;background:linear-gradient(145deg,rgba(46,233,143,.22),rgba(53,199,244,.08));box-shadow:var(--glow);position:relative}
.brand-mark:before{content:"QS";position:absolute;inset:0;display:grid;place-items:center;color:var(--accent);font-weight:800;font-size:12px;letter-spacing:.08em}
.brand-name{font-size:18px;font-weight:800;line-height:1}
.brand-sub{color:var(--muted);font-size:12px;margin-top:4px}
.header-copy{min-width:0}
h1{font-size:22px;line-height:1.1;margin:0 0 6px;letter-spacing:0}
.sub{margin:0;color:var(--muted);font-size:13px;max-width:900px}
.header-badges{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap}
.trust{display:flex;align-items:center;gap:9px;border:1px solid rgba(46,233,143,.42);border-radius:8px;padding:7px 10px;color:var(--accent);background:rgba(46,233,143,.08);box-shadow:var(--glow);font-size:12px;white-space:nowrap}
.trust span{color:#a9f5cc;border-left:1px solid rgba(46,233,143,.35);padding-left:9px}
.version{border:1px solid var(--line-strong);border-radius:8px;padding:7px 10px;color:#9fe7ff;background:rgba(53,199,244,.08);white-space:nowrap;font-size:12px}
main{max-width:1540px;margin:0 auto;padding:18px 22px 32px;display:grid;grid-template-columns:minmax(320px,400px) minmax(0,1fr);gap:18px}
.rail,.workspace{min-width:0}
.panel{border:1px solid var(--line);background:linear-gradient(180deg,rgba(16,31,45,.88),rgba(9,23,35,.92));border-radius:8px;box-shadow:var(--shadow)}
.panel h2{font-size:15px;margin:0;padding:14px 14px 10px;border-bottom:1px solid var(--line)}
.panel-title{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px;border-bottom:1px solid var(--line)}
.panel-title h2{border:0;padding:0}
.lock-badge,.count-pill,.filter-chip{display:inline-flex;align-items:center;min-height:24px;border:1px solid var(--line);border-radius:999px;padding:3px 9px;color:var(--muted);background:rgba(255,255,255,.03);font-size:11px;white-space:nowrap}
.rail.locked{border-color:rgba(245,193,93,.52);box-shadow:0 0 0 1px rgba(245,193,93,.08),var(--shadow)}
.rail.locked .lock-badge{color:var(--warn);border-color:rgba(245,193,93,.55);background:rgba(245,193,93,.1)}
.form{padding:14px;display:grid;gap:12px}
.field{display:grid;gap:5px}
.field span,.check span{font-size:12px;color:var(--muted)}
.form-note{margin:0;border:1px solid rgba(46,233,143,.24);border-radius:6px;background:rgba(46,233,143,.06);color:#bff7d5;padding:8px 10px;font-size:12px}
.field input,.field select{width:100%;min-height:34px;border:1px solid var(--line);border-radius:6px;background:#07131d;color:var(--fg);padding:6px 8px}
.field input:focus,.field select:focus,.control-tools input:focus,.control-tools select:focus,textarea:focus{outline:1px solid rgba(53,199,244,.6);border-color:var(--accent-2)}
.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.check{display:flex;align-items:center;gap:8px;min-height:34px;border:1px solid var(--line);border-radius:6px;padding:6px 8px;background:rgba(255,255,255,.025)}
.check input{inline-size:16px;block-size:16px;accent-color:var(--accent)}
.check:has(input:checked){border-color:rgba(46,233,143,.38);background:rgba(46,233,143,.07)}
.actions{display:flex;gap:8px;flex-wrap:wrap}
button{min-height:36px;border:1px solid var(--line);border-radius:6px;background:linear-gradient(180deg,var(--panel-3),var(--panel-2));color:var(--fg);padding:7px 11px;cursor:pointer}
button:hover:not(:disabled){border-color:var(--line-strong);background:#152a3b}
button.primary{background:linear-gradient(180deg,#27d883,#0d8f5d);border-color:rgba(46,233,143,.72);color:#ecfff5;box-shadow:0 0 0 1px rgba(46,233,143,.18),0 14px 28px rgba(0,0,0,.25)}
button.danger{color:var(--bad)}
button:disabled,input:disabled,select:disabled,textarea:disabled{opacity:.52;cursor:not-allowed}
.notice{margin:0;padding:10px 14px;color:var(--muted);border-top:1px solid var(--line);font-size:12px}
.statusbar{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}
.metric{border:1px solid var(--line);background:linear-gradient(135deg,rgba(20,39,55,.95),rgba(8,20,31,.94));border-radius:8px;padding:13px;min-height:112px;display:grid;align-content:space-between;position:relative;overflow:hidden}
.metric:after{content:"";position:absolute;right:-24px;bottom:-28px;inline-size:90px;block-size:90px;border:1px solid rgba(53,199,244,.14);border-radius:50%}
.metric span{display:block;color:var(--muted);font-size:11px}
.metric b{display:block;font-size:24px;margin-top:6px;overflow-wrap:anywhere}
.metric em{display:block;color:var(--muted-2);font-style:normal;font-size:11px;margin-top:6px}
.metric.phase-card{grid-column:1/-1;min-height:54px;display:flex;align-items:center;justify-content:space-between;gap:12px;border-color:rgba(46,233,143,.35);background:linear-gradient(90deg,rgba(46,233,143,.12),rgba(53,199,244,.06))}
.layout{display:grid;grid-template-columns:minmax(280px,360px) minmax(0,1fr);gap:14px}
.jobs{overflow:auto;max-height:650px}
.job{width:100%;text-align:left;border:0;border-bottom:1px solid var(--line);border-radius:0;background:transparent;padding:12px;display:grid;gap:6px}
.job:hover,.job.active{background:rgba(53,199,244,.07)}
.job.active{box-shadow:inset 3px 0 0 var(--accent)}
.job strong{font-size:13px;overflow-wrap:anywhere}
.job small{color:var(--muted)}
.pill{display:inline-flex;align-items:center;justify-content:center;min-height:22px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:11px;width:max-content;background:rgba(255,255,255,.025)}
.completed{color:var(--ok);border-color:rgba(46,233,143,.35)}.running,.queued,.canceling{color:var(--accent-2);border-color:rgba(53,199,244,.42)}.failed,.canceled{color:var(--bad);border-color:rgba(255,98,93,.42)}
.running{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(53,199,244,.0)}50%{box-shadow:0 0 0 3px rgba(53,199,244,.12)}}
.detail{padding:14px;display:grid;gap:14px;min-height:420px}
.detail-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.detail-title{display:grid;gap:5px;min-width:0}
.detail-title strong{overflow-wrap:anywhere}
.phase-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.phase-step{border:1px solid var(--line);border-radius:6px;padding:8px;color:var(--muted);background:rgba(255,255,255,.025);font-size:11px;min-height:42px}
.phase-step.done{color:#bdf6d0;border-color:rgba(46,233,143,.35);background:rgba(46,233,143,.07)}
.phase-step.active{color:#bceeff;border-color:rgba(53,199,244,.55);background:rgba(53,199,244,.08)}
.progress-wrap{display:grid;gap:7px}
.progress-label{display:flex;justify-content:space-between;color:var(--muted);font-size:12px}
.progress{height:16px;border:1px solid var(--line);background:#06111a;border-radius:999px;overflow:hidden}
.bar{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .25s ease}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.meta div{border:1px solid var(--line);border-radius:6px;padding:8px;min-height:48px;overflow-wrap:anywhere;background:rgba(255,255,255,.025)}
.meta span{display:block;color:var(--muted);font-size:11px;margin-bottom:3px}
.log-wrap{border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#050d12}
.log-head{display:flex;justify-content:space-between;align-items:center;gap:10px;border-bottom:1px solid var(--line);padding:8px 10px;color:var(--muted);font-size:11px}
.log-head div{display:flex;gap:8px;flex-wrap:wrap}
.log{color:#d9f7df;min-height:210px;max-height:390px;overflow:auto;padding:10px;font-size:12px;white-space:pre-wrap}
.empty{color:var(--muted);padding:16px}
.control{margin-top:14px}
.control-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding:14px;border-bottom:1px solid var(--line)}
.control-head h2{border:0;padding:0}
.control-copy{margin:6px 0 0;color:var(--muted);font-size:12px;max-width:780px}
.control-tools{padding:12px;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;border-bottom:1px solid var(--line)}
.control-tools input,.control-tools select{width:100%;min-height:34px;border:1px solid var(--line);border-radius:6px;background:#07131d;color:var(--fg);padding:5px 7px}
.control-tools .active-filter{border-color:rgba(53,199,244,.62);color:#bceeff;background:rgba(53,199,244,.08)}
.control-scroll{overflow:auto}
.control-table{width:100%;border-collapse:collapse;font-size:12px}
.control-table th,.control-table td{border-bottom:1px solid var(--line);padding:9px;text-align:left;vertical-align:top}
.control-table th{color:var(--muted);font-size:11px}
.control-table tbody tr{cursor:pointer}
.control-table tbody tr:hover,.control-table tbody tr.selected{background:rgba(53,199,244,.06)}
.control-table tbody tr.selected{outline:1px solid rgba(46,233,143,.42);outline-offset:-1px}
.risk-badge{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:11px}
.risk-high,.risk-critical{color:var(--bad);border-color:rgba(255,98,93,.45);background:rgba(255,98,93,.08)}.risk-medium{color:var(--warn);border-color:rgba(245,193,93,.42);background:rgba(245,193,93,.08)}.risk-low{color:var(--ok);border-color:rgba(46,233,143,.36);background:rgba(46,233,143,.07)}
.path-cell{display:grid;gap:4px;min-width:260px}
.backup-hint{color:#aef4cd;font-size:11px}
.action-set{display:flex;gap:6px;flex-wrap:wrap;min-width:250px}
.action-btn{min-height:30px;padding:5px 9px;font-size:11px}
.action-btn[data-action="delete"]{color:var(--bad);border-color:rgba(255,98,93,.36)}
.action-btn[data-action="restore"]{color:#bff7d5;border-color:rgba(46,233,143,.36)}
.control-foot{display:flex;justify-content:space-between;gap:12px;padding:10px 14px;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.68);display:none;align-items:center;justify-content:center;padding:20px;z-index:20;backdrop-filter:blur(6px)}
.modal-card{width:min(920px,96vw);max-height:88vh;overflow:auto;background:linear-gradient(180deg,#0d1b28,#091622);border:1px solid var(--line-strong);border-radius:8px;box-shadow:0 30px 90px rgba(0,0,0,.56);padding:0}
.modal-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;padding:16px;border-bottom:1px solid var(--line)}
.modal-head h2{border:0;padding:0;font-size:19px}
.modal-kicker{color:var(--accent);font-size:11px;margin-bottom:4px}
.modal-body{padding:16px;display:grid;gap:14px}
.modal-copy{margin:0;color:var(--muted);font-size:12px}
.artifact-meta{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}
.artifact-meta div{border:1px solid var(--line);border-radius:6px;padding:8px;background:rgba(255,255,255,.025);min-width:0}
.artifact-meta span{display:block;color:var(--muted);font-size:10px;margin-bottom:4px}
.artifact-meta b{display:block;font-size:12px;overflow-wrap:anywhere}
.edit-label,.diff-label{color:var(--muted);font-size:12px}
.edit-area{width:100%;min-height:260px;background:#06111a;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:10px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;line-height:1.45}
.diff{white-space:pre-wrap;border:1px solid var(--line);border-radius:6px;background:#050d12;color:#d9f7df;padding:10px;max-height:380px;overflow:auto}
.modal-note{display:flex;justify-content:space-between;gap:12px;border:1px solid rgba(46,233,143,.35);border-radius:6px;background:rgba(46,233,143,.06);padding:10px 12px;color:#d9f7df;font-size:12px}
.modal-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.local-copy{color:var(--muted);font-size:11px}
@media (max-width:980px){.top,main,.layout{grid-template-columns:1fr}.brand{border-right:0;padding-right:0}.header-badges{justify-content:flex-start}.statusbar{grid-template-columns:repeat(2,minmax(0,1fr))}.jobs{max-height:320px}.artifact-meta{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:980px){.control-tools{grid-template-columns:1fr 1fr}}
@media (max-width:560px){header,main{padding-left:14px;padding-right:14px}.checks,.statusbar,.meta,.control-tools,.phase-strip,.artifact-meta{grid-template-columns:1fr}.version,.trust{width:max-content}.metric.phase-card{display:grid}}
</style>
</head>
<body>
<header>
  <div class="top">
    <div class="brand" aria-label="Quietscope local web controller">
      <div class="brand-mark" aria-hidden="true"></div>
      <div>
        <div class="brand-name">Quietscope</div>
        <div class="brand-sub">Local Web Controller</div>
      </div>
    </div>
    <div class="header-copy">
      <h1>macOS Security Audit</h1>
      <p class="sub">{{.Notice}}</p>
    </div>
    <div class="header-badges">
      <div class="trust">100% Local<span>No telemetry</span><span>No network calls</span></div>
      <div class="version">UI {{.Version}}</div>
    </div>
  </div>
</header>
<main>
  <aside id="audit-rail" class="rail panel">
    <div class="panel-title"><h2>Audit Control</h2><span id="audit-lock" class="lock-badge">Ready</span></div>
    <form id="audit-form" class="form">
      <p id="audit-lock-note" class="form-note">Loopback controller ready. All audit work stays on this machine.</p>
      <div class="checks" aria-label="Audit options">
        <label class="check"><input id="deep" type="checkbox"><span>Deep</span></label>
        <label class="check"><input id="ai-audit" type="checkbox" checked><span>AI audit</span></label>
        <label class="check"><input id="no-sudo" type="checkbox" checked><span>No sudo</span></label>
        <label class="check"><input id="clean-dry-run" type="checkbox"><span>Cleanup dry-run</span></label>
      </div>
      <div class="checks" aria-label="Report outputs">
        <label class="check"><input id="want-text" type="checkbox" checked><span>TXT</span></label>
        <label class="check"><input id="want-json" type="checkbox" checked><span>JSON</span></label>
        <label class="check"><input id="want-html" type="checkbox" checked><span>HTML</span></label>
      </div>
      <label class="field"><span>Output directory</span><input id="output-dir" type="text" autocomplete="off" placeholder="Default Desktop folder"></label>
      <label class="field"><span>Project root</span><input id="project-root" type="text" autocomplete="off" placeholder="Optional project path"></label>
      <label class="field"><span>Max file size MiB</span><input id="max-file-size-mb" type="number" min="1" step="1" value="5"></label>
      <div class="actions">
        <button id="start-audit" class="primary" type="submit">Start Audit</button>
        <button id="refresh" type="button">Refresh</button>
      </div>
    </form>
    <p class="notice">Cleanup confirmation remains CLI-only.</p>
  </aside>
  <section class="workspace">
    <div class="statusbar" id="statusbar"></div>
    <div class="layout">
      <section class="panel">
        <h2>Runs</h2>
        <div id="jobs" class="jobs"><div class="empty">No audits yet.</div></div>
      </section>
      <section class="panel">
        <h2>Run Detail</h2>
        <div id="detail" class="detail"><div class="empty">Select or start an audit.</div></div>
      </section>
    </div>
    <section class="panel control">
      <div class="control-head">
        <div>
          <h2>AI Control Center</h2>
          <p class="control-copy">Preview local artifact changes before applying them. Backups are created for write actions, and restore keeps rollback visible.</p>
        </div>
        <span id="artifact-count" class="count-pill">0 artifacts</span>
      </div>
      <div class="control-tools">
        <input id="artifact-search" type="search" placeholder="Search artifacts">
        <select id="artifact-tool"><option value="">All tools</option></select>
        <select id="artifact-kind"><option value="">All kinds</option></select>
        <select id="artifact-scope"><option value="">All scopes</option></select>
        <select id="artifact-action"><option value="">All actions</option><option value="available">Available</option><option value="blocked">Blocked</option></select>
      </div>
      <div class="control-scroll">
        <table class="control-table">
          <thead><tr><th>Tool</th><th>Kind</th><th>Scope</th><th>Risk</th><th>Path</th><th>Actions</th></tr></thead>
          <tbody id="artifacts"><tr><td colspan="6" class="empty">Run an AI audit to populate manageable artifacts.</td></tr></tbody>
        </table>
      </div>
      <div class="control-foot"><span>Actions are local-only. Preview first, backup before writes, restore from saved backups.</span><span id="artifact-filter-chip" class="filter-chip">All actions</span></div>
    </section>
  </section>
</main>
<div id="action-modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-card"><div class="modal-head"><div><div class="modal-kicker">Local-only action preview</div><h2 id="modal-title">Preview edit</h2></div><button id="modal-close" type="button">Close</button></div><div id="modal-body" class="modal-body"></div></div></div>
<script>
(function(){
  "use strict";
  const token = "{{.Token}}";
  sessionStorage.setItem("quietscope_ui_token", token);
  const state = { jobs: [], selected: "", artifacts: [], selectedArtifact: "", lastPreview: null };
  const activeStatuses = ["running","queued","canceling"];
  const $ = (id) => document.getElementById(id);
  function text(v){ return v === null || v === undefined || v === "" ? "-" : String(v); }
  function escapeHTML(v){ return text(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;"); }
  function jsArg(v){ return String(v||"").replace(/\\/g,"\\\\").replace(/'/g,"\\'"); }
  function cls(v){ return String(v||"").toLowerCase(); }
  function latestEvent(job){ const events = job.events || []; return events.length ? events[events.length - 1] : null; }
  function isActive(job){ return activeStatuses.includes(cls(job && job.status)); }
  function activeJob(){ return state.jobs.find(isActive); }
  function progress(job){
    const event = latestEvent(job);
    if(!event || !event.total) return cls(job.status) === "completed" ? 100 : 0;
    return Math.max(0, Math.min(100, Math.round((Number(event.completed || 0) / Number(event.total || 1)) * 100)));
  }
  function time(v){ if(!v || String(v).startsWith("0001-")) return "-"; const d = new Date(v); return Number.isNaN(d.getTime()) ? "-" : d.toLocaleString(); }
  function duration(job){
    const start = Date.parse(job.started_at || "");
    const end = Date.parse(job.finished_at || "");
    if(!start) return "-";
    const ms = (end || Date.now()) - start;
    if(ms < 1000) return ms + "ms";
    return (ms / 1000).toFixed(1) + "s";
  }
  function eventText(job){
    const event = latestEvent(job);
    return event ? [event.check_name,event.message,event.type].filter(Boolean).join(" ").toLowerCase() : "";
  }
  function phaseLabel(job){
    const status = cls(job && job.status);
    if(status === "queued") return "Queued";
    if(status === "canceling") return "Canceling";
    if(status === "completed") return "Completed";
    if(status === "failed") return "Failed";
    if(status === "canceled") return "Canceled";
    const raw = eventText(job);
    if(raw.includes("ai")) return "AI audit in progress";
    if(raw.includes("persist")) return "Persistence checks";
    if(raw.includes("cleanup") || raw.includes("storage")) return "Cleanup dry-run";
    if(raw.includes("report")) return "Writing report";
    if(raw.includes("system") || raw.includes("security")) return "System security";
    return status ? status.charAt(0).toUpperCase() + status.slice(1) : "Audit in progress";
  }
  function phaseIndex(job){
    const status = cls(job && job.status);
    if(status === "completed") return 4;
    const raw = eventText(job);
    if(raw.includes("cleanup") || raw.includes("storage") || raw.includes("report")) return 3;
    if(raw.includes("persist")) return 2;
    if(raw.includes("ai")) return 1;
    return 0;
  }
  function warningCount(job){
    return (job.events || []).filter(e=>/warn|warning/i.test([e.type,e.message,e.error].filter(Boolean).join(" "))).length;
  }
  function metric(label,value,klass,hint){
    const d = document.createElement("div"); d.className = "metric";
    const s = document.createElement("span"); s.textContent = label;
    const b = document.createElement("b"); b.textContent = text(value); if(klass) b.className = klass;
    d.append(s,b);
    if(hint){ const e = document.createElement("em"); e.textContent = hint; d.appendChild(e); }
    return d;
  }
  function renderAuditLock(){
    const job = activeJob();
    const locked = Boolean(job);
    const rail = $("audit-rail"), form = $("audit-form"), badge = $("audit-lock"), note = $("audit-lock-note");
    rail.classList.toggle("locked", locked);
    form.classList.toggle("is-locked", locked);
    badge.textContent = locked ? "Locked: " + phaseLabel(job) : "Ready";
    note.textContent = locked ? "Audit in progress. Setup controls are locked until this local run finishes." : "Loopback controller ready. All audit work stays on this machine.";
    form.querySelectorAll("input,select,button[type='submit']").forEach(el=>{ el.disabled = locked; });
  }
  function renderStatus(){
    const box = $("statusbar"); box.textContent = "";
    const total = state.jobs.length;
    const current = activeJob();
    const running = state.jobs.filter(isActive).length;
    const failed = state.jobs.filter(j=>cls(j.status) === "failed" || cls(j.status) === "canceled").length;
    const latest = state.jobs[0];
    box.append(metric("Total runs", total, "", "All local audit runs"));
    box.append(metric("Active", running, running ? "running" : "", running ? "Currently running" : "No active run"));
    box.append(metric("Failed/Canceled", failed, failed ? "failed" : "", failed ? "Requires attention" : "All clear"));
    box.append(metric("Latest score", latest && latest.summary ? latest.summary.overall_risk_score + "/100" : "-", "", latest && latest.summary ? text(latest.summary.risk_level) : "No completed score yet"));
    if(current){
      const phase = metric("Current phase", phaseLabel(current), "running", "Local-only audit in progress");
      phase.classList.add("phase-card");
      box.appendChild(phase);
    }
  }
  function renderJobs(){
    const box = $("jobs"); box.textContent = "";
    if(!state.jobs.length){ box.innerHTML = '<div class="empty">No audits yet.</div>'; return; }
    state.jobs.forEach(job=>{
      const btn = document.createElement("button");
      btn.type = "button"; btn.className = "job" + (job.id === state.selected ? " active" : "");
      btn.setAttribute("aria-pressed", job.id === state.selected ? "true" : "false");
      btn.addEventListener("click",async()=>{ state.selected = job.id; state.selectedArtifact = ""; await refreshArtifacts(); render(); });
      const title = document.createElement("strong"); title.textContent = job.id;
      const line = document.createElement("small"); line.textContent = time(job.created_at) + " | " + text(job.output_dir);
      const pill = document.createElement("span"); pill.className = "pill " + cls(job.status); pill.textContent = text(job.status);
      const phase = document.createElement("small"); phase.textContent = phaseLabel(job);
      btn.append(title,pill,phase,line); box.appendChild(btn);
    });
  }
  function eventLine(event){
    const at = event.started_at && !String(event.started_at).startsWith("0001-") ? new Date(event.started_at) : null;
    const stamp = at && !Number.isNaN(at.getTime()) ? at.toLocaleTimeString() + " " : "";
    const prefix = event.type ? "[" + event.type + "] " : "";
    const check = event.check_name ? event.check_name + " " : "";
    const count = event.total ? "(" + Number(event.completed || 0) + "/" + event.total + ") " : "";
    const err = event.error ? " error=" + event.error : "";
    const ms = event.duration_ms ? " " + event.duration_ms + "ms" : "";
    return stamp + prefix + count + check + text(event.message) + ms + err;
  }
  function renderDetail(){
    const box = $("detail"); box.textContent = "";
    const job = state.jobs.find(j=>j.id === state.selected) || state.jobs[0];
    if(!job){ box.innerHTML = '<div class="empty">Select or start an audit.</div>'; return; }
    state.selected = job.id;
    const pct = progress(job);
    const head = document.createElement("div"); head.className = "detail-head";
    const titleBox = document.createElement("div"); titleBox.className = "detail-title";
    const pill = document.createElement("span"); pill.className = "pill " + cls(job.status); pill.textContent = text(job.status);
    const title = document.createElement("strong"); title.textContent = job.id;
    const phase = document.createElement("small"); phase.textContent = phaseLabel(job);
    titleBox.append(title,phase);
    head.append(titleBox,pill);
    const strip = document.createElement("div"); strip.className = "phase-strip";
    ["System security","AI audit","Persistence","Cleanup"].forEach((label,i)=>{
      const step = document.createElement("div");
      const idx = phaseIndex(job);
      step.className = "phase-step" + (idx > i ? " done" : "") + (idx === i && isActive(job) ? " active" : "");
      step.textContent = label;
      strip.appendChild(step);
    });
    const progressWrap = document.createElement("div"); progressWrap.className = "progress-wrap";
    const progressLabel = document.createElement("div"); progressLabel.className = "progress-label";
    const progressPhase = document.createElement("span"); progressPhase.textContent = phaseLabel(job);
    const progressPct = document.createElement("span"); progressPct.textContent = pct + "%";
    progressLabel.append(progressPhase,progressPct);
    const prog = document.createElement("div"); prog.className = "progress";
    const bar = document.createElement("div"); bar.className = "bar"; bar.style.width = pct + "%"; prog.appendChild(bar);
    progressWrap.append(progressLabel,prog);
    const actions = document.createElement("div"); actions.className = "actions";
    const cancel = document.createElement("button"); cancel.type = "button"; cancel.className = "danger"; cancel.textContent = "Cancel";
    cancel.disabled = !isActive(job);
    cancel.title = cancel.disabled ? "Only an active local audit can be canceled." : "Request safe cancellation for this local run.";
    cancel.addEventListener("click",()=>cancelJob(job.id));
    const report = document.createElement("button"); report.type = "button"; report.textContent = "Open Report";
    report.disabled = !job.report_url;
    report.title = report.disabled ? "Report will be available when the audit completes." : "Open the generated local report.";
    report.addEventListener("click",()=>{ if(job.report_url) window.open(job.report_url, "_blank", "noopener"); });
    const del = document.createElement("button"); del.type = "button"; del.className = "danger"; del.textContent = "Delete";
    del.disabled = isActive(job);
    del.title = del.disabled ? "Active runs cannot be deleted." : "Delete this run and its report files from disk.";
    del.addEventListener("click",()=>deleteJob(job.id));
    actions.append(cancel,report,del);
    const meta = document.createElement("div"); meta.className = "meta";
    [["Started",time(job.started_at)],["Duration",duration(job)],["Output",job.output_dir],["Risk",job.summary ? job.summary.risk_level : "-"],["Findings",job.summary ? job.summary.total_findings : "-"],["Error",job.error || "-"]].forEach(([k,v])=>{
      const d=document.createElement("div"); const s=document.createElement("span"); s.textContent=k; const b=document.createElement("b"); b.textContent=text(v); d.append(s,b); meta.appendChild(d);
    });
    const logWrap = document.createElement("div"); logWrap.className = "log-wrap";
    const logHead = document.createElement("div"); logHead.className = "log-head";
    const logTitle = document.createElement("strong"); logTitle.textContent = "Live log";
    const logMeta = document.createElement("div");
    const warn = document.createElement("span"); warn.className = warningCount(job) ? "pill failed" : "pill"; warn.textContent = "Warnings " + warningCount(job);
    const auto = document.createElement("span"); auto.className = "pill completed"; auto.textContent = "Auto-scroll ON";
    logMeta.append(warn,auto); logHead.append(logTitle,logMeta);
    const log = document.createElement("div"); log.className = "log"; log.textContent = (job.events || []).map(eventLine).join("\n") || "Waiting for progress events.";
    logWrap.append(logHead,log);
    box.append(head,strip,progressWrap,actions,meta,logWrap);
    log.scrollTop = log.scrollHeight;
  }
  function actionFor(artifact, action){ return (artifact.safe_actions || []).find(a=>a.action === action) || {available:false, disabled_reason:"Unsupported action"}; }
  function artifactButton(artifact, action, label){
    const availability = actionFor(artifact, action);
    const disabled = !availability.available;
    const title = disabled ? (availability.disabled_reason || artifact.disabled_reason || "Unavailable") : (availability.requires_backup ? "Preview changes first. Backup will be created before execution." : "Preview local artifact content.");
    return '<button class="action-btn" data-action="' + escapeHTML(action) + '" type="button" ' + (disabled ? 'disabled ' : '') + 'title="' + escapeHTML(title) + '" onclick="window.previewArtifactAction(\'' + jsArg(artifact.id) + '\',\'' + action + '\')">' + escapeHTML(label) + '</button>';
  }
  function fillArtifactFilters(){
    [["artifact-tool","tool"],["artifact-kind","kind"],["artifact-scope","scope"]].forEach(([id,key])=>{
      const el=$(id); if(!el || el.dataset.ready === "1") return;
      const values = Array.from(new Set(state.artifacts.map(a=>a[key]).filter(Boolean))).sort();
      values.forEach(v=>{ const o=document.createElement("option"); o.value=v; o.textContent=v; el.appendChild(o); });
      el.dataset.ready = "1";
    });
  }
  function filteredArtifacts(){
    const q = $("artifact-search").value.toLowerCase();
    const tool = $("artifact-tool").value;
    const kind = $("artifact-kind").value;
    const scope = $("artifact-scope").value;
    const action = $("artifact-action").value;
    return state.artifacts.filter(a=>{
      if(q && !JSON.stringify(a).toLowerCase().includes(q)) return false;
      if(tool && a.tool !== tool) return false;
      if(kind && a.kind !== kind) return false;
      if(scope && a.scope !== scope) return false;
      const hasAvailable = (a.safe_actions || []).some(x=>x.available);
      if(action === "available" && !hasAvailable) return false;
      if(action === "blocked" && hasAvailable) return false;
      return true;
    });
  }
  function renderArtifacts(){
    fillArtifactFilters();
    const body = $("artifacts"); body.textContent = "";
    const rows = filteredArtifacts();
    const count = $("artifact-count");
    if(count) count.textContent = rows.length + " / " + state.artifacts.length + " artifacts";
    ["artifact-search","artifact-tool","artifact-kind","artifact-scope","artifact-action"].forEach(id=>{
      const el=$(id); if(el) el.classList.toggle("active-filter", Boolean(el.value));
    });
    const chip = $("artifact-filter-chip");
    if(chip){
      const active = [["tool",$("artifact-tool").value],["kind",$("artifact-kind").value],["scope",$("artifact-scope").value],["action",$("artifact-action").value]].filter(x=>x[1]);
      chip.textContent = active.length ? active.map(x=>x[0] + ": " + x[1]).join(" | ") : "All actions";
    }
    if(!rows.length){ body.innerHTML = '<tr><td colspan="6" class="empty">No matching manageable artifacts.</td></tr>'; return; }
    rows.forEach(a=>{
      const tr=document.createElement("tr");
      tr.className = a.id === state.selectedArtifact ? "selected" : "";
      tr.addEventListener("click",()=>{ state.selectedArtifact = a.id; renderArtifacts(); });
      [a.tool,a.kind,a.scope].forEach(v=>{ const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td); });
      const risk=document.createElement("td"); const riskBadge=document.createElement("span"); riskBadge.className = "risk-badge risk-" + cls(a.risk); riskBadge.textContent = text(a.risk); risk.appendChild(riskBadge); tr.appendChild(risk);
      const path=document.createElement("td"); path.className = "path-cell"; const pathText=document.createElement("span"); pathText.textContent=text(a.path); path.appendChild(pathText);
      if(a.backup_available){ const backup=document.createElement("span"); backup.className="backup-hint"; backup.textContent="backup available for restore"; path.appendChild(backup); }
      tr.appendChild(path);
      const actionCell=document.createElement("td"); actionCell.className="action-set";
      actionCell.innerHTML = ["read","edit","disable","enable","fix","clean","delete","restore"].map(x=>artifactButton(a,x,x)).join("");
      tr.appendChild(actionCell);
      body.appendChild(tr);
    });
  }
  function render(){ renderAuditLock(); renderStatus(); renderJobs(); renderDetail(); renderArtifacts(); }
  async function refresh(){
    const res = await fetch("/api/audits", {cache:"no-store"});
    state.jobs = await res.json();
    if(!state.selected && state.jobs[0]) state.selected = state.jobs[0].id;
    await refreshArtifacts();
    render();
  }
  async function refreshArtifacts(){
    try {
      const job = state.jobs.find(j=>j.id === state.selected) || state.jobs[0];
      const url = job ? "/api/artifacts?job_id=" + encodeURIComponent(job.id) : "/api/artifacts";
      const res = await fetch(url, {cache:"no-store"});
      if(!res.ok) return;
      state.artifacts = await res.json();
      if(state.selectedArtifact && !state.artifacts.some(a=>a.id === state.selectedArtifact)) state.selectedArtifact = "";
      ["artifact-tool","artifact-kind","artifact-scope"].forEach(id=>{ const el=$(id); if(el){ while(el.options.length>1) el.remove(1); el.dataset.ready=""; } });
    } catch (_) {}
  }
  async function postAction(endpoint, payload){
    const res = await fetch(endpoint, {method:"POST", headers:{"Content-Type":"application/json","X-Audit-Token":token}, body:JSON.stringify(payload)});
    if(!res.ok) throw new Error(await res.text());
    return res.json();
  }
  function artifactById(id){ return state.artifacts.find(a=>a.id === id); }
  function artifactMetaHTML(artifact){
    return '<div class="artifact-meta"><div><span>Tool</span><b>' + escapeHTML(artifact.tool) + '</b></div><div><span>Kind</span><b>' + escapeHTML(artifact.kind) + '</b></div><div><span>Risk</span><b>' + escapeHTML(artifact.risk) + '</b></div><div><span>Backup</span><b>' + escapeHTML(artifact.backup_available ? "Restore available" : "Created on apply") + '</b></div><div style="grid-column:1/-1"><span>Path</span><b>' + escapeHTML(artifact.path) + '</b></div></div>';
  }
  window.previewArtifactAction = async function(id, action){
    const artifact = artifactById(id); if(!artifact) return;
    state.selectedArtifact = id;
    state.lastPreview = null;
    const payload = {job_id: state.selected, action, path: artifact.path, artifact_id: artifact.id};
    if(artifact.kind === "mcp_server") payload.server_name = artifact.tool;
    const modal=$("action-modal"), body=$("modal-body"); modal.style.display="flex"; $("modal-title").textContent= action === "edit" ? "Preview edit" : "Preview " + action; body.innerHTML='<div class="empty">Preview changes</div>';
    try {
      if(action === "edit" && artifact.kind !== "mcp_server"){
        const read = await postAction("/api/actions/preview", {...payload, action:"read"});
        body.innerHTML='<p class="modal-copy">Review changes locally before applying. This edit will only affect your local server.</p>' + artifactMetaHTML(artifact) + '<label class="edit-label" for="edit-content">Edit content (local only)</label><textarea id="edit-content" class="edit-area" oninput="window.markEditDirty()">' + escapeHTML(read.content || "") + '</textarea><div class="diff-label">Preview changes</div><pre id="action-diff" class="diff">Preview changes</pre><div class="modal-note"><strong>Backup will be created before execution.</strong><span class="pill completed">Local only</span></div><div class="modal-footer"><span class="local-copy">No data leaves this machine. Preview changes to enable apply.</span><div class="actions"><button type="button" onclick="window.previewEdit(\'' + jsArg(id) + '\')">Preview changes</button><button id="apply-edit" class="primary" type="button" disabled onclick="window.executeEdit(\'' + jsArg(id) + '\')">Apply with backup</button></div></div>';
        return;
      }
      if(action === "edit" && artifact.kind === "mcp_server"){
        const patch = window.prompt("Enter JSON fields to update on this MCP server", "{\"disabled\":true}");
        if(!patch){ modal.style.display="none"; return; }
        payload.server_config = JSON.parse(patch);
      }
      const preview = await postAction("/api/actions/preview", payload);
      state.lastPreview = payload;
      const availability = actionFor(artifact, action);
      const canApply = availability.requires_preview || availability.requires_backup || action !== "read";
      const applyLabel = action === "restore" ? "Restore from backup" : "Apply with backup";
      body.innerHTML='<p class="modal-copy">Preview local action before execution. No data leaves this machine.</p>' + artifactMetaHTML(artifact) + '<div class="diff-label">Preview changes</div><pre class="diff">' + escapeHTML(preview.diff || preview.content || preview.message || "No changes") + '</pre><div class="modal-note"><strong>Backup will be created before execution.</strong><span class="pill completed">Local only</span></div>' + (canApply ? '<div class="modal-footer"><span class="local-copy">Backups are stored locally for restore.</span><div class="actions"><button class="primary" type="button" onclick="window.executePreview()">' + applyLabel + '</button></div></div>' : '<div class="modal-footer"><span class="local-copy">Read-only preview. No apply action is needed.</span></div>');
    } catch(err) {
      body.innerHTML='<div class="empty">Parser failed, manual review required: ' + escapeHTML(String(err)) + '</div>';
    }
  };
  window.markEditDirty = function(){
    const apply = $("apply-edit");
    const diff = $("action-diff");
    if(apply) apply.disabled = true;
    if(diff) diff.textContent = "Preview changes";
  };
  window.previewEdit = async function(id){
    const artifact = artifactById(id); const content=$("edit-content").value;
    const preview = await postAction("/api/actions/preview", {job_id:state.selected, action:"edit", path:artifact.path, artifact_id:artifact.id, content});
    $("action-diff").textContent = preview.diff || preview.message || "No changes";
    const apply = $("apply-edit");
    if(apply) apply.disabled = false;
  };
  window.executeEdit = async function(id){
    const artifact = artifactById(id); const content=$("edit-content").value;
    await postAction("/api/actions/execute", {job_id:state.selected, action:"edit", path:artifact.path, artifact_id:artifact.id, content});
    $("action-modal").style.display="none"; await refresh();
  };
  window.executePreview = async function(){
    if(!state.lastPreview) return;
    await postAction("/api/actions/execute", state.lastPreview);
    $("action-modal").style.display="none"; await refresh();
  };
  async function startAudit(evt){
    evt.preventDefault();
    if(activeJob()){ window.alert("An audit is already running locally."); return; }
    const payload = {
      want_text: $("want-text").checked,
      want_json: $("want-json").checked,
      want_html: $("want-html").checked,
      deep: $("deep").checked,
      ai_audit: $("ai-audit").checked,
      no_sudo: $("no-sudo").checked,
      clean_dry_run: $("clean-dry-run").checked,
      output_dir: $("output-dir").value.trim(),
      project_root: $("project-root").value.trim(),
      max_file_size_mb: Number($("max-file-size-mb").value || 5)
    };
    const res = await fetch("/api/audits", {method:"POST", headers:{"Content-Type":"application/json","X-Audit-Token":token}, body:JSON.stringify(payload)});
    if(!res.ok){ window.alert(await res.text()); return; }
    const job = await res.json();
    state.selected = job.id;
    await refresh();
  }
  async function cancelJob(id){
    const res = await fetch("/api/audits/" + encodeURIComponent(id) + "/cancel", {method:"POST", headers:{"X-Audit-Token":token}});
    if(!res.ok){ window.alert(await res.text()); return; }
    await refresh();
  }
  async function deleteJob(id){
    if(!window.confirm("Are you sure you want to delete this run and its report files from disk?")) return;
    const res = await fetch("/api/audits/" + encodeURIComponent(id), {method:"DELETE", headers:{"X-Audit-Token":token}});
    if(!res.ok){ window.alert(await res.text()); return; }
    if(state.selected === id) {
      state.selected = "";
    }
    await refresh();
  }
  $("audit-form").addEventListener("submit", startAudit);
  $("refresh").addEventListener("click", refresh);
  $("modal-close").addEventListener("click", () => { $("action-modal").style.display = "none"; });
  ["artifact-search","artifact-tool","artifact-kind","artifact-scope","artifact-action"].forEach(id=>$(id).addEventListener("input", renderArtifacts));
  refresh();
  setInterval(refresh, 1500);
})();
</script>
</body>
</html>`
