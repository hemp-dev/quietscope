package ui

const LocalOnlyNotice = "The local UI binds to 127.0.0.1, launches local audits only, and never uploads reports or file contents."

const ControlDashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{color-scheme:light dark;--bg:#f4f5f2;--fg:#111714;--muted:#65716b;--panel:#ffffff;--panel-2:#edf1ed;--line:#cfd8d0;--accent:#0b6b57;--accent-2:#1e5aa8;--bad:#b42318;--warn:#9a5b00;--ok:#157a47;--shadow:0 10px 28px rgba(17,23,20,.08)}
@media (prefers-color-scheme:dark){:root{--bg:#111411;--fg:#eef3ec;--muted:#aab5aa;--panel:#181d19;--panel-2:#202820;--line:#334036;--accent:#66d2b0;--accent-2:#8ebcff;--bad:#ff9488;--warn:#ffc36b;--ok:#7bd89f;--shadow:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;line-height:1.42}
button,input,select{font:inherit}
header{border-bottom:1px solid var(--line);background:var(--panel);padding:18px 22px}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;max-width:1500px;margin:0 auto}
h1{font-size:22px;line-height:1.1;margin:0 0 6px;letter-spacing:0}
.sub{margin:0;color:var(--muted);font-size:13px}
.version{border:1px solid var(--line);border-radius:6px;padding:6px 9px;color:var(--muted);background:var(--panel-2);white-space:nowrap}
main{max-width:1500px;margin:0 auto;padding:18px 22px 32px;display:grid;grid-template-columns:minmax(300px,380px) minmax(0,1fr);gap:18px}
.rail,.workspace{min-width:0}
.panel{border:1px solid var(--line);background:var(--panel);border-radius:8px;box-shadow:var(--shadow)}
.panel h2{font-size:15px;margin:0;padding:14px 14px 10px;border-bottom:1px solid var(--line)}
.form{padding:14px;display:grid;gap:12px}
.field{display:grid;gap:5px}
.field span,.check span{font-size:12px;color:var(--muted)}
.field input,.field select{width:100%;min-height:34px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);padding:6px 8px}
.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.check{display:flex;align-items:center;gap:8px;min-height:34px;border:1px solid var(--line);border-radius:6px;padding:6px 8px;background:var(--bg)}
.check input{inline-size:16px;block-size:16px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
button{min-height:36px;border:1px solid var(--line);border-radius:6px;background:var(--panel-2);color:var(--fg);padding:7px 11px;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{color:var(--bad)}
button:disabled{opacity:.55;cursor:not-allowed}
.notice{margin:0;padding:10px 14px;color:var(--muted);border-top:1px solid var(--line);font-size:12px}
.statusbar{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:14px}
.metric{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:12px}
.metric span{display:block;color:var(--muted);font-size:11px}
.metric b{display:block;font-size:22px;margin-top:4px;overflow-wrap:anywhere}
.layout{display:grid;grid-template-columns:minmax(280px,360px) minmax(0,1fr);gap:14px}
.jobs{overflow:auto;max-height:650px}
.job{width:100%;text-align:left;border:0;border-bottom:1px solid var(--line);border-radius:0;background:transparent;padding:11px 12px;display:grid;gap:4px}
.job:hover,.job.active{background:var(--panel-2)}
.job strong{font-size:13px;overflow-wrap:anywhere}
.job small{color:var(--muted)}
.pill{display:inline-flex;align-items:center;justify-content:center;min-height:22px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:11px;width:max-content}
.completed{color:var(--ok)}.running,.queued,.canceling{color:var(--accent-2)}.failed,.canceled{color:var(--bad)}
.detail{padding:14px;display:grid;gap:14px;min-height:420px}
.progress{height:16px;border:1px solid var(--line);background:var(--bg);border-radius:999px;overflow:hidden}
.bar{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .25s ease}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.meta div{border:1px solid var(--line);border-radius:6px;padding:8px;min-height:48px;overflow-wrap:anywhere}
.meta span{display:block;color:var(--muted);font-size:11px;margin-bottom:3px}
.log{border:1px solid var(--line);border-radius:8px;background:#0d120f;color:#d6f5df;min-height:210px;max-height:390px;overflow:auto;padding:10px;font-size:12px;white-space:pre-wrap}
@media (prefers-color-scheme:light){.log{background:#121a15;color:#d9f7df}}
.empty{color:var(--muted);padding:16px}
@media (max-width:980px){main,.layout{grid-template-columns:1fr}.statusbar{grid-template-columns:repeat(2,minmax(0,1fr))}.jobs{max-height:320px}}
@media (max-width:560px){header,main{padding-left:14px;padding-right:14px}.top{display:grid}.checks,.statusbar,.meta{grid-template-columns:1fr}.version{width:max-content}}
</style>
</head>
<body>
<header>
  <div class="top">
    <div>
      <h1>macOS Security Audit</h1>
      <p class="sub">{{.Notice}}</p>
    </div>
    <div class="version">UI {{.Version}}</div>
  </div>
</header>
<main>
  <aside class="rail panel">
    <h2>Audit Control</h2>
    <form id="audit-form" class="form">
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
        <button class="primary" type="submit">Start Audit</button>
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
  </section>
</main>
<script>
(function(){
  "use strict";
  const token = "{{.Token}}";
  const state = { jobs: [], selected: "" };
  const $ = (id) => document.getElementById(id);
  function text(v){ return v === null || v === undefined || v === "" ? "-" : String(v); }
  function cls(v){ return String(v||"").toLowerCase(); }
  function latestEvent(job){ const events = job.events || []; return events.length ? events[events.length - 1] : null; }
  function progress(job){
    const event = latestEvent(job);
    if(!event || !event.total) return job.status === "completed" ? 100 : 0;
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
  function metric(label,value,klass){
    const d = document.createElement("div"); d.className = "metric";
    const s = document.createElement("span"); s.textContent = label;
    const b = document.createElement("b"); b.textContent = text(value); if(klass) b.className = klass;
    d.append(s,b); return d;
  }
  function renderStatus(){
    const box = $("statusbar"); box.textContent = "";
    const total = state.jobs.length;
    const running = state.jobs.filter(j=>["running","queued","canceling"].includes(j.status)).length;
    const failed = state.jobs.filter(j=>j.status === "failed" || j.status === "canceled").length;
    const latest = state.jobs[0];
    box.append(metric("Total runs", total));
    box.append(metric("Active", running, running ? "running" : ""));
    box.append(metric("Failed/Canceled", failed, failed ? "failed" : ""));
    box.append(metric("Latest score", latest && latest.summary ? latest.summary.overall_risk_score + "/100" : "-"));
  }
  function renderJobs(){
    const box = $("jobs"); box.textContent = "";
    if(!state.jobs.length){ box.innerHTML = '<div class="empty">No audits yet.</div>'; return; }
    state.jobs.forEach(job=>{
      const btn = document.createElement("button");
      btn.type = "button"; btn.className = "job" + (job.id === state.selected ? " active" : "");
      btn.addEventListener("click",()=>{ state.selected = job.id; render(); });
      const title = document.createElement("strong"); title.textContent = job.id;
      const line = document.createElement("small"); line.textContent = time(job.created_at) + " | " + text(job.output_dir);
      const pill = document.createElement("span"); pill.className = "pill " + cls(job.status); pill.textContent = text(job.status);
      btn.append(title,pill,line); box.appendChild(btn);
    });
  }
  function eventLine(event){
    const prefix = event.type ? "[" + event.type + "] " : "";
    const check = event.check_name ? event.check_name + " " : "";
    const count = event.total ? "(" + Number(event.completed || 0) + "/" + event.total + ") " : "";
    const err = event.error ? " error=" + event.error : "";
    const ms = event.duration_ms ? " " + event.duration_ms + "ms" : "";
    return prefix + count + check + text(event.message) + ms + err;
  }
  function renderDetail(){
    const box = $("detail"); box.textContent = "";
    const job = state.jobs.find(j=>j.id === state.selected) || state.jobs[0];
    if(!job){ box.innerHTML = '<div class="empty">Select or start an audit.</div>'; return; }
    state.selected = job.id;
    const pct = progress(job);
    const head = document.createElement("div");
    const pill = document.createElement("span"); pill.className = "pill " + cls(job.status); pill.textContent = text(job.status);
    const title = document.createElement("strong"); title.textContent = " " + job.id;
    head.append(pill,title);
    const prog = document.createElement("div"); prog.className = "progress";
    const bar = document.createElement("div"); bar.className = "bar"; bar.style.width = pct + "%"; prog.appendChild(bar);
    const actions = document.createElement("div"); actions.className = "actions";
    const cancel = document.createElement("button"); cancel.type = "button"; cancel.className = "danger"; cancel.textContent = "Cancel";
    cancel.disabled = !["running","queued","canceling"].includes(job.status);
    cancel.addEventListener("click",()=>cancelJob(job.id));
    const report = document.createElement("button"); report.type = "button"; report.textContent = "Open Report";
    report.disabled = !job.report_url;
    report.addEventListener("click",()=>{ if(job.report_url) window.open(job.report_url, "_blank", "noopener"); });
    actions.append(cancel,report);
    const meta = document.createElement("div"); meta.className = "meta";
    [["Started",time(job.started_at)],["Duration",duration(job)],["Output",job.output_dir],["Risk",job.summary ? job.summary.risk_level : "-"],["Findings",job.summary ? job.summary.total_findings : "-"],["Error",job.error || "-"]].forEach(([k,v])=>{
      const d=document.createElement("div"); const s=document.createElement("span"); s.textContent=k; const b=document.createElement("b"); b.textContent=text(v); d.append(s,b); meta.appendChild(d);
    });
    const log = document.createElement("div"); log.className = "log"; log.textContent = (job.events || []).map(eventLine).join("\n") || "Waiting for progress events.";
    box.append(head,prog,actions,meta,log);
  }
  function render(){ renderStatus(); renderJobs(); renderDetail(); }
  async function refresh(){
    const res = await fetch("/api/audits", {cache:"no-store"});
    state.jobs = await res.json();
    if(!state.selected && state.jobs[0]) state.selected = state.jobs[0].id;
    render();
  }
  async function startAudit(evt){
    evt.preventDefault();
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
    const res = await fetch("/api/audits/" + encodeURIComponent(id), {method:"DELETE", headers:{"X-Audit-Token":token}});
    if(!res.ok){ window.alert(await res.text()); return; }
    await refresh();
  }
  $("audit-form").addEventListener("submit", startAudit);
  $("refresh").addEventListener("click", refresh);
  refresh();
  setInterval(refresh, 1500);
})();
</script>
</body>
</html>`
