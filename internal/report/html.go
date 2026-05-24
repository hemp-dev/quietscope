package report

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"

	"github.com/projectauthors/quietscope/internal/audit"
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
:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#17202a;--muted:#5d6d7e;--panel:#fff;--line:#d7dde5;--accent:#1769aa;--bad:#b42318;--warn:#a15c00;--ok:#16784a;--info:#596579}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--fg:#eef2f7;--muted:#abb6c4;--panel:#181d23;--line:#2e3640;--accent:#66b2ff;--bad:#ff8a7a;--warn:#ffbd66;--ok:#7bd89f;--info:#aab3c2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.45}header{padding:28px 24px 16px;border-bottom:1px solid var(--line);background:var(--panel)}main{padding:20px 24px 40px;max-width:1400px;margin:0 auto}h1{margin:0 0 8px;font-size:28px;letter-spacing:0}h2{font-size:20px;margin:28px 0 12px}.sub{color:var(--muted);margin:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:14px}.card b{display:block;font-size:24px;margin-top:4px}.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin:16px 0}.toolbar label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:4px}.toolbar input,.toolbar select,.toolbar button{min-height:36px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--fg);padding:6px 10px}.toolbar button{cursor:pointer}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:8px;background:var(--panel)}table{width:100%;border-collapse:collapse;min-width:960px}th,td{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:12px;color:var(--muted);cursor:pointer;position:sticky;top:0;background:var(--panel)}tr:last-child td{border-bottom:0}.pill{display:inline-block;border-radius:999px;border:1px solid var(--line);padding:2px 8px;font-size:12px}.critical,.high{color:var(--bad)}.medium{color:var(--warn)}.low{color:var(--accent)}.info{color:var(--info)}.PASS{color:var(--ok)}.WARN{color:var(--warn)}.FAIL{color:var(--bad)}details{max-width:760px}summary{cursor:pointer;color:var(--accent)}pre{white-space:pre-wrap;word-break:break-word;background:rgba(127,127,127,.08);padding:10px;border-radius:6px}.notice{border-left:4px solid var(--accent);padding:10px 12px;background:var(--panel);border-radius:4px}.section-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.item{border:1px solid var(--line);border-radius:8px;background:var(--panel);padding:12px;overflow-wrap:anywhere}.sr-only{position:absolute;left:-10000px}@media print{.toolbar{display:none}body{background:#fff;color:#000}header,.card,.item,.table-wrap{border-color:#999}.table-wrap{overflow:visible}table{min-width:0;font-size:11px}}
</style>
</head>
<body>
<header>
  <h1>Quietscope</h1>
  <p class="sub">Privacy-first local report. No external scripts, fonts, analytics, uploads, or network requests.</p>
</header>
<main>
<noscript><p class="notice">JavaScript is disabled. The JSON payload remains embedded in this file; enable JavaScript for filtering and dashboard rendering.</p></noscript>
<section aria-labelledby="summary-title">
  <h2 id="summary-title">Dashboard</h2>
  <div id="summary" class="grid" aria-live="polite"></div>
</section>
<section class="toolbar" aria-label="Report controls">
  <label>Search <input id="search" type="search" aria-label="Search findings"></label>
  <label>Severity <select id="severity"><option value="">All</option></select></label>
  <label>Category <select id="category"><option value="">All</option></select></label>
  <label>Status <select id="status"><option value="">All</option></select></label>
  <label>Special <select id="special"><option value="">All</option><option value="cleanup">Cleanup candidates</option><option value="ai">AI/security findings</option><option value="secrets">Secrets exposure</option></select></label>
  <label><input id="privacy" type="checkbox"> Privacy mode</label>
  <button id="print" type="button">Print / Save as PDF</button>
  <button id="copy" type="button">Copy summary</button>
</section>
<section aria-labelledby="findings-title">
  <h2 id="findings-title">Findings</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th data-sort="severity">Severity</th><th data-sort="status">Status</th><th data-sort="category">Category</th><th data-sort="title">Title</th><th>Details</th></tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>
</section>
<section aria-labelledby="ai-title">
  <h2 id="ai-title">AI Local Security</h2>
  <div id="ai-section" class="section-list"></div>
</section>
<section aria-labelledby="ai-context-title">
  <h2 id="ai-context-title">AI Skills & Context Inventory</h2>
  <p class="notice">Context impact estimates how likely this file or directory is to influence AI-agent behavior or be automatically included in an AI tool's working context. It is not a malware verdict.</p>
  <div id="ai-context-summary" class="grid" aria-live="polite"></div>
  <section class="toolbar" aria-label="AI context inventory filters">
    <label>Tool <select id="ai-tool"><option value="">All</option></select></label>
    <label>Directory Category <select id="ai-dir-category"><option value="">All</option></select></label>
    <label>Artifact Type <select id="ai-artifact-type"><option value="">All</option></select></label>
    <label>Scope <select id="ai-scope"><option value="">All</option></select></label>
    <label>Impact <select id="ai-impact"><option value="">All</option></select></label>
    <label>Auto-loaded <select id="ai-auto"><option value="">All</option></select></label>
    <label>Cleanup <select id="ai-cleanup"><option value="">All</option><option value="true">Cleanup candidates</option><option value="false">Not cleanup candidates</option></select></label>
    <label>Suspicious <select id="ai-suspicious"><option value="">All</option><option value="true">Has patterns</option><option value="false">No patterns</option></select></label>
    <label>Min Size MiB <input id="ai-size-min" type="number" min="0" step="1" aria-label="Minimum AI directory size in MiB"></label>
  </section>
  <h3>AI-related directories</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th data-ai-dir-sort="tool">Tool</th><th>Path</th><th data-ai-dir-sort="category">Category</th><th data-ai-dir-sort="size">Size</th><th>File Count</th><th data-ai-dir-sort="modified">Last Modified</th><th data-ai-dir-sort="impact">Context Impact</th><th>Score</th><th>Cleanup Candidate</th><th>Recommendation</th></tr></thead>
      <tbody id="ai-dir-body"></tbody>
    </table>
  </div>
  <h3>AI skills/context artifacts</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th data-ai-artifact-sort="tool">Tool</th><th data-ai-artifact-sort="type">Artifact Type</th><th>Path</th><th data-ai-artifact-sort="scope">Scope</th><th>Size</th><th>Permissions</th><th data-ai-artifact-sort="auto">Auto-loaded</th><th data-ai-artifact-sort="impact">Context Impact</th><th>Suspicious Patterns</th><th>Recommendation</th></tr></thead>
      <tbody id="ai-artifact-body"></tbody>
    </table>
  </div>
</section>
<section aria-labelledby="ai-catalog-title">
  <h2 id="ai-catalog-title">AI Tool Catalog</h2>
  <p class="notice">Detection is factual and read-only. A detected tool or provider is not a risk by itself; risk depends on permissions, context scope, shell access, MCP tools, remote provider usage, and exposed local servers.</p>
  <div id="ai-provider-summary" class="grid" aria-live="polite"></div>
  <section class="toolbar" aria-label="AI tool catalog filters">
    <label>Tool Category <select id="catalog-category"><option value="">All</option></select></label>
    <label>Vendor/Provider <select id="catalog-vendor"><option value="">All</option></select></label>
    <label>Model Family <select id="provider-family"><option value="">All</option></select></label>
    <label>China-origin Provider <select id="china-origin"><option value="">All</option><option value="true">Yes</option><option value="false">No</option></select></label>
    <label>Has API Env Key <select id="provider-env"><option value="">All</option><option value="true">Yes</option><option value="false">No</option></select></label>
    <label>Has MCP Tools <select id="catalog-mcp"><option value="">All</option><option value="true">Yes</option><option value="false">No</option></select></label>
    <label>Min Disk MiB <input id="catalog-size-min" type="number" min="0" step="1" aria-label="Minimum catalog disk size in MiB"></label>
  </section>
  <h3>Detected AI tools</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Tool</th><th>Vendor</th><th>Categories</th><th>Apps/Binaries</th><th>Configs</th><th>Cache/Logs</th><th>Disk</th><th>Ports</th><th>Risk Notes</th></tr></thead>
      <tbody id="ai-tool-catalog-body"></tbody>
    </table>
  </div>
  <h3>Hermes Agent</h3>
  <div id="hermes-section" class="section-list"></div>
  <h3>OpenCode / opencode</h3>
  <div id="opencode-section" class="section-list"></div>
  <h3>MCP clients and servers</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Server</th><th>Category</th><th>Scope</th><th>Config</th><th>Command</th><th>Env Keys</th><th>Risks</th><th>Recommendation</th></tr></thead>
      <tbody id="mcp-server-body"></tbody>
    </table>
  </div>
  <h3>Chinese AI Models & Providers</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Provider</th><th>Vendor</th><th>Families</th><th>Env Keys</th><th>Configs</th><th>Caches</th><th>Cache Size</th><th>Risk Basis</th><th>Recommendation</th></tr></thead>
      <tbody id="chinese-provider-body"></tbody>
    </table>
  </div>
  <h3>Local model inventory</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Tool</th><th>Provider Hint</th><th>Path</th><th>Size</th><th>Files</th><th>Last Modified</th><th>Auto-clean</th><th>Recommendation</th></tr></thead>
      <tbody id="local-model-body"></tbody>
    </table>
  </div>
  <h3>AI security scanners and guard tools</h3>
  <div id="ai-security-tools-section" class="section-list"></div>
</section>
<section aria-labelledby="storage-title">
  <h2 id="storage-title">Storage & Cleanup</h2>
  <p class="notice">Cleanup is never automatic. CLI cleanup requires the exact confirmation phrase.</p>
  <div id="cleanup-section" class="section-list"></div>
</section>
<script type="application/json" id="audit-data">{{.JSON}}</script>
<script>
(function(){
  "use strict";
  const raw = document.getElementById("audit-data").textContent;
  const data = JSON.parse(raw);
  const state = { sort: "severity", dir: 1, aiDirSort: "size", aiDirDir: -1, aiArtifactSort: "impact", aiArtifactDir: -1 };
  const severityOrder = {critical: 5, high: 4, medium: 3, low: 2, info: 1};
  const impactOrder = {critical: 5, high: 4, medium: 3, low: 2, none: 1};
  const $ = (id) => document.getElementById(id);
  function text(value){ return value === null || value === undefined ? "" : String(value); }
  function bytes(n){ if(!n) return "0 B"; const u=["B","KiB","MiB","GiB","TiB"]; let i=0,v=Number(n); while(v>=1024&&i<u.length-1){v/=1024;i++;} return (i? v.toFixed(1):v.toFixed(0))+" "+u[i]; }
  function masked(s){ s=text(s); if(!$("privacy").checked) return s; const root=text((data.metadata||{}).project_root); if(root){ s=s.split(root).join("<project>"); } return s.replace(/\/Users\/([^\/\s]+)/g,"/Users/<user>").replace(/hostname: [^;\n]+/ig,"hostname: <hidden>").replace(/\"hostname\"\s*:\s*\"[^\"]+\"/ig,'"hostname":"<hidden>"'); }
  function addCard(parent,label,value,cls){ const d=document.createElement("div"); d.className="card"; const span=document.createElement("span"); span.textContent=label; const b=document.createElement("b"); b.className=cls||""; b.textContent=value; d.append(span,b); parent.appendChild(d); }
  function renderSummary(){
    const s=data.summary||{}, m=data.metadata||{}, sys=data.system_info||{};
    const box=$("summary"); box.textContent="";
    addCard(box,"Overall Risk Score", text(s.overall_risk_score)+"/100", String(s.risk_level||"").toLowerCase());
    addCard(box,"Risk Level", text(s.risk_level), String(s.risk_level||"").toLowerCase());
    addCard(box,"Total Findings", text(s.total_findings));
    addCard(box,"High/Critical", text((s.high_count||0)+(s.critical_count||0)), "high");
    addCard(box,"PASS/WARN/FAIL/INFO/SKIPPED", [s.pass_count,s.warn_count,s.fail_count,s.info_count,s.skipped_count||0].join("/"));
    addCard(box,"Cleanup Reclaimable", bytes(s.cleanup_reclaimable_bytes));
    addCard(box,"AI Findings", text(s.ai_risk_count));
    addCard(box,"Secrets Exposure", text(s.secrets_exposure_count), s.secrets_exposure_count ? "medium" : "info");
    addCard(box,"Generated", text(m.generated_at));
    addCard(box,"macOS", masked(sys.macos_version||sys.go_runtime_os||"unknown"));
    addCard(box,"Hostname", $("privacy").checked ? "<hidden>" : text(sys.hostname||"unknown"));
  }
  function fillSelect(id, values){ const el=$(id); Array.from(new Set(values.filter(Boolean))).sort().forEach(v=>{const o=document.createElement("option"); o.value=v; o.textContent=v; el.appendChild(o);}); }
  fillSelect("severity", (data.findings||[]).map(f=>f.severity));
  fillSelect("category", (data.findings||[]).map(f=>f.category));
  fillSelect("status", (data.findings||[]).map(f=>f.status));
  fillSelect("ai-tool", (data.ai_context_inventory||[]).map(a=>a.tool_name).concat((data.ai_related_directories||[]).map(d=>d.tool_name)));
  fillSelect("ai-dir-category", (data.ai_related_directories||[]).map(d=>d.category));
  fillSelect("ai-artifact-type", (data.ai_context_inventory||[]).map(a=>a.artifact_type));
  fillSelect("ai-scope", (data.ai_context_inventory||[]).map(a=>a.scope));
  fillSelect("ai-impact", (data.ai_context_inventory||[]).map(a=>a.context_impact).concat((data.ai_related_directories||[]).map(d=>d.context_impact)));
  fillSelect("ai-auto", (data.ai_context_inventory||[]).map(a=>a.auto_loaded_likelihood));
  fillSelect("catalog-category", (data.ai_tool_catalog||[]).flatMap(t=>t.categories||[]));
  fillSelect("catalog-vendor", (data.ai_tool_catalog||[]).map(t=>t.vendor).concat((data.chinese_ai_providers||[]).map(p=>p.vendor)));
  fillSelect("provider-family", (data.chinese_ai_providers||[]).flatMap(p=>p.families||[]));
  function filtered(){
    const q=$("search").value.toLowerCase(), sev=$("severity").value, cat=$("category").value, st=$("status").value, special=$("special").value;
    return (data.findings||[]).filter(f=>{
      const blob=JSON.stringify(f).toLowerCase();
      if(q && !blob.includes(q)) return false;
      if(sev && f.severity!==sev) return false;
      if(cat && f.category!==cat) return false;
      if(st && f.status!==st) return false;
      if(special==="cleanup" && !f.cleanup_candidate) return false;
      if(special==="ai" && !(f.category==="ai_security"||f.command_execution_risk||f.network_exfiltration_risk)) return false;
      if(special==="secrets" && !(f.category==="secrets"||f.data_exposure_risk)) return false;
      return true;
    }).sort((a,b)=>{
      let av=a[state.sort], bv=b[state.sort];
      if(state.sort==="severity"){ av=severityOrder[av]||0; bv=severityOrder[bv]||0; return (bv-av)*state.dir; }
      return text(av).localeCompare(text(bv))*state.dir;
    });
  }
  function renderFindings(){
    const body=$("findings-body"); body.textContent="";
    filtered().forEach(f=>{
      const tr=document.createElement("tr");
      [["severity",f.severity],["status",f.status],["category",f.category],["title",f.title]].forEach(([k,v])=>{const td=document.createElement("td"); const pill=document.createElement("span"); pill.className="pill "+text(v); pill.textContent=masked(v); td.appendChild(pill); tr.appendChild(td);});
      const td=document.createElement("td"); const det=document.createElement("details"); const sum=document.createElement("summary"); sum.textContent="Evidence and recommendation"; const pre=document.createElement("pre");
      pre.textContent=[
        "ID: "+text(f.id),
        "Evidence: "+masked(f.evidence),
        "Recommendation: "+masked(f.recommendation),
        "Command checked: "+masked(f.command_checked),
        "safe_to_auto_fix: "+text(f.safe_to_auto_fix),
        "cleanup_candidate: "+text(f.cleanup_candidate),
        "estimated_size: "+bytes(f.estimated_size_bytes),
        "data_exposure_risk: "+text(f.data_exposure_risk),
        "command_execution_risk: "+text(f.command_execution_risk),
        "network_exfiltration_risk: "+text(f.network_exfiltration_risk)
      ].join("\n");
      det.append(sum,pre); td.appendChild(det); tr.appendChild(td); body.appendChild(tr);
    });
  }
  function addItem(parent,title,lines){ const d=document.createElement("div"); d.className="item"; const h=document.createElement("strong"); h.textContent=title; const pre=document.createElement("pre"); pre.textContent=masked(lines.join("\n")); d.append(h,pre); parent.appendChild(d); }
  function renderAI(){
    const box=$("ai-section"); box.textContent=""; const ai=data.ai_security||{};
    addItem(box,"Installed AI Tools",(ai.installed_tools||[]).map(t=>text(t.name)+" | "+text(t.kind)+" | "+text(t.path)));
    addItem(box,"MCP Config Risks",(ai.mcp_configs||[]).map(c=>text(c.risk)+" | "+text(c.path)+" | "+text(c.server_name||"")+" | "+text(c.command||"")+" | "+text(c.description||"")));
    addItem(box,"Local LLM Servers",(ai.local_servers||[]).map(s=>text(s.risk)+" | "+text(s.name)+" pid="+text(s.pid)+" "+text(s.address)+":"+text(s.port)));
    addItem(box,"Prompt Injection Artifacts",(ai.prompt_artifacts||[]).map(a=>text(a.severity)+" | "+text(a.path)+":"+text(a.line)+" | "+text(a.phrase)));
    addItem(box,"AI Hardening Recommendations", ai.recommendations||[]);
  }
  function aiDirRows(){
    const tool=$("ai-tool").value, cat=$("ai-dir-category").value, impact=$("ai-impact").value, cleanup=$("ai-cleanup").value, min=Number($("ai-size-min").value||0)*1024*1024;
    return (data.ai_related_directories||[]).filter(d=>{
      if(tool && d.tool_name!==tool) return false;
      if(cat && d.category!==cat) return false;
      if(impact && d.context_impact!==impact) return false;
      if(cleanup && String(d.cleanup_candidate)!==cleanup) return false;
      if(min && Number(d.size_bytes||0)<min) return false;
      return true;
    }).sort((a,b)=>{
      let av,bv,key=state.aiDirSort;
      if(key==="size"){ av=Number(a.size_bytes||0); bv=Number(b.size_bytes||0); return (av-bv)*state.aiDirDir; }
      if(key==="impact"){ av=impactOrder[a.context_impact]||0; bv=impactOrder[b.context_impact]||0; return (av-bv)*state.aiDirDir; }
      if(key==="modified"){ av=Date.parse(a.last_modified||"")||0; bv=Date.parse(b.last_modified||"")||0; return (av-bv)*state.aiDirDir; }
      av=key==="tool"?a.tool_name:a.category; bv=key==="tool"?b.tool_name:b.category; return text(av).localeCompare(text(bv))*state.aiDirDir;
    });
  }
  function aiArtifactRows(){
    const tool=$("ai-tool").value, type=$("ai-artifact-type").value, scope=$("ai-scope").value, impact=$("ai-impact").value, auto=$("ai-auto").value, suspicious=$("ai-suspicious").value;
    return (data.ai_context_inventory||[]).filter(a=>{
      if(tool && a.tool_name!==tool) return false;
      if(type && a.artifact_type!==type) return false;
      if(scope && a.scope!==scope) return false;
      if(impact && a.context_impact!==impact) return false;
      if(auto && a.auto_loaded_likelihood!==auto) return false;
      if(suspicious && String(Boolean((a.suspicious_patterns||[]).length))!==suspicious) return false;
      return true;
    }).sort((a,b)=>{
      let av,bv,key=state.aiArtifactSort;
      if(key==="impact"){ av=impactOrder[a.context_impact]||0; bv=impactOrder[b.context_impact]||0; return (av-bv)*state.aiArtifactDir; }
      av=key==="tool"?a.tool_name:key==="type"?a.artifact_type:key==="scope"?a.scope:a.auto_loaded_likelihood;
      bv=key==="tool"?b.tool_name:key==="type"?b.artifact_type:key==="scope"?b.scope:b.auto_loaded_likelihood;
      return text(av).localeCompare(text(bv))*state.aiArtifactDir;
    });
  }
  function renderAIContext(){
    const sum=$("ai-context-summary"); sum.textContent=""; const s=data.ai_context_summary||{};
    addCard(sum,"AI Directories",text(s.total_ai_directories));
    addCard(sum,"AI Disk Usage",bytes(s.total_ai_directory_size_bytes));
    addCard(sum,"Context Artifacts",text(s.total_ai_context_artifacts));
    addCard(sum,"Critical Impact",text(s.critical_context_impact_count),"high");
    addCard(sum,"High Impact",text(s.high_context_impact_count),"medium");
    addCard(sum,"World-writable",text(s.world_writable_ai_artifacts_count),s.world_writable_ai_artifacts_count?"high":"info");
    addCard(sum,"Suspicious Patterns",text(s.suspicious_ai_prompt_patterns_count),s.suspicious_ai_prompt_patterns_count?"medium":"info");
    const dirBody=$("ai-dir-body"); dirBody.textContent="";
    aiDirRows().forEach(d=>{
      const tr=document.createElement("tr");
      [d.tool_name,masked(d.path),d.category,bytes(d.size_bytes),d.file_count,d.last_modified,d.context_impact,d.context_impact_score,d.cleanup_candidate,masked(d.recommendation)].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      dirBody.appendChild(tr);
    });
    const artifactBody=$("ai-artifact-body"); artifactBody.textContent="";
    aiArtifactRows().forEach(a=>{
      const tr=document.createElement("tr");
      const patternText=(a.suspicious_patterns||[]).map(p=>text(p.line)+": "+text(p.pattern)+" | "+masked(p.snippet)).join("\n");
      [a.tool_name,a.artifact_type,masked(a.path),a.scope,bytes(a.size_bytes),a.permissions,a.auto_loaded_likelihood,a.context_impact,patternText||"none",masked(a.recommendation)].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      artifactBody.appendChild(tr);
    });
  }
  function renderAIToolCatalog(){
    const summaryBox=$("ai-provider-summary"); summaryBox.textContent=""; const s=data.ai_provider_summary||{};
    addCard(summaryBox,"AI Tools",text(s.total_ai_tools_detected));
    addCard(summaryBox,"MCP Clients",text(s.total_mcp_clients_detected));
    addCard(summaryBox,"MCP Servers",text(s.total_mcp_servers_detected));
    addCard(summaryBox,"Hermes",s.hermes_detected?"detected":"not detected",s.hermes_detected?"medium":"info");
    addCard(summaryBox,"OpenCode",s.opencode_detected?"detected":"not detected",s.opencode_detected?"medium":"info");
    addCard(summaryBox,"Chinese Providers",text(s.chinese_providers_detected));
    addCard(summaryBox,"Provider Env Keys",text(s.remote_provider_env_keys_detected),s.remote_provider_env_keys_detected?"medium":"info");
    addCard(summaryBox,"Model Cache Size",bytes(s.local_model_cache_size_bytes));
    addCard(summaryBox,"Non-loopback AI Servers",text(s.non_loopback_ai_servers),s.non_loopback_ai_servers?"high":"info");
    const category=$("catalog-category").value, vendor=$("catalog-vendor").value, mcp=$("catalog-mcp").value, min=Number($("catalog-size-min").value||0)*1024*1024;
    const toolBody=$("ai-tool-catalog-body"); toolBody.textContent="";
    (data.ai_tool_catalog||[]).filter(t=>{
      if(category && !(t.categories||[]).includes(category)) return false;
      if(vendor && t.vendor!==vendor) return false;
      if(mcp && String((t.categories||[]).includes("mcp_client")||(t.categories||[]).includes("mcp_server"))!==mcp) return false;
      if(min && Number(t.disk_usage_bytes||0)<min) return false;
      return true;
    }).forEach(t=>{
      const tr=document.createElement("tr");
      [t.display_name,t.vendor,(t.categories||[]).join(", "),masked([...(t.app_paths||[]),...(t.binary_paths||[])].join("\n")),masked((t.config_paths||[]).join("\n")),masked([...(t.cache_paths||[]),...(t.log_paths||[])].join("\n")),bytes(t.disk_usage_bytes),(t.ports||[]).join(", "),(t.risk_notes||[]).join("\n")].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      toolBody.appendChild(tr);
    });
    const hermes=data.hermes_agent||{}; const hermesBox=$("hermes-section"); hermesBox.textContent="";
    addItem(hermesBox,"Hermes installed",[String(Boolean(hermes.detected)),"size="+bytes(hermes.size_bytes),"context_impact="+text(hermes.context_impact||"none"),"env_keys="+(hermes.env_keys_detected||[]).join(", ")]);
    addItem(hermesBox,"Hermes paths",[...(hermes.config_paths||[]),...(hermes.skill_paths||[]),...(hermes.memory_paths||[]),...(hermes.command_paths||[]),...(hermes.cache_log_paths||[])]);
    addItem(hermesBox,"Hermes recommendations",hermes.recommendations||[]);
    const oc=data.opencode||{}; const ocBox=$("opencode-section"); ocBox.textContent="";
    addItem(ocBox,"OpenCode installed",[String(Boolean(oc.detected)),"size="+bytes(oc.size_bytes),"context_impact="+text(oc.context_impact||"none"),"env_keys="+(oc.env_keys_detected||[]).join(", ")]);
    addItem(ocBox,"OpenCode paths",[...(oc.app_paths||[]),...(oc.binary_paths||[]),...(oc.config_paths||[]),...(oc.agent_paths||[]),...(oc.prompt_rule_paths||[]),...(oc.cache_log_paths||[])]);
    addItem(ocBox,"OpenCode recommendations",oc.recommendations||[]);
    const mcpBody=$("mcp-server-body"); mcpBody.textContent="";
    (data.mcp_servers||[]).filter(sv=>!mcp || "true"===mcp).forEach(sv=>{
      const risks="cmd="+text(sv.command_execution_risk)+" fs="+text(sv.filesystem_access_risk)+" net="+text(sv.network_exfiltration_risk)+" cred="+text(sv.credential_access_risk)+" cloud="+text(sv.cloud_access_risk)+" browser="+text(sv.browser_automation_risk);
      const tr=document.createElement("tr");
      [sv.server_name,sv.risk_category,sv.scope,masked(sv.config_path),masked(sv.command),(sv.env_keys_only||[]).join(", "),risks,sv.recommendation].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      mcpBody.appendChild(tr);
    });
    const family=$("provider-family").value, china=$("china-origin").value, hasEnv=$("provider-env").value;
    const providerBody=$("chinese-provider-body"); providerBody.textContent="";
    (data.chinese_ai_providers||[]).filter(p=>{
      if(vendor && p.vendor!==vendor) return false;
      if(family && !(p.families||[]).includes(family)) return false;
      if(china && String(p.country_or_region==="China")!==china) return false;
      if(hasEnv && String(Boolean((p.env_keys_detected||[]).length))!==hasEnv) return false;
      return true;
    }).forEach(p=>{
      const tr=document.createElement("tr");
      [p.display_name,p.vendor,(p.families||[]).join(", "),(p.env_keys_detected||[]).join(", "),masked((p.config_paths||[]).join("\n")),masked((p.cache_paths||[]).join("\n")),bytes(p.local_cache_size_bytes),p.risk_level,masked(p.recommendation)].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      providerBody.appendChild(tr);
    });
    const modelBody=$("local-model-body"); modelBody.textContent="";
    (data.local_model_inventory||[]).filter(m=>!min || Number(m.size_bytes||0)>=min).forEach(m=>{
      const tr=document.createElement("tr");
      [m.tool_name,m.provider_hint,masked(m.path),bytes(m.size_bytes),m.file_count,m.last_modified,m.safe_to_auto_clean,masked(m.recommendation)].forEach(v=>{const td=document.createElement("td"); td.textContent=text(v); tr.appendChild(td);});
      modelBody.appendChild(tr);
    });
    const securityBox=$("ai-security-tools-section"); securityBox.textContent="";
    (data.ai_security_tools||[]).forEach(t=>addItem(securityBox,t.name,["positive_signal="+text(t.positive_security_signal),...(t.paths||[]),...(t.risk_notes||[])]));
    if(!(data.ai_security_tools||[]).length) addItem(securityBox,"No AI security tools found",["No scoped AI security scanner configs were found."]);
  }
  function renderCleanup(){
    const box=$("cleanup-section"); box.textContent="";
    (data.cleanup_candidates||[]).forEach(c=>addItem(box,c.path,["size="+bytes(c.estimated_size_bytes),"risk="+text(c.risk),"safe_to_auto_fix="+text(c.safe_to_auto_fix),"reason="+text(c.reason)]));
    if(!(data.cleanup_candidates||[]).length) addItem(box,"No cleanup candidates",["No allowlisted cleanup candidates were found."]);
  }
  function renderAll(){ renderSummary(); renderFindings(); renderAI(); renderAIContext(); renderAIToolCatalog(); renderCleanup(); }
  ["search","severity","category","status","special","privacy","ai-tool","ai-dir-category","ai-artifact-type","ai-scope","ai-impact","ai-auto","ai-cleanup","ai-suspicious","ai-size-min","catalog-category","catalog-vendor","provider-family","china-origin","provider-env","catalog-mcp","catalog-size-min"].forEach(id=>$(id).addEventListener("input",renderAll));
  document.querySelectorAll("th[data-sort]").forEach(th=>th.addEventListener("click",()=>{ const key=th.getAttribute("data-sort"); state.dir = state.sort===key ? -state.dir : 1; state.sort=key; renderFindings(); }));
  document.querySelectorAll("th[data-ai-dir-sort]").forEach(th=>th.addEventListener("click",()=>{ const key=th.getAttribute("data-ai-dir-sort"); state.aiDirDir = state.aiDirSort===key ? -state.aiDirDir : -1; state.aiDirSort=key; renderAIContext(); }));
  document.querySelectorAll("th[data-ai-artifact-sort]").forEach(th=>th.addEventListener("click",()=>{ const key=th.getAttribute("data-ai-artifact-sort"); state.aiArtifactDir = state.aiArtifactSort===key ? -state.aiArtifactDir : -1; state.aiArtifactSort=key; renderAIContext(); }));
  $("print").addEventListener("click",()=>window.print());
  $("copy").addEventListener("click",()=>{ const s=data.summary||{}; const summary="quietscope "+text((data.metadata||{}).version)+": score "+text(s.overall_risk_score)+"/100 ("+text(s.risk_level)+"), findings "+text(s.total_findings)+", cleanup "+bytes(s.cleanup_reclaimable_bytes); if(navigator.clipboard){navigator.clipboard.writeText(summary).catch(()=>window.prompt("Copy summary",summary));} else {window.prompt("Copy summary",summary);} });
  renderAll();
})();
</script>
</main>
</body>
</html>`
