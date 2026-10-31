"""
SYNTAXIS Web Dashboard
A lightweight built-in web server that exposes the auditor pipeline
through a browser UI. No extra dependencies beyond the project itself.

Usage:
    python web/app.py [--port 7272]
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Ensure stdout uses UTF-8
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REPO_ROOT = Path(__file__).parent.parent.resolve()
STATIC_DIR = Path(__file__).parent / "static"
JOBS: dict[str, dict] = {}   # job_id -> {status, output, result}
JOBS_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# HTML page (single-file SPA served from Python)
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SYNTAXIS - Vulnerability Auditor</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--text:#e6edf3;--muted:#8b949e;--font:'Segoe UI',system-ui,sans-serif}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh}
  header{background:var(--card);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
  header h1{font-size:1.4rem;font-weight:700;color:var(--accent)}
  header span{color:var(--muted);font-size:.85rem}
  nav{display:flex;gap:.25rem;margin-left:auto}
  nav button{background:none;border:1px solid var(--border);color:var(--muted);padding:.4rem .9rem;border-radius:6px;cursor:pointer;font-size:.85rem;transition:all .15s}
  nav button.active,nav button:hover{background:var(--accent);color:#000;border-color:var(--accent)}
  main{max-width:1100px;margin:0 auto;padding:2rem}
  .panel{display:none}.panel.active{display:block}
  h2{font-size:1.1rem;margin-bottom:1.2rem;color:var(--text)}
  .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.2rem}
  label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:.4rem}
  input,select{width:100%;background:#010409;border:1px solid var(--border);color:var(--text);padding:.6rem .8rem;border-radius:6px;font-size:.9rem;outline:none}
  input:focus,select:focus{border-color:var(--accent)}
  .row{display:flex;gap:.8rem;flex-wrap:wrap;align-items:flex-end;margin-top:1rem}
  .field{flex:1;min-width:200px}
  .chk{display:flex;align-items:center;gap:.4rem;font-size:.85rem;color:var(--muted);padding-top:1.4rem}
  .chk input{width:auto}
  button.btn{background:var(--accent);color:#000;border:none;padding:.6rem 1.4rem;border-radius:6px;cursor:pointer;font-weight:600;font-size:.9rem;transition:opacity .15s}
  button.btn:hover{opacity:.85}
  button.btn.danger{background:var(--red);color:#fff}
  button.btn.muted{background:var(--border);color:var(--text)}
  pre{background:#010409;border:1px solid var(--border);border-radius:6px;padding:1rem;font-size:.78rem;line-height:1.6;overflow-x:auto;white-space:pre-wrap;max-height:420px;overflow-y:auto}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.72rem;font-weight:600;text-transform:uppercase}
  .badge.CRITICAL{background:#6e1d1d;color:#f85149}
  .badge.HIGH{background:#3d2800;color:#d29922}
  .badge.MEDIUM{background:#1b2d00;color:#7ee787}
  .badge.LOW{background:#1b2834;color:#58a6ff}
  .badge.INFO{background:#1c2128;color:#8b949e}
  .badge.ok{background:#0d2d1a;color:#3fb950}
  .badge.err{background:#2d0d0d;color:#f85149}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;color:var(--muted);padding:.5rem .7rem;border-bottom:1px solid var(--border);font-weight:500}
  td{padding:.55rem .7rem;border-bottom:1px solid #21262d;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#1c2128}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:.4rem}
  @keyframes spin{to{transform:rotate(360deg)}}
  .metric{display:flex;flex-direction:column;align-items:center;background:#010409;border:1px solid var(--border);border-radius:8px;padding:1rem 1.5rem}
  .metric .val{font-size:2rem;font-weight:700;color:var(--accent);line-height:1}
  .metric .lbl{font-size:.75rem;color:var(--muted);margin-top:.3rem}
  .metrics-row{display:flex;gap:.8rem;flex-wrap:wrap;margin-bottom:1.2rem}
  .job-status{font-size:.82rem;padding:.4rem .8rem;border-radius:6px;display:inline-flex;align-items:center;gap:.4rem}
  .job-status.running{background:#0d2834;color:var(--accent)}
  .job-status.done{background:#0d2d1a;color:var(--green)}
  .job-status.error{background:#2d0d0d;color:var(--red)}
  .findings-empty{color:var(--muted);font-size:.9rem;text-align:center;padding:2rem}
  .tab-bar{display:flex;gap:.3rem;margin-bottom:1rem}
  .tab{background:none;border:1px solid var(--border);color:var(--muted);padding:.35rem .9rem;border-radius:6px;cursor:pointer;font-size:.82rem}
  .tab.active{background:#1c2128;color:var(--text);border-color:var(--accent)}
</style>
</head>
<body>
<header>
  <div>
    <h1>&#9658; SYNTAXIS</h1>
    <span>Automated Multi-Agent Codebase Vulnerability &amp; Dependency Auditor</span>
  </div>
  <nav>
    <button class="active" onclick="show('scan',this)">Scan</button>
    <button onclick="show('remediate',this)">Remediate</button>
    <button onclick="show('evaluate',this)">Benchmark</button>
    <button onclick="show('reports',this)">Reports</button>
  </nav>
</header>
<main>

<!-- ===== SCAN PANEL ===== -->
<div id="panel-scan" class="panel active">
  <h2>Security Scan</h2>
  <div class="card">
    <label>Target path (local directory)</label>
    <input id="scan-target" type="text" placeholder="e.g. benchmarks/fixtures/cmd  or  C:\path\to\project" value="benchmarks/fixtures/cmd"/>
    <div class="row">
      <div class="field"><label>Output format</label>
        <select id="scan-fmt"><option value="json,markdown">JSON + Markdown</option><option value="json">JSON only</option><option value="markdown">Markdown only</option></select>
      </div>
      <div class="chk"><input type="checkbox" id="scan-offline" checked/><label>Offline mode</label></div>
      <div class="chk"><input type="checkbox" id="scan-nollm" checked/><label>No LLM</label></div>
      <div class="chk"><input type="checkbox" id="scan-noagents"/><label>No agents</label></div>
      <div class="chk"><input type="checkbox" id="scan-nosast"/><label>No SAST</label></div>
      <div class="chk"><input type="checkbox" id="scan-nodeps"/><label>No deps</label></div>
      <button class="btn" onclick="runScan()">Run Scan</button>
    </div>
  </div>
  <div id="scan-status"></div>
  <div id="scan-results"></div>
</div>

<!-- ===== REMEDIATE PANEL ===== -->
<div id="panel-remediate" class="panel">
  <h2>Remediation</h2>
  <div class="card">
    <label>Target path</label>
    <input id="rem-target" type="text" placeholder="e.g. benchmarks/fixtures/remediation" value="benchmarks/fixtures/remediation"/>
    <div class="row">
      <div class="chk"><input type="checkbox" id="rem-offline"/><label>Offline</label></div>
      <div class="chk"><input type="checkbox" id="rem-nollm" checked/><label>No LLM</label></div>
      <div class="chk"><input type="checkbox" id="rem-validate" checked/><label>Validate patches</label></div>
      <button class="btn" onclick="runRemediate()">Generate Patches</button>
    </div>
  </div>
  <div id="rem-status"></div>
  <div id="rem-results"></div>
</div>

<!-- ===== EVALUATE PANEL ===== -->
<div id="panel-evaluate" class="panel">
  <h2>Benchmark Evaluation</h2>
  <div class="card">
    <label>Dataset manifest</label>
    <input id="eval-dataset" type="text" value="benchmarks/manifest.json"/>
    <div class="row">
      <div class="field"><label>Category filter (leave blank for all)</label>
        <select id="eval-cat">
          <option value="">All categories</option>
          <option value="sql">sql</option>
          <option value="cmd">cmd</option>
          <option value="path">path</option>
          <option value="deser">deser</option>
          <option value="xss">xss</option>
          <option value="deps">deps</option>
          <option value="graph">graph</option>
          <option value="remediation">remediation</option>
        </select>
      </div>
      <div class="chk"><input type="checkbox" id="eval-offline" checked/><label>Offline</label></div>
      <div class="chk"><input type="checkbox" id="eval-nollm" checked/><label>No LLM</label></div>
      <button class="btn" onclick="runEval()">Run Benchmark</button>
    </div>
  </div>
  <div id="eval-status"></div>
  <div id="eval-results"></div>
</div>

<!-- ===== REPORTS PANEL ===== -->
<div id="panel-reports" class="panel">
  <h2>Saved Reports</h2>
  <div class="card">
    <button class="btn muted" onclick="loadReports()">Refresh</button>
    <div id="reports-list" style="margin-top:1rem"></div>
  </div>
</div>

</main>
<script>
// ---- nav ----
function show(id, btn) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById('panel-'+id).classList.add('active');
  btn.classList.add('active');
  if(id==='reports') loadReports();
}

// ---- job polling ----
function pollJob(jobId, statusEl, onDone) {
  let dots = 0;
  const iv = setInterval(async()=>{
    const r = await fetch('/api/job/'+jobId);
    const d = await r.json();
    dots=(dots+1)%4;
    statusEl.innerHTML = `<div class="job-status running"><span class="spinner"></span>Running${'.'.repeat(dots+1)}</div>`;
    if(d.status==='done'||d.status==='error'){
      clearInterval(iv);
      onDone(d);
    }
  }, 800);
}

// ---- SCAN ----
async function runScan() {
  const statusEl = document.getElementById('scan-status');
  const resultsEl = document.getElementById('scan-results');
  resultsEl.innerHTML='';
  statusEl.innerHTML='<div class="job-status running"><span class="spinner"></span>Starting scan...</div>';
  const body = {
    target: document.getElementById('scan-target').value,
    format: document.getElementById('scan-fmt').value,
    offline: document.getElementById('scan-offline').checked,
    no_llm: document.getElementById('scan-nollm').checked,
    no_agents: document.getElementById('scan-noagents').checked,
    no_sast: document.getElementById('scan-nosast').checked,
    no_deps: document.getElementById('scan-nodeps').checked,
  };
  const r = await fetch('/api/scan', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const {job_id} = await r.json();
  pollJob(job_id, statusEl, d=>{
    if(d.status==='error'){
      statusEl.innerHTML='<div class="job-status error">Error</div>';
      resultsEl.innerHTML=`<div class="card"><pre>${esc(d.output)}</pre></div>`;
    } else {
      statusEl.innerHTML='<div class="job-status done">Done</div>';
      renderScanResults(d.result, d.output, resultsEl);
    }
  });
}

function renderScanResults(res, raw, el) {
  if(!res){el.innerHTML=`<div class="card"><pre>${esc(raw)}</pre></div>`;return;}
  const findings = res.findings||[];
  const sum = res.summary||{};
  let html=`<div class="card">
    <div class="metrics-row">
      <div class="metric"><div class="val">${findings.length}</div><div class="lbl">Total Findings</div></div>
      <div class="metric"><div class="val" style="color:var(--red)">${sum.critical_count||0}</div><div class="lbl">Critical</div></div>
      <div class="metric"><div class="val" style="color:var(--yellow)">${sum.high_count||0}</div><div class="lbl">High</div></div>
      <div class="metric"><div class="val" style="color:var(--green)">${sum.medium_count||0}</div><div class="lbl">Medium</div></div>
      <div class="metric"><div class="val">${sum.files_analyzed||0}</div><div class="lbl">Files Analyzed</div></div>
      <div class="metric"><div class="val">${(sum.analysis_duration_seconds||0).toFixed(2)}s</div><div class="lbl">Duration</div></div>
    </div>`;
  if(findings.length===0){
    html+=`<div class="findings-empty">No findings detected.</div>`;
  } else {
    html+=`<table><thead><tr><th>Severity</th><th>Type</th><th>Title</th><th>Location</th><th>Remediation</th></tr></thead><tbody>`;
    for(const f of findings){
      const loc = f.location?`${f.location.file_path}:${f.location.line}`:(f.affected_file||'');
      html+=`<tr>
        <td><span class="badge ${f.severity}">${f.severity}</span></td>
        <td><code style="font-size:.75rem">${f.cwe_id||f.finding_type||''}</code></td>
        <td>${esc(f.title)}</td>
        <td style="font-family:monospace;font-size:.78rem">${esc(loc)}</td>
        <td style="font-size:.78rem;color:var(--muted)">${esc((f.remediation_advice||'').substring(0,120))}${(f.remediation_advice||'').length>120?'…':''}</td>
      </tr>`;
    }
    html+=`</tbody></table>`;
  }
  html+=`</div><div class="card"><label>Raw output</label><pre>${esc(raw)}</pre></div>`;
  el.innerHTML=html;
}

// ---- REMEDIATE ----
async function runRemediate() {
  const statusEl = document.getElementById('rem-status');
  const resultsEl = document.getElementById('rem-results');
  resultsEl.innerHTML='';
  statusEl.innerHTML='<div class="job-status running"><span class="spinner"></span>Starting remediation...</div>';
  const body = {
    target: document.getElementById('rem-target').value,
    offline: document.getElementById('rem-offline').checked,
    no_llm: document.getElementById('rem-nollm').checked,
    validate: document.getElementById('rem-validate').checked,
  };
  const r = await fetch('/api/remediate', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const {job_id} = await r.json();
  pollJob(job_id, statusEl, d=>{
    if(d.status==='error'){
      statusEl.innerHTML='<div class="job-status error">Error</div>';
      resultsEl.innerHTML=`<div class="card"><pre>${esc(d.output)}</pre></div>`;
    } else {
      statusEl.innerHTML='<div class="job-status done">Done</div>';
      resultsEl.innerHTML=`<div class="card"><pre>${esc(d.output)}</pre></div>`;
    }
  });
}

// ---- EVALUATE ----
async function runEval() {
  const statusEl = document.getElementById('eval-status');
  const resultsEl = document.getElementById('eval-results');
  resultsEl.innerHTML='';
  statusEl.innerHTML='<div class="job-status running"><span class="spinner"></span>Running benchmark...</div>';
  const cat = document.getElementById('eval-cat').value;
  const body = {
    dataset: document.getElementById('eval-dataset').value,
    offline: document.getElementById('eval-offline').checked,
    no_llm: document.getElementById('eval-nollm').checked,
    category: cat||null,
  };
  const r = await fetch('/api/evaluate', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const {job_id} = await r.json();
  pollJob(job_id, statusEl, d=>{
    if(d.status==='error'){
      statusEl.innerHTML='<div class="job-status error">Error</div>';
      resultsEl.innerHTML=`<div class="card"><pre>${esc(d.output)}</pre></div>`;
    } else {
      statusEl.innerHTML='<div class="job-status done">Done</div>';
      renderEvalResults(d.result, d.output, resultsEl);
    }
  });
}

function renderEvalResults(res, raw, el) {
  if(!res){el.innerHTML=`<div class="card"><pre>${esc(raw)}</pre></div>`;return;}
  const m = res.overall_metrics||{};
  let html=`<div class="card">
    <div class="metrics-row">
      <div class="metric"><div class="val" style="color:var(--green)">${m.tp||0}</div><div class="lbl">True Positives</div></div>
      <div class="metric"><div class="val" style="color:var(--green)">${m.tn||0}</div><div class="lbl">True Negatives</div></div>
      <div class="metric"><div class="val" style="color:var(--red)">${m.fp||0}</div><div class="lbl">False Positives</div></div>
      <div class="metric"><div class="val" style="color:var(--yellow)">${m.fn||0}</div><div class="lbl">False Negatives</div></div>
      <div class="metric"><div class="val">${fmt(m.precision)}</div><div class="lbl">Precision</div></div>
      <div class="metric"><div class="val">${fmt(m.recall)}</div><div class="lbl">Recall</div></div>
      <div class="metric"><div class="val" style="color:var(--accent)">${fmt(m.f1)}</div><div class="lbl">F1 Score</div></div>
      <div class="metric"><div class="val">${fmt(m.accuracy)}</div><div class="lbl">Accuracy</div></div>
    </div>`;
  const per = res.per_category||{};
  if(Object.keys(per).length>0){
    html+=`<h2 style="margin-bottom:.8rem;font-size:.9rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">Per Category</h2>
    <table><thead><tr><th>Category</th><th>TP</th><th>TN</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>`;
    for(const [cat,cm] of Object.entries(per)){
      html+=`<tr><td><strong>${cat}</strong></td><td>${cm.tp}</td><td>${cm.tn}</td><td>${cm.fp}</td><td>${cm.fn}</td><td>${fmt(cm.precision)}</td><td>${fmt(cm.recall)}</td><td>${fmt(cm.f1)}</td></tr>`;
    }
    html+=`</tbody></table>`;
  }
  const cases = res.case_results||[];
  if(cases.length>0){
    html+=`<br><h2 style="margin-bottom:.8rem;font-size:.9rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">Case Results</h2>
    <table><thead><tr><th>ID</th><th>Category</th><th>Label</th><th>Status</th><th>Findings</th><th>CWE Match</th><th>Time</th></tr></thead><tbody>`;
    for(const c of cases){
      const sc = {tp:'ok',tn:'ok',fp:'err',fn:'err',error:'err',ambiguous:'INFO'}[c.status]||'INFO';
      html+=`<tr>
        <td><code>${c.case_id}</code></td>
        <td>${c.category}</td>
        <td>${c.label}</td>
        <td><span class="badge ${sc}">${c.status.toUpperCase()}</span></td>
        <td>${c.findings_count}</td>
        <td>${c.matched_cwe?'<span style="color:var(--green)">Yes</span>':'<span style="color:var(--muted)">No</span>'}</td>
        <td>${(c.duration_seconds||0).toFixed(3)}s</td>
      </tr>`;
    }
    html+=`</tbody></table>`;
  }
  html+=`</div><div class="card"><label>Raw output</label><pre>${esc(raw)}</pre></div>`;
  el.innerHTML=html;
}

// ---- REPORTS ----
async function loadReports() {
  const el = document.getElementById('reports-list');
  el.innerHTML='<span class="spinner"></span> Loading...';
  const r = await fetch('/api/reports');
  const d = await r.json();
  if(!d.reports||d.reports.length===0){el.innerHTML='<div class="findings-empty">No reports found.</div>';return;}
  let html='<table><thead><tr><th>File</th><th>Type</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>';
  for(const rp of d.reports){
    html+=`<tr>
      <td style="font-family:monospace;font-size:.8rem">${esc(rp.name)}</td>
      <td><span class="badge ${rp.ext==='json'?'ok':'INFO'}">${rp.ext.toUpperCase()}</span></td>
      <td>${rp.size}</td>
      <td style="color:var(--muted)">${rp.mtime}</td>
      <td><a href="/api/report-file?path=${encodeURIComponent(rp.path)}" target="_blank" style="color:var(--accent);font-size:.8rem">Open</a></td>
    </tr>`;
  }
  html+='</tbody></table>';
  el.innerHTML=html;
}

function fmt(v){return v!=null?v.toFixed(4):'N/A'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

window.onload=()=>loadReports();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _run_job(job_id: str, cmd: list[str], result_path: str | None = None):
    """Run a CLI command in a background thread, storing output in JOBS."""
    def _worker():
        with JOBS_LOCK:
            JOBS[job_id] = {"status": "running", "output": "", "result": None}
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(REPO_ROOT),
                env=env,
            )
            output = proc.stdout + proc.stderr
            result = None
            if result_path and Path(result_path).exists():
                try:
                    result = json.loads(Path(result_path).read_text(encoding="utf-8"))
                except Exception:
                    pass
            with JOBS_LOCK:
                JOBS[job_id] = {"status": "done", "output": output, "result": result}
        except Exception as exc:
            with JOBS_LOCK:
                JOBS[job_id] = {"status": "error", "output": str(exc), "result": None}

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def _get_reports() -> list[dict]:
    reports_dir = REPO_ROOT / "reports"
    items = []
    if reports_dir.exists():
        for p in sorted(reports_dir.rglob("*"), key=lambda x: x.stat().st_mtime, reverse=True):
            if p.is_file() and p.suffix in (".json", ".md", ".txt"):
                stat = p.stat()
                items.append({
                    "name": p.name,
                    "path": str(p),
                    "ext": p.suffix.lstrip("."),
                    "size": f"{stat.st_size:,} B" if stat.st_size < 10240 else f"{stat.st_size//1024:,} KB",
                    "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
                })
    return items


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress request logging

    def _json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._html(HTML)
            return

        if path == "/api/reports":
            self._json({"reports": _get_reports()})
            return

        if path.startswith("/api/job/"):
            job_id = path.split("/")[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id, {"status": "not_found", "output": "", "result": None})
            self._json(job)
            return

        if path == "/api/report-file":
            qs = parse_qs(parsed.query)
            file_path = qs.get("path", [""])[0]
            p = Path(file_path)
            # Safety: must be inside REPO_ROOT/reports
            try:
                p.resolve().relative_to((REPO_ROOT / "reports").resolve())
            except ValueError:
                self._json({"error": "Access denied"}, 403)
                return
            if not p.exists():
                self._json({"error": "Not found"}, 404)
                return
            content = p.read_text(encoding="utf-8", errors="replace")
            ct = "application/json" if p.suffix == ".json" else "text/plain"
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ct + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path == "/api/scan":
            job_id = str(uuid.uuid4())[:8]
            target = body.get("target", ".")
            fmt = body.get("format", "json,markdown")
            args = [sys.executable, "-m", "auditor.cli", "scan", target, "--format", fmt]
            out_file = None
            if body.get("offline"):
                args.append("--offline")
            if body.get("no_llm"):
                args.append("--no-llm")
            if body.get("no_agents"):
                args.append("--no-agents")
            if body.get("no_sast"):
                args.append("--no-sast")
            if body.get("no_deps"):
                args.append("--no-deps")
            # write JSON to a temp file so we can parse findings
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                out_file = tf.name
            args += ["-o", out_file]
            _run_job(job_id, args, result_path=out_file)
            self._json({"job_id": job_id})
            return

        if path == "/api/remediate":
            job_id = str(uuid.uuid4())[:8]
            target = body.get("target", ".")
            args = [sys.executable, "-m", "auditor.cli", "remediate", target, "--no-llm"]
            if body.get("offline"):
                args.append("--offline")
            if body.get("validate"):
                args.append("--validate")
            _run_job(job_id, args)
            self._json({"job_id": job_id})
            return

        if path == "/api/evaluate":
            job_id = str(uuid.uuid4())[:8]
            dataset = body.get("dataset", "benchmarks/manifest.json")
            args = [sys.executable, "-m", "auditor.cli", "evaluate", "--dataset", dataset]
            if body.get("offline"):
                args.append("--offline")
            if body.get("no_llm"):
                args.append("--no-llm")
            if body.get("category"):
                args += ["--category", body["category"]]
            # capture JSON report
            out_dir = REPO_ROOT / "reports" / "evaluation"
            out_dir.mkdir(parents=True, exist_ok=True)
            run_id = str(uuid.uuid4())[:8]
            result_file = out_dir / f"evaluation_{run_id}.json"
            args += ["--output-dir", str(out_dir), "--format", "json,markdown"]
            _run_job(job_id, args, result_path=str(result_file))
            self._json({"job_id": job_id})
            return

        self._json({"error": "Not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="SYNTAXIS Web Dashboard")
    ap.add_argument("--port", type=int, default=7272)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    host = "127.0.0.1"
    port = args.port
    url = f"http://{host}:{port}"

    server = HTTPServer((host, port), Handler)
    print(f"SYNTAXIS Dashboard running at {url}")
    print("Press Ctrl+C to stop.")

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()

