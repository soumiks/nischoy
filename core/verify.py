#!/usr/bin/env python3
"""
Nischoy.ai Verification Runner
Parses C code, converts to SMT2, applies security constraints, runs Z3.
Outputs results as an HTML fragment for the dashboard.
"""
import sys
import os
import json
import time

# Add core dir to path
sys.path.insert(0, os.path.dirname(__file__))

from parser import CParser
from converter import SMTConverter
from constraints import SecurityConstraints
import z3

def run_check(name, ast, constraint_fn):
    """Run a single verification check. Returns a result dict."""
    converter = SMTConverter()
    solver, vars_dict = converter.convert(ast)
    
    violation = constraint_fn(vars_dict)
    if violation is None:
        return {"name": name, "status": "SKIPPED", "reason": "No matching variables"}
    
    # Push a new scope so we can add the violation without polluting the solver
    solver.push()
    solver.add(violation)
    
    start = time.time()
    result = solver.check()
    elapsed = time.time() - start
    
    smt2 = solver.to_smt2()
    solver.pop()
    
    status = "VERIFIED" if result == z3.unsat else "FAILED"
    
    return {
        "name": name,
        "function": ast["function"],
        "status": status,
        "elapsed_ms": round(elapsed * 1000, 1),
        "smt2": smt2
    }

def generate_html(results, project, version):
    """Generate a full results HTML page."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    
    cards = ""
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "VERIFIED")
    failed = sum(1 for r in results if r["status"] == "FAILED")
    
    for r in results:
        color = "green" if r["status"] == "VERIFIED" else "red"
        smt2_block = ""
        if r.get("smt2"):
            smt2_block = f"""
      <details>
        <summary>View SMT2 Constraints</summary>
        <pre><code>{r['smt2']}</code></pre>
      </details>"""
        
        cards += f"""
    <div class="result-card {color}">
      <div class="result-header">
        <span class="status-dot {color}"></span>
        <h3>{r['name']}</h3>
        <span class="badge {color}">{r['status']}</span>
      </div>
      <p class="result-meta">Function: <code>{r.get('function', 'N/A')}</code> · Z3 solved in {r.get('elapsed_ms', '?')}ms</p>{smt2_block}
    </div>"""

    overall_color = "green" if failed == 0 else "red"
    overall_status = "ALL VERIFIED" if failed == 0 else f"{failed} FAILED"

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nischoy — {project} Verification Results</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    :root {{
      --bg: #0a0e17;
      --bg-card: #111827;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #22d3ee;
      --green: #22c55e;
      --red: #ef4444;
      --border: #1e293b;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      line-height: 1.6;
    }}
    .container {{ max-width: 800px; margin: 0 auto; padding: 3rem 2rem; }}
    .back-link {{ color: var(--text-muted); text-decoration: none; font-size: 0.9rem; }}
    .back-link:hover {{ color: var(--accent); }}
    h1 {{
      font-size: 2.2rem; font-weight: 800; margin: 2rem 0 0.5rem;
      background: linear-gradient(135deg, #06b6d4, #8b5cf6);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }}
    .summary {{
      display: flex; gap: 1.5rem; margin: 2rem 0;
      flex-wrap: wrap;
    }}
    .summary-card {{
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px;
    }}
    .summary-card .num {{ font-size: 2rem; font-weight: 800; }}
    .summary-card .label {{ font-size: 0.8rem; color: var(--text-muted); }}
    .summary-card.{overall_color} {{ border-color: var(--{overall_color}); }}
    .result-card {{
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem;
    }}
    .result-card.green {{ border-left: 3px solid var(--green); }}
    .result-card.red {{ border-left: 3px solid var(--red); }}
    .result-header {{ display: flex; align-items: center; gap: 0.75rem; }}
    .result-header h3 {{ flex: 1; font-size: 1rem; }}
    .status-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
    .status-dot.green {{ background: var(--green); box-shadow: 0 0 8px rgba(34, 197, 94, 0.5); }}
    .status-dot.red {{ background: var(--red); box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }}
    .badge {{
      padding: 0.15rem 0.5rem; border-radius: 4px;
      font-size: 0.75rem; font-weight: 700;
    }}
    .badge.green {{ background: rgba(34, 197, 94, 0.15); color: var(--green); }}
    .badge.red {{ background: rgba(239, 68, 68, 0.15); color: var(--red); }}
    .result-meta {{ color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem; }}
    code {{ background: rgba(34, 211, 238, 0.1); padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85rem; }}
    details {{ margin-top: 1rem; }}
    summary {{ cursor: pointer; color: var(--accent); font-size: 0.85rem; }}
    pre {{
      background: #000; padding: 1rem; border-radius: 8px;
      overflow-x: auto; font-size: 0.8rem; color: var(--text-muted);
      margin-top: 0.5rem;
    }}
    .timestamp {{ color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; }}
  </style>
</head>
<body>
  <div class="container">
    <a href="/" class="back-link">← nischoy.ai</a>
    <h1>{project} Verification</h1>
    <p style="color: var(--text-muted); margin-bottom: 0.5rem;">
      SMT2 formal verification of security-critical code paths
    </p>

    <div class="summary">
      <div class="summary-card {overall_color}">
        <div class="num" style="color: var(--{overall_color})">{overall_status}</div>
        <div class="label">Overall</div>
      </div>
      <div class="summary-card">
        <div class="num">{total}</div>
        <div class="label">Properties Checked</div>
      </div>
      <div class="summary-card">
        <div class="num" style="color: var(--green)">{passed}</div>
        <div class="label">Verified</div>
      </div>
      <div class="summary-card">
        <div class="num" style="color: var(--red)">{failed}</div>
        <div class="label">Failed</div>
      </div>
    </div>

    {cards}

    <p class="timestamp">Last verified: {timestamp} · Solver: Z3 {z3.get_version_string()}</p>
  </div>
</body>
</html>"""
    return html


def generate_dashboard(projects):
    """Generate the top-level results.html with one row per project."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    total_projects = len(projects)
    all_green = all(p["status"] == "VERIFIED" for p in projects)

    rows = ""
    for p in sorted(projects, key=lambda x: x["name"]):
        color = "green" if p["status"] == "VERIFIED" else "red"
        rows += f"""
    <a href="/{p['slug']}.html" class="project-row {color}">
      <div class="project-left">
        <span class="status-dot {color}"></span>
        <div>
          <div class="project-name">{p['name']}</div>
          <div class="project-meta">{p['version']} · {p['language']} · {p['checks']} properties checked</div>
        </div>
      </div>
      <span class="badge {color}">{p['status']}</span>
    </a>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nischoy — Verification Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    :root {{
      --bg: #0a0e17; --bg-card: #111827; --text: #e2e8f0;
      --text-muted: #94a3b8; --accent: #22d3ee;
      --green: #22c55e; --red: #ef4444; --border: #1e293b;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      line-height: 1.6;
    }}
    .container {{ max-width: 800px; margin: 0 auto; padding: 3rem 2rem; }}
    .back-link {{ color: var(--text-muted); text-decoration: none; font-size: 0.9rem; }}
    .back-link:hover {{ color: var(--accent); }}
    h1 {{
      font-size: 2.2rem; font-weight: 800; margin: 2rem 0 0.5rem;
      background: linear-gradient(135deg, #06b6d4, #8b5cf6);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }}
    .subtitle {{ color: var(--text-muted); margin-bottom: 2.5rem; }}
    .project-row {{
      display: flex; align-items: center; justify-content: space-between;
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 0.75rem;
      text-decoration: none; color: var(--text); transition: all 0.2s;
    }}
    .project-row:hover {{ border-color: var(--accent); transform: translateY(-1px); }}
    .project-row.green {{ border-left: 3px solid var(--green); }}
    .project-row.red {{ border-left: 3px solid var(--red); }}
    .project-left {{ display: flex; align-items: center; gap: 1rem; }}
    .status-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
    .status-dot.green {{ background: var(--green); box-shadow: 0 0 8px rgba(34, 197, 94, 0.5); }}
    .status-dot.red {{ background: var(--red); box-shadow: 0 0 8px rgba(239, 68, 68, 0.5); }}
    .project-name {{ font-weight: 700; font-size: 1.1rem; }}
    .project-meta {{ color: var(--text-muted); font-size: 0.8rem; }}
    .badge {{
      padding: 0.2rem 0.6rem; border-radius: 4px;
      font-size: 0.75rem; font-weight: 700;
    }}
    .badge.green {{ background: rgba(34, 197, 94, 0.15); color: var(--green); }}
    .badge.red {{ background: rgba(239, 68, 68, 0.15); color: var(--red); }}
    .timestamp {{ color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; }}
    .count {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
  </style>
</head>
<body>
  <div class="container">
    <a href="/" class="back-link">← nischoy.ai</a>
    <h1>Verification Dashboard</h1>
    <p class="subtitle">SMT2 formal verification of security-critical open source code paths.</p>
    <p class="count">{total_projects} project(s) verified</p>
    {rows}
    <p class="timestamp">Last updated: {timestamp} · Solver: Z3 {z3.get_version_string()}</p>
  </div>
</body>
</html>"""


def run_project_checks(project_slug, project_name, version, language, source_file, checks_config):
    if not os.path.exists(source_file):
        print(f"ERROR: {project_name} source not found at {source_file}. Clone it first.")
        return False
        
    parser = CParser(source_file)
    results = []
    for name, ast, constraint_fn in checks_config(parser):
        print(f"  [{project_name}] Checking: {name}...")
        r = run_check(name, ast, constraint_fn)
        print(f"    → {r['status']} ({r.get('elapsed_ms', '?')}ms)")
        results.append(r)
        
    # Generate per-project detail page
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'public')
    os.makedirs(output_dir, exist_ok=True)
    
    detail_path = os.path.join(output_dir, f'{project_slug}.html')
    detail_html = generate_html(results, project_name, version)
    with open(detail_path, 'w') as f:
        f.write(detail_html)
    print(f"Detail page written to {detail_path}")
    
    failed = sum(1 for r in results if r["status"] == "FAILED")
    total = len(results)
    passed = total - failed
    
    project_result = {
        "slug": project_slug,
        "name": project_name,
        "version": version,
        "language": language,
        "checks": total,
        "passed": passed,
        "failed": failed,
        "status": "VERIFIED" if failed == 0 else "FAILED",
    }
    
    return project_result

def get_curl_checks(parser):
    return [
        ("Port Number Bounds (0-65535)", 
         parser.parse_port_validation(), 
         SecurityConstraints.port_bounds),
        ("IPv6 Bracket Integrity", 
         parser.parse_ipv6_validation(), 
         SecurityConstraints.ipv6_bracket_integrity),
        ("No CRLF in Credentials (Header Injection)", 
         parser.parse_credential_validation(), 
         SecurityConstraints.no_crlf_in_credentials),
        ("Hostname Character Validation (SSRF)", 
         parser.parse_hostname_validation(), 
         SecurityConstraints.hostname_no_dangerous_chars),
        ("URL Control Character Rejection (Smuggling)", 
         parser.parse_junkscan(), 
         SecurityConstraints.no_control_chars_in_url),
    ]

def get_zlib_checks(parser):
    return [
        ("Adler32 Length Bounds",
         parser.parse_adler32_combine(),
         SecurityConstraints.adler32_len_bounds),
    ]

def main():
    registry = [
        ("curl", "curl", "master", "C", "/tmp/curl/lib/urlapi.c", get_curl_checks),
        ("zlib", "zlib", "master", "C", "/tmp/zlib/adler32.c", get_zlib_checks),
    ]
    
    output_dir = os.path.join(os.path.dirname(__file__), '..', 'public')
    manifest_path = os.path.join(output_dir, 'manifest.json')
    
    final_projects = []
    
    for slug, name, version, lang, source, checks_fn in registry:
        res = run_project_checks(slug, name, version, lang, source, checks_fn)
        if res:
            final_projects.append(res)
            
    # Write manifest
    with open(manifest_path, 'w') as f:
        json.dump(final_projects, f, indent=2)
        
    # Generate dashboard
    dashboard_path = os.path.join(output_dir, 'results.html')
    dashboard_html = generate_dashboard(final_projects)
    with open(dashboard_path, 'w') as f:
        f.write(dashboard_html)
    print(f"Dashboard written to {dashboard_path}")
    
    total_failed = sum(p["failed"] for p in final_projects)
    if total_failed:
        print(f"\n⚠️  {total_failed} constraint(s) FAILED overall — potential vulnerabilities found!")
    else:
        print(f"\n✅ All projects VERIFIED")

if __name__ == "__main__":
    main()
