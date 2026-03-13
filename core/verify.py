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

def run_check(name, ast, constraint_fn, explanation=""):
    """Run a single verification check. Returns a result dict."""
    converter = SMTConverter()
    solver, vars_dict = converter.convert(ast)
    
    violation = constraint_fn(vars_dict)
    if violation is None:
        return {"name": name, "status": "SKIPPED", "reason": "No matching variables", "explanation": explanation}
    
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
        "smt2": smt2,
        "explanation": explanation
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
        
        explanation_block = f"""<p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 1rem;">{r.get('explanation', '')}</p>""" if r.get('explanation') else ""
        
        cards += f"""
    <div class="result-card {color}">
      <div class="result-header">
        <span class="status-dot {color}"></span>
        <h3>{r['name']}</h3>
        <span class="badge {color}">{r['status']}</span>
      </div>
      <p class="result-meta">Function: <code>{r.get('function', 'N/A')}</code> · Z3 solved in {r.get('elapsed_ms', '?')}ms</p>
      {explanation_block}{smt2_block}
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
    for name, ast, constraint_fn, explanation in checks_config(parser):
        print(f"  [{project_name}] Checking: {name}...")
        r = run_check(name, ast, constraint_fn, explanation)
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
         SecurityConstraints.port_bounds,
         "Ensures that a parsed port number strictly falls between 0 and 65535. This prevents integer overflow bugs where negative numbers or extremely large numbers could bypass downstream access controls."),
        ("IPv6 Bracket Integrity", 
         parser.parse_ipv6_validation(), 
         SecurityConstraints.ipv6_bracket_integrity,
         "Mathematically proves that any IPv6 address parsed starting with a '[' bracket must also correctly terminate with a ']' bracket. This guarantees memory boundaries during address tokenization."),
        ("No CRLF in Credentials (Header Injection)", 
         parser.parse_credential_validation(), 
         SecurityConstraints.no_crlf_in_credentials,
         "Verifies that HTTP headers cannot be injected via the username or password fields in a URL by asserting that no Carriage Return (\\r) or Line Feed (\\n) characters are present."),
        ("Hostname Character Validation (SSRF)", 
         parser.parse_hostname_validation(), 
         SecurityConstraints.hostname_no_dangerous_chars,
         "Prevents Server-Side Request Forgery (SSRF) and parser-differential attacks by ensuring the hostname does not contain whitespace, @, #, ?, or other control characters."),
        ("URL Control Character Rejection (Smuggling)", 
         parser.parse_junkscan(), 
         SecurityConstraints.no_control_chars_in_url,
         "Proves the URL rejects all non-printable ASCII characters (<= 31 or == 127). This fundamentally prevents request smuggling and parser confusion vulnerabilities."),
        ("URL Input Length Bounds (CURL_MAX_INPUT_LENGTH)",
         parser.parse_url_input_length(),
         SecurityConstraints.url_input_length_bounds,
         "Verifies that the total URL length never exceeds CURL_MAX_INPUT_LENGTH (8,000,000 bytes). An unbounded URL could cause excessive memory allocation or denial-of-service via heap exhaustion."),
        ("Scheme Length Bounds (MAX_SCHEME_LEN)",
         parser.parse_scheme_length(),
         SecurityConstraints.scheme_length_bounds,
         "Proves that the URL scheme component (e.g. 'https') is between 1 and 40 characters. A zero-length scheme causes null-dereference; an oversized scheme overflows the fixed-size schemebuf[] on the stack."),
        ("Redirect Counter Bounds (Open Redirect DoS)",
         parser.parse_redirect_bounds(),
         SecurityConstraints.redirect_counter_bounds,
         "Ensures the redirect follow counter (uint16) and max redirects config (int16) stay within their type bounds. An unchecked counter could wrap around, enabling infinite redirect loops and denial-of-service."),
        ("Timeout Value Bounds (Overflow Prevention)",
         parser.parse_timeout_bounds(),
         SecurityConstraints.timeout_value_bounds,
         "Proves that CURLOPT_CONNECTTIMEOUT and CURLOPT_TIMEOUT values are non-negative and ≤ 2,147,483 seconds. When curl converts seconds to milliseconds internally (×1000), values above this threshold overflow a signed 32-bit integer, causing negative timeouts that bypass connection limits."),
    ]

def get_zlib_checks(parser):
    return [
        ("Adler32 Length Bounds",
         parser.parse_adler32_combine(),
         SecurityConstraints.adler32_len_bounds,
         "Ensures that the length parameter used in Adler-32 checksum calculations cannot exceed safe buffer boundaries, preventing integer overflow during chunk processing."),
        ("CRC32 Combine Length Bounds",
         parser.parse_crc32_combine_len(),
         SecurityConstraints.crc32_combine_len_bounds,
         "Verifies that the length parameter in crc32_combine_gen64 is non-negative. A negative length would cause incorrect GF(2) polynomial arithmetic, producing corrupted checksums that bypass data integrity validation."),
        ("Deflate Window Bits Bounds (8-15)",
         parser.parse_deflate_window_bits(),
         SecurityConstraints.deflate_window_bits_bounds,
         "Proves that the deflate windowBits parameter is strictly between 8 and 15 after normalization. Values outside this range would cause 1<<windowBits to produce an invalid window size, leading to heap buffer overflow during LZ77 sliding window operations."),
        ("Deflate Memory Level Bounds (1-9)",
         parser.parse_deflate_mem_level(),
         SecurityConstraints.deflate_mem_level_bounds,
         "Ensures the deflate memLevel parameter is within 1..MAX_MEM_LEVEL (9). An out-of-bounds memLevel controls hash table and pending buffer allocation sizes — exceeding it causes massive over-allocation or undersized buffers leading to heap corruption."),
        ("Inflate Window Bits Bounds (8-15)",
         parser.parse_inflate_window_bits(),
         SecurityConstraints.inflate_window_bits_bounds,
         "Verifies that the inflate windowBits parameter is within 8..15 after stripping wrap/gzip flags. Invalid windowBits would allocate a window of size 1<<windowBits, causing either a zero-size allocation (use-after-free) or excessive memory consumption (DoS)."),
        ("Deflate Dictionary Length Bounds",
         parser.parse_deflate_dict_length(),
         SecurityConstraints.deflate_dict_length_bounds,
         "Proves that the dictionary length passed to deflateSetDictionary does not exceed the maximum window size (32768 bytes for MAX_WBITS=15). An oversized dictionary would overflow the sliding window buffer during the initial dictionary copy."),
        ("CompressBound No Overflow",
         parser.parse_compress_bound(),
         SecurityConstraints.compress_bound_no_overflow,
         "Verifies that compressBound's output is always >= sourceLen, detecting integer wrap-around. If the bound wraps below sourceLen, the caller allocates an undersized destination buffer, causing a heap buffer overflow during deflate."),
        ("Deflate Dictionary Length Fits uint16",
         parser.parse_deflate_dict_length(),
         SecurityConstraints.deflate_dict_length_uint16_fit,
         "Proves deflateSetDictionary never accepts a dictionary length that exceeds 16-bit copy-counter capacity (65535). This guards downstream copy loops that may use narrowed counters from integer truncation bugs."),
    ]

def get_libsodium_checks(parser):
    libsodium_root = "/tmp/libsodium/src/libsodium"
    secretbox_parser = CParser(os.path.join(libsodium_root, "crypto_secretbox", "crypto_secretbox_easy.c"))
    box_parser = CParser(os.path.join(libsodium_root, "crypto_box", "crypto_box_easy.c"))
    return [
        ("KDF Blake2b Subkey Length Bounds",
         parser.parse_kdf_blake2b_derive_from_key(),
         SecurityConstraints.kdf_blake2b_subkey_len_bounds,
         "Cryptographic constraint: Verifies that the derived subkey length strictly adheres to the bounds defined by the Blake2b hashing algorithm, preventing memory corruption or weak keys."),
        ("KDF Blake2b Subkey ID uint64 Domain",
         parser.parse_kdf_blake2b_subkey_id(),
         SecurityConstraints.kdf_blake2b_subkey_id_bounds,
         "Proves subkey_id remains inside the unsigned 64-bit domain before it is serialized into the BLAKE2b salt. This blocks negative/sign-extended IDs and oversized values that could cause cross-context key collisions."),
        ("Secretbox Message Length Bounds",
         secretbox_parser.parse_crypto_secretbox_message_len(),
         SecurityConstraints.crypto_secretbox_message_len_bounds,
         "Proves that callers never encrypt more than crypto_secretbox_MESSAGEBYTES_MAX bytes. Without this cap the MAC-and-stream construction would wrap size_t arithmetic and allocate undersized buffers."),
        ("Secretbox Ciphertext Includes MAC",
         secretbox_parser.parse_crypto_secretbox_open_clen(),
         SecurityConstraints.crypto_secretbox_ciphertext_len_bounds,
         "Ensures that crypto_secretbox_open_easy rejects ciphertexts shorter than the 16-byte Poly1305 tag. This prevents length underflow before subtracting MACBYTES, which would otherwise lead to giant plaintext copies."),
        ("Curve25519 Box Message Length Bounds",
         box_parser.parse_crypto_box_message_len(),
         SecurityConstraints.crypto_box_message_len_bounds,
         "Shows that crypto_box_easy enforces the NaCl MESSAGEBYTES_MAX limit. The composed XSalsa20 stream cipher would misbehave if mlen rolled past SIZE_MAX or exceeded the largest representable keystream."),
        ("Curve25519 Box Ciphertext Includes MAC",
         box_parser.parse_crypto_box_open_clen(),
         SecurityConstraints.crypto_box_ciphertext_len_bounds,
         "Validates that every ciphertext given to crypto_box_open_easy carries at least a 16-byte Poly1305 authenticator, preventing integer underflow when stripping the MAC before decryption."),
    ]

def get_sqlite_checks(parser):
    return [
        ("SQLite3 Limit ID Bounds",
         parser.parse_sqlite3_limit(),
         SecurityConstraints.sqlite3_limit_bounds,
         "Ensures that the index ID for setting SQLite runtime limits is within valid bounds. This prevents out-of-bounds array access when configuring database properties."),
        ("SQLite3 Page Size Bounds (512-65536)",
         parser.parse_sqlite3_page_size(),
         SecurityConstraints.sqlite3_page_size_bounds,
         "Proves that the database page size is between 512 and 65536 bytes (SQLITE_MAX_PAGE_SIZE). An invalid page size would corrupt the B-tree layer, causing heap buffer overflows during page read/write operations."),
        ("SQLite3 Function Argument Count Bounds",
         parser.parse_sqlite3_function_narg(),
         SecurityConstraints.sqlite3_function_narg_bounds,
         "Verifies that user-defined function argument counts are between -1 (variadic) and SQLITE_MAX_FUNCTION_ARG (127). Out-of-bounds values would overflow the argument array on the VDBE stack frame."),
        ("SQLite3 Memory-Mapped I/O Size Bounds",
         parser.parse_sqlite3_mmap_size(),
         SecurityConstraints.sqlite3_mmap_size_bounds,
         "Ensures that the maximum memory-mapped I/O size (mxMmap) is non-negative. A negative mmap size would cause mmap() to receive an enormous unsigned length, mapping gigabytes of address space and causing denial-of-service."),
        ("SQLite3 Attached Database Index Bounds",
         parser.parse_sqlite3_attached_db(),
         SecurityConstraints.sqlite3_attached_db_bounds,
         "Proves that the attached database index is between 0 and SQLITE_MAX_ATTACHED (125). An out-of-bounds index would cause array overflows in the db->aDb[] schema array, corrupting adjacent heap metadata."),
        ("SQLite3 SQL Statement Length Bounds",
         parser.parse_sqlite3_sql_length(),
         SecurityConstraints.sqlite3_sql_length_bounds,
         "Verifies that SQL statement length never exceeds SQLITE_MAX_SQL_LENGTH (1,000,000,000 bytes). An unbounded SQL string triggers excessive tokenizer memory allocation and can cause denial-of-service via parser stack exhaustion."),
        ("SQLite3 Expression Tree Depth Bounds",
         parser.parse_sqlite3_expr_depth(),
         SecurityConstraints.sqlite3_expr_depth_bounds,
         "Proves that recursive expression nesting depth cannot exceed SQLITE_MAX_EXPR_DEPTH (1000). Without this bound, a deeply nested SQL expression causes C stack overflow during code generation, enabling remote code execution."),
        ("SQLite3 Column Count Bounds (SQLITE_MAX_COLUMN)",
         parser.parse_sqlite3_column_count(),
         SecurityConstraints.sqlite3_column_count_bounds,
         "Ensures the number of columns in a table or index stays within SQLITE_MAX_COLUMN (hard max 32767). Exceeding this limit overflows the 16-bit column index stored in Index structures, corrupting query plans."),
        ("SQLite3 BLOB/String Length Bounds (SQLITE_MAX_LENGTH)",
         parser.parse_sqlite3_blob_length(),
         SecurityConstraints.sqlite3_blob_length_bounds,
         "Proves that BLOB and string values never exceed SQLITE_MAX_LENGTH (1,000,000,000 bytes). Without this cap, oversized values cause integer overflow in memory allocation arithmetic, leading to heap buffer overflows."),
        ("SQLite3 SQL Parameter Index Bounds (SQLITE_MAX_VARIABLE_NUMBER)",
         parser.parse_sqlite3_variable_number(),
         SecurityConstraints.sqlite3_variable_number_bounds,
         "Verifies that SQL parameter indices (?NNN syntax) are between 1 and SQLITE_MAX_VARIABLE_NUMBER (32766). An out-of-bounds parameter index overflows the apArg[] array on the VDBE stack, enabling heap corruption via crafted SQL."),
    ]

def get_openssl_checks(parser):
    return [
        ("DSA_SIG DER decode length bounds",
         parser.parse_d2i_DSA_SIG(),
         SecurityConstraints.dsa_sig_len_bounds,
         "Verifies that the length parameter provided when decoding an ASN.1 DER encoded DSA signature is strictly non-negative. This prevents catastrophic integer underflow vulnerabilities during cryptographic parsing."),
        ("EVP Cipher Key Length Bounds",
         parser.parse_openssl_evp_key_size(),
         SecurityConstraints.openssl_evp_key_size_bounds,
         "Ensures the EVP cipher key length is between 1 and 64 bytes, preventing zero-length keys (no encryption) or oversized keys that could overflow fixed-size key schedule buffers."),
        ("BIGNUM Bit Count Bounds",
         parser.parse_openssl_bn_num_bits(),
         SecurityConstraints.openssl_bn_num_bits_bounds,
         "Validates that BIGNUM bit counts are non-negative and at most 16384, preventing denial-of-service via absurdly large key generation or modular exponentiation operations."),
        ("X.509 Certificate Version Bounds",
         parser.parse_openssl_x509_version(),
         SecurityConstraints.openssl_x509_version_bounds,
         "Proves the X.509 certificate version field is 0 (v1), 1 (v2), or 2 (v3). Invalid versions could bypass extension parsing logic and certificate validation checks."),
    ]

def get_nginx_checks(parser):
    return [
        ("HTTP/2 Field Length Bounds",
         parser.parse_ngx_http_v2_state_field_len(),
         SecurityConstraints.nginx_field_len_bounds,
         "Proves that HTTP/2 HPACK header field lengths are never negative. A negative length in HTTP/2 state parsing could cause infinite loops or massive out-of-bounds memory reads."),
        ("HTTP Status Code Bounds",
         parser.parse_ngx_http_status_code(),
         SecurityConstraints.nginx_status_code_bounds,
         "Validates that parsed HTTP response status codes are within the valid range 100-599. Out-of-range status codes could confuse downstream proxies and enable response splitting attacks."),
        ("Request URI Length Bounds",
         parser.parse_ngx_http_uri_length(),
         SecurityConstraints.nginx_uri_length_bounds,
         "Ensures the parsed request URI length is between 1 and 8192 bytes. Zero-length URIs cause null-pointer dereferences; excessively long URIs enable buffer overflow in fixed-size URI buffers."),
        ("HTTP Header Count Bounds",
         parser.parse_ngx_http_header_count(),
         SecurityConstraints.nginx_header_count_bounds,
         "Limits the number of parsed HTTP headers to 100, preventing slowloris-style denial-of-service attacks via excessive header injection."),
        ("HTTP Minor Version Bounds",
         parser.parse_ngx_http_version_minor(),
         SecurityConstraints.nginx_http_minor_version_bounds,
         "Ensures parsed HTTP minor versions are in the range 0-9. Out-of-range values can destabilize request parsing state machines and create parser differential behavior across proxies."),
    ]

def get_libxml2_checks(parser):
    return [
        ("Entity Expansion Depth Limit",
         parser.parse_libxml2_parser_max_depth(),
         SecurityConstraints.libxml2_depth_bounds,
         "Verifies the 'Billion Laughs' protection: ensures the recursive entity expansion depth cannot exceed 40. This mathematically guarantees the parser is immune to exponential XML entity denial-of-service attacks."),
        ("Attribute Count Per Element Bounds",
         parser.parse_libxml2_attr_count(),
         SecurityConstraints.libxml2_attr_count_bounds,
         "Limits the number of attributes on a single XML element to 10,000. Unbounded attribute counts enable quadratic blowup DoS attacks during namespace resolution and duplicate attribute detection."),
        ("Element/Attribute Name Length Bounds",
         parser.parse_libxml2_name_length(),
         SecurityConstraints.libxml2_name_length_bounds,
         "Ensures XML element and attribute names are between 1 and 50,000 characters. Zero-length names cause parser state corruption; excessively long names exhaust memory during dictionary interning."),
    ]

def get_libpng_checks(parser):
    return [
        ("IHDR Image Width Bounds",
         parser.parse_png_ihdr_width(),
         SecurityConstraints.png_width_bounds,
         "Ensures that the image width parsed from a PNG IHDR chunk is strictly greater than 0 and less than or equal to INT_MAX. This prevents integer overflow when allocating memory for image row buffers."),
        ("IHDR Image Height Bounds",
         parser.parse_png_ihdr_height(),
         SecurityConstraints.png_height_bounds,
         "Ensures the image height from the IHDR chunk is positive and within INT_MAX. A zero or negative height causes division-by-zero in interlace calculations; exceeding INT_MAX overflows row count arithmetic."),
        ("IHDR Bit Depth Bounds",
         parser.parse_png_ihdr_bit_depth(),
         SecurityConstraints.png_bit_depth_bounds,
         "Validates the PNG bit depth is between 1 and 16. Invalid bit depths cause undefined shift operations and incorrect pixel buffer sizing, leading to heap corruption."),
        ("Chunk Length Bounds",
         parser.parse_png_chunk_length(),
         SecurityConstraints.png_chunk_length_bounds,
         "Ensures PNG chunk lengths are non-negative and within INT_MAX. Negative chunk lengths (via signed integer interpretation) cause massive over-allocation or heap buffer overflows during chunk data reads."),
    ]

def get_mbedtls_checks(parser):
    return [
        ("SSL Record Data Length Bounds",
         parser.parse_mbedtls_ssl_record_len(),
         SecurityConstraints.mbedtls_record_len_bounds,
         "Verifies that the decrypted TLS record payload length never exceeds the maximum permissible SSL record size (16,384 bytes). This prevents buffer overflow when assembling fragments."),
        ("Ciphertext Length Bounds",
         parser.parse_mbedtls_ciphertext_len(),
         SecurityConstraints.mbedtls_ciphertext_len_bounds,
         "Validates that the ciphertext buffer length for TLS record decryption is within 0-16384 bytes. Oversized ciphertext triggers heap buffer overflow during in-place decryption."),
        ("TLS Major Version Bounds",
         parser.parse_mbedtls_major_version(),
         SecurityConstraints.mbedtls_major_version_bounds,
         "Proves the TLS major version is exactly 3 (covering SSL 3.0 through TLS 1.3). An incorrect major version bypasses handshake state validation and enables protocol downgrade attacks."),
        ("TLS Minor Version Bounds",
         parser.parse_mbedtls_minor_version(),
         SecurityConstraints.mbedtls_minor_version_bounds,
         "Ensures the TLS minor version is between 0 and 4 (SSL 3.0=0, TLS 1.0=1, 1.1=2, 1.2=3, 1.3=4). Out-of-range values cause array index out-of-bounds in cipher suite selection tables."),
        ("TLS Record Content Type Bounds",
         parser.parse_mbedtls_content_type(),
         SecurityConstraints.mbedtls_content_type_bounds,
         "Verifies TLS record content types are limited to the protocol-defined range 20..24 (change_cipher_spec, alert, handshake, application_data, heartbeat). Out-of-range content types can desynchronize record parsing and bypass state-machine checks."),
    ]

def get_openssh_checks(parser):
    return [
        ("Max Auth Tries Bounds",
         parser.parse_openssh_auth_max_tries(),
         SecurityConstraints.openssh_max_authtries_bounds,
         "Proves that the configuration variable for maximum authentication attempts must be between 1 and 100. This ensures the SSH daemon cannot be configured into an infinite password brute-force loop."),
        ("Channel ID Bounds",
         parser.parse_openssh_channel_id(),
         SecurityConstraints.openssh_channel_id_bounds,
         "Validates that SSH channel IDs are between 0 and 65535. Out-of-range channel IDs cause array-based channel table overflows, enabling remote code execution via crafted channel open requests."),
        ("SSH Packet Length Bounds",
         parser.parse_openssh_packet_len(),
         SecurityConstraints.openssh_packet_len_bounds,
         "Ensures SSH packet lengths are between 5 and 262144 bytes. Packets shorter than 5 bytes lack mandatory fields; packets exceeding 256KB enable memory exhaustion denial-of-service attacks."),
    ]

def get_sudo_checks(parser):
    return [
        ("UID Bounds Validation",
         parser.parse_sudo_uid_check(),
         SecurityConstraints.sudo_uid_bounds,
         "Ensures that User IDs processed by the sudo privilege escalater are between 0 and 65534. This prevents privilege bypasses via integer overflow attacks on the UID type."),
        ("GID Bounds Validation",
         parser.parse_sudo_gid_check(),
         SecurityConstraints.sudo_gid_bounds,
         "Validates that Group IDs are between 0 and 65534. The value 65535 (nobody/nogroup) and negative GIDs can bypass group-based access control checks in the sudoers policy."),
        ("Environment Variable Count Bounds",
         parser.parse_sudo_env_count(),
         SecurityConstraints.sudo_env_count_bounds,
         "Limits the number of environment variables passed through sudo to 1024. Unbounded environment inheritance enables stack exhaustion and env-based privilege escalation (e.g., LD_PRELOAD injection)."),
        ("Argument Count Bounds",
         parser.parse_sudo_argv_count(),
         SecurityConstraints.sudo_argv_count_bounds,
         "Ensures the argument count is between 1 and 4096. Zero arguments cause null-pointer dereference; excessive arguments enable stack-based buffer overflow in argument vector construction."),
    ]

def get_git_checks(parser):
    return [
        ("Protocol Version Bounds",
         parser.parse_git_protocol_version(),
         SecurityConstraints.git_protocol_version_bounds,
         "Validates that the parsed Git network protocol version is bounded between version 0 and version 2, ensuring state machine stability and preventing parser confusion on the wire protocol."),
        ("pkt-line Length Bounds",
         parser.parse_git_pkt_line_len(),
         SecurityConstraints.git_pkt_line_len_bounds,
         "Ensures Git pkt-line lengths are between 0 and 65520 bytes (the protocol maximum). Oversized pkt-lines cause heap buffer overflow in the sideband demultiplexer and smart HTTP transport."),
        ("Tree Traversal Depth Bounds",
         parser.parse_git_tree_depth(),
         SecurityConstraints.git_tree_depth_bounds,
         "Limits recursive tree traversal depth to 4096, preventing stack overflow from maliciously crafted repositories with deeply nested directory structures (CVE-style symlink/tree bombs)."),
        ("Pathname Length Bounds",
         parser.parse_git_path_len(),
         SecurityConstraints.git_path_len_bounds,
         "Validates that file path lengths are between 1 and 4096 characters. Zero-length paths bypass .gitignore rules; excessively long paths overflow fixed-size path buffers on certain platforms."),
        ("Object Type Enum Bounds",
         parser.parse_git_object_type(),
         SecurityConstraints.git_object_type_bounds,
         "Ensures parsed object types fall within the valid enum range OBJ_COMMIT(1) through OBJ_REF_DELTA(7) as defined in object.h. Invalid type values cause out-of-bounds array access in object type dispatch tables."),
        ("Symbolic Ref Resolution Depth",
         parser.parse_git_symref_depth(),
         SecurityConstraints.git_symref_depth_bounds,
         "Limits symbolic reference resolution depth to SYMREF_MAXDEPTH(5) as defined in refs-internal.h. Unbounded symref chains enable infinite loop DoS via circular symbolic references."),
        ("Hash Algorithm ID Bounds",
         parser.parse_git_hash_algo(),
         SecurityConstraints.git_hash_algo_bounds,
         "Validates hash algorithm identifier is either GIT_HASH_SHA1(1) or GIT_HASH_SHA256(2). Invalid algorithm IDs cause null pointer dereference in the hash vtable lookup."),
        ("Pack Object Header Length Bounds",
         parser.parse_git_pack_obj_header_len(),
         SecurityConstraints.git_pack_obj_header_len_bounds,
         "Ensures pack object header length is between 1 and MAX_PACK_OBJECT_HEADER(10) bytes as defined in pack.h. Oversized headers cause heap buffer overflow in pack encoding/decoding routines."),
        ("Hash Raw Size Bounds",
         parser.parse_git_hash_rawsz(),
         SecurityConstraints.git_hash_rawsz_bounds,
         "Validates that hash digest raw size is between GIT_SHA1_RAWSZ(20) and GIT_MAX_RAWSZ(32) bytes. Incorrect sizes cause buffer overflows in hash comparison and copy operations throughout the codebase."),
        ("Hash Digest Bit-Length Bounds",
         parser.parse_git_hash_rawsz(),
         SecurityConstraints.git_hash_bits_bounds,
         "Ensures computed digest width remains within 160-256 bits (20-32 bytes). This protects callers that allocate fixed digest-sized buffers from over/under-sized hash values during copy and comparison operations."),
    ]

def main():
    registry = [
        ("curl", "curl", "master", "C", "/tmp/curl/lib/urlapi.c", get_curl_checks),
        ("zlib", "zlib", "master", "C", "/tmp/zlib/adler32.c", get_zlib_checks),
        ("libsodium", "libsodium", "master", "C", "/tmp/libsodium/src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c", get_libsodium_checks),
        ("sqlite", "sqlite", "master", "C", "/tmp/sqlite/src/main.c", get_sqlite_checks),
        ("openssl", "OpenSSL", "master", "C", "/tmp/openssl/crypto/dsa/dsa_sign.c", get_openssl_checks),
        ("nginx", "nginx", "master", "C", "/tmp/nginx/src/http/v2/ngx_http_v2.c", get_nginx_checks),
        ("libxml2", "libxml2", "master", "C", "/tmp/libxml2/parser.c", get_libxml2_checks),
        ("libpng", "libpng", "master", "C", "/tmp/libpng/pngrutil.c", get_libpng_checks),
        ("mbedtls", "mbedTLS", "master", "C", "/tmp/mbedtls/library/ssl_msg.c", get_mbedtls_checks),
        ("openssh", "OpenSSH", "master", "C", "/tmp/openssh/auth.c", get_openssh_checks),
        ("sudo", "sudo", "master", "C", "/tmp/sudo/src/sudo.c", get_sudo_checks),
        ("git", "git", "master", "C", "/tmp/git/connect.c", get_git_checks),
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
